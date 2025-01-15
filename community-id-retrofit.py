#!env python3

import gzip
import os
import json
import communityid
import tempfile
import shutil
import re
# TODO: argparse needed

replace_regex = re.compile('(.*"uid":"[A-Za-z0-9]+",)(.*)')
conn_log_regex = re.compile('conn\.([0-9:-]+\.)?log(\.gz)?')

def insert_community_id(original_line, community_id):
    # you might be asking why this is being done with a regex replacement rather than modifying and dumping 
    #       the json object.  tl;dr: floating point numbers.  reading in a float like 0.00002288818359375
    #       is reflected as 2.288818359375e-05.  we don't want to modify any existing values, so: this is the way.
    return replace_regex.sub(r'\1"community_id":"%s",\2' % (community_id), original_line)

def open_conditional_gzip(filename):
    gzip_file = False
    fh = gzip.open(filename, 'rb')

    try:
        fh.read(1)
        gzip_file = True

    except gzip.BadGzipFile:
        fh.close()
        fh = open(filename, 'rb')

        try:
            fh.read(1)
        except:
            print('some error reading file')
            exit(2)

    fh.seek(0)
    return (fh, gzip_file)

def build_uid_map(conn_filename, overwrite=False):
    uid_map = {}
    cid = communityid.CommunityID()

    community_id_added = False

    (conn_fh, conn_is_gzip_file) = open_conditional_gzip(conn_filename)

    first_line = conn_fh.readline()
    first_line_json = json.loads(first_line)

    if 'uid' not in first_line_json:
            print(f'no uid value here: {conn_filename}')
            ## TODO: should just skip this file instead of exit()
            exit(2)
    else:
        conn_fh.seek(0)
        for line in conn_fh:
            line_json = json.loads(line)

            uid = line_json['uid']

            if 'community_id' in line_json:
                community_id = line_json['community_id']

            else:
                # need to calculate and populate the community_id into the file, overwriting if directed
                # build the uid_map dict while calculating the community_id value
                pass

                source_ip = line_json['id.orig_h']
                destination_ip = line_json['id.resp_h']
                source_port = line_json['id.orig_p']
                destination_port = line_json['id.resp_p']
                protocol = communityid.get_proto(line_json['proto'])

                tpl = communityid.FlowTuple(protocol, source_ip, destination_ip, source_port, destination_port)

                # calculate the community id
                community_id = cid.calc(tpl)

            uid_map[uid] = community_id

    conn_fh.close()
    return uid_map

def create_new_logfile(filename, is_gzip_file):
    if is_gzip_file:
        new_logfile_fh = gzip.open(filename, 'wb')
    else:
        new_logfile_fh = open(filename, 'wb')

    return new_logfile_fh

def retrofit_community_id(uid_map, log_filename, overwrite=False, new_filename=''):
    (logfile_fh, log_is_gzip_file) = open_conditional_gzip(log_filename)

    first_line = logfile_fh.readline()
    first_line_json = json.loads(first_line)

    community_id_inserted = False

    if 'uid' not in first_line_json or 'community_id' in first_line_json:
        return

    else:
        logfile_fh.seek(0)
        new_logfile_fh = create_new_logfile(new_filename, log_is_gzip_file)

    for logfile_line in logfile_fh:
        json_logfile_entry = json.loads(logfile_line)

        logfile_line = logfile_line.decode('utf-8')

        try:
            log_entry_uid = json_logfile_entry['uid']
            community_id = uid_map[log_entry_uid]

            new_json_logfile_line = insert_community_id(logfile_line, community_id)
            community_id_inserted = True

        except KeyError:
            # no community_id for this uid, so just write out the unmodified source line
            new_json_logfile_line = logfile_line

        new_logfile_fh.write(new_json_logfile_line.encode('utf-8'))

    logfile_fh.close()
    new_logfile_fh.close()

    if overwrite and community_id_inserted:
        shutil.move(new_filename, log_filename)

## Temp usage variables!!! these need to be replaced via argparse
## todo: should we also have a "backup original" option?
overwrite_source = False
##

## traversal algorithm, take 2
for root, dirs, files in os.walk('.'):
    for filename in files:
        conn_match = conn_log_regex.match(filename)

        if conn_match:
            conn_filename = os.path.join(root, filename)
            print(f'using {conn_filename} for uid_map')
            pdb.set_trace()
            uid_map = build_uid_map(conn_filename)

            time_range = conn_match.group(1)
            if time_range == None:
                time_range = ''
            extension = conn_match.group(2)
            if extension == None:
                extension = ''

            file_regex = re.compile(f'.*\.({time_range}\.)?log{extension}')

            for name2 in os.listdir(root):
                if file_regex.match(name2):

                    log_filename = os.path.join(root, name2)

                    if overwrite_source:
                        tmp_name = tempfile.mktemp()
                        print(f'- enriching {root}/{name2} (overwrite)')
                    else:
                        tmp_name = log_filename.replace('.log', '.new.log')
                        print(f'- enriching {root}/{name2} -> {tmp_name}')

                    retrofit_community_id(uid_map, log_filename, overwrite_source, tmp_name)
