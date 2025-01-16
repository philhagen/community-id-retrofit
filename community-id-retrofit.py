#!env python3
# community-id-retrofit.py version 1.0
# (C) 2025 Lewes Technology Consulting, LLC
#
# This script will extract or calculate the community_id value from Zeek's
# conn.log files, then append it to existing Zeek log records in other
# Zeek log files.

import gzip
import os
import json
import communityid
import tempfile
import shutil
import re
import argparse

replace_regex = re.compile('(.*"uid":"[A-Za-z0-9]+",)(.*)')
conn_log_regex = re.compile("conn\.([0-9:-]+)?\.?(log(?:\.gz)?)")


def insert_community_id(original_line, community_id):
    # you might be asking why this is being done with a regex replacement rather than modifying and dumping
    #       the json object.  tl;dr: floating point numbers.  reading in a float like 0.00002288818359375
    #       is reflected as 2.288818359375e-05.  we don't want to modify any existing values, so: this is the way.
    return replace_regex.sub(
        r'\1"community_id":"%s",\2' % (community_id), original_line
    )


def open_conditional_gzip(filename):
    gzip_file = False
    fh = gzip.open(filename, "rb")

    try:
        fh.read(1)
        gzip_file = True

    except gzip.BadGzipFile:
        fh.close()
        fh = open(filename, "rb")

        try:
            fh.read(1)
        except:
            print("some error reading file")
            exit(2)

    fh.seek(0)
    return (fh, gzip_file)


def build_uid_map(conn_filename, overwrite=False):
    uid_map = {}
    cid = communityid.CommunityID()

    (conn_fh, conn_is_gzip_file) = open_conditional_gzip(conn_filename)

    first_line = conn_fh.readline()
    first_line_json = json.loads(first_line)

    if "uid" not in first_line_json:
        if not args.verbose:
            print(f"no uid value here: {conn_filename}")
            return False

    else:
        conn_fh.seek(0)
        for line in conn_fh:
            line_json = json.loads(line)

            uid = line_json["uid"]

            if "community_id" in line_json:
                community_id = line_json["community_id"]

            else:
                # need to calculate and populate the community_id into the file, overwriting if directed
                # build the uid_map dict while calculating the community_id value
                pass

                source_ip = line_json["id.orig_h"]
                destination_ip = line_json["id.resp_h"]
                source_port = line_json["id.orig_p"]
                destination_port = line_json["id.resp_p"]
                protocol = communityid.get_proto(line_json["proto"])

                tpl = communityid.FlowTuple(
                    protocol, source_ip, destination_ip, source_port, destination_port
                )

                # calculate the community id
                community_id = cid.calc(tpl)

            uid_map[uid] = community_id

    conn_fh.close()
    return uid_map


def create_new_logfile(filename, is_gzip_file):
    if is_gzip_file:
        new_logfile_fh = gzip.open(filename, "wb")

    else:
        new_logfile_fh = open(filename, "wb")

    return new_logfile_fh


def retrofit_community_id(uid_map, filename, overwrite=False, new_filename=""):
    (logfile_fh, log_is_gzip_file) = open_conditional_gzip(filename)

    first_line = logfile_fh.readline()
    first_line_json = json.loads(first_line)

    community_id_inserted = False

    if "uid" not in first_line_json:
        if args.verbose:
            print(f"  - No uid in {root}/{retrofit_filename}, skipping")
        return
    elif "community_id" in first_line_json:
        if args.verbose:
            print(
                f"  - community_id field already exists in {root}/{retrofit_filename}, skipping"
            )
        return

    else:
        logfile_fh.seek(0)
        if not args.testrun:
            new_logfile_fh = create_new_logfile(new_filename, log_is_gzip_file)

    for logfile_line in logfile_fh:
        json_logfile_entry = json.loads(logfile_line)

        logfile_line = logfile_line.decode("utf-8")

        try:
            log_entry_uid = json_logfile_entry["uid"]
            community_id = uid_map[log_entry_uid]

            new_json_logfile_line = insert_community_id(logfile_line, community_id)
            community_id_inserted = True

        except KeyError:
            # no community_id for this uid, so just write out the unmodified source line
            new_json_logfile_line = logfile_line

        if not args.testrun:
            new_logfile_fh.write(new_json_logfile_line.encode("utf-8"))

    logfile_fh.close()
    if not args.testrun:
        new_logfile_fh.close()

    if overwrite and community_id_inserted:
        if args.verbose:
            print(f"  - Retrofitted {root}/{retrofit_filename} (overwrite)")

        if not args.testrun:
            shutil.move(new_filename, filename)

    elif community_id_inserted:
        if args.verbose:
            print(f"  - Retrofitting {root}/{retrofit_filename} -> {tmp_name}")

    elif not community_id_inserted and not args.testrun:
        os.remove(new_filename)


parser = argparse.ArgumentParser(
    description="Traverse a directory tree containing Zeek log files in JSON format, adding a community_id field to each wherever a uid field already exists."
)
parser.add_argument(
    "-r",
    "--read",
    dest="inputdir",
    help="Root directory to traverse.  Default: ./",
    default=".",
)
parser.add_argument(
    "-o",
    "--overwrite",
    dest="overwrite_source",
    action="store_true",
    default=False,
    help="Overwrite source files.  Default: Create new log files alongside the originals, which will be left unchanged.",
)
parser.add_argument(
    "-t",
    "--testrun",
    dest="testrun",
    action="store_true",
    default=False,
    help="Just run a trial and don't make any changes. Default: false",
)
parser.add_argument(
    "-v",
    "--verbose",
    dest="verbose",
    action="store_true",
    default=False,
    help="Verbose output.  Default: false",
)
args = parser.parse_args()

## traversal algorithm, take 2
for root, dirs, files in os.walk(args.inputdir):
    for filename in files:
        conn_match = conn_log_regex.match(filename)

        if conn_match:
            conn_filename = os.path.join(root, filename)

            print(f"using {conn_filename} for uid_map")

            uid_map = build_uid_map(conn_filename)

            if uid_map == False:
                if args.verbose:
                    print("- No uid->community_id map could be created.  Skipping.")
                continue

            if args.verbose:
                print(f"- Found or calculated {len(uid_map)} community_id values")

            time_range = conn_match.group(1)
            extension = conn_match.group(2)

            if time_range == None:
                file_regex = re.compile(f".*\.{extension}")
            else:
                file_regex = re.compile(f".*\.{time_range}\.{extension}")

            for retrofit_filename in os.listdir(root):
                if file_regex.match(retrofit_filename):

                    retrofit_filepath = os.path.join(root, retrofit_filename)

                    if args.overwrite_source:
                        tmp_name = tempfile.mktemp()
                    else:
                        tmp_name = retrofit_filepath.replace(".log", ".new.log")

                    retrofit_community_id(
                        uid_map, retrofit_filepath, args.overwrite_source, tmp_name
                    )
