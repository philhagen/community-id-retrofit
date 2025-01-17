# Community ID Retrofit

This script inserts a `community_id` string into log files from the Zeek Network Security Monitoring platform alongside existing Zeek Connection ID (`uid`) fields.

## Background

In 2018, Corelight introduced the Community ID flow hashing standard.  This is a standardized way of labeling traffic conversations across a variety of network-based tools.

Prior to this feature, Zeek only used the Connection ID value (labeled as `uid`), which appears in numerous Zeek log files.  This was a convenient field to use as an analyst pivoted across various Zeek log files, and it is still calculated and logged in the latest versions of Zeek.  However, the `uid` field is only consistent for logs generated by the same individual Zeek process.  Since a digital forensic investigation involving Zeek data may involve logs from multiple sensors, or generated from multiple pcap files, the `uid` value becomes less useful since the same network conversation observed from two different points results in two different `uid` values.

The Community ID sought in part to alleviate this shortfall.  This feature was available as an extension package prior to Zeek version 6 and as a core component of Zeek version 6 and later.  However, the newly calculated `community_id` field is only logged in the connection log file.  The `uid` value is still required for correlation of events and artifacts across different Zeek log files.

## Goal for this Script

The script in this repository will retrofit a `community_id` value into all Zeek logs that contain a `uid` value.  If a connection log file already has a `community_id` value calculated, this value will be used.  If this field is not available, the `community_id` value will be calculated from the values in the connection log.  It is then inserted into all log files that contain a `uid` value.  The script recursively traverses a directory tree of Zeek files in plain text or gzip-compressed format.  At this time, only JSON-formatted Zeek log files are supported.

## Usage

The script has just a few command line parameters.  All of these are optional.

- `-r <input directory>` or `--read <input directory>`: The root directory to traverse for replacements.  The default is to start at the current directory.
- `-o` or `--overwrite`: Overwrite log files with those including the newly-added `community_id` field.  The default is to create new logfiles alongside the originals.
- `-t` or `--testrun`: Do not make any changes.  Most useful with `-v`, below.  Default is to perform the retrofit operation.
- `-v` or `--verbose`: Display extra detail about the retrofit operation.  Default is to run silently unless errors are encountered.
- `-h` or `--help`: Display usage instructions.

### Example

The below example shows the original and modified lines from a `files.log` entry.  (The lines have been truncated for space.)

```bash
% head -n 1 files.log | jq
{
  "ts":1674054511.216466,
  "fuid":"FeKGpf3GkLluk8n3Ic",
  "uid":"CE20kl0Vp7bggrVdk",
  "id.orig_h":"172.16.6.11",
  ...
}

% ../../../community-id-retrofit.py -r . -o -v
using ./conn.log for uid_map
- Found or calculated 41 community_id values
  - Retrofitted ./ntlm.log (overwrite)
  - No uid in ./loaded_scripts.log, skipping
  - No uid in ./notice.log, skipping
  - No uid in ./pe.log, skipping
  - community_id field already exists in ./conn.log, skipping
  - Retrofitted ./smb_files.log (overwrite)
  - No uid in ./stats.log, skipping
  - No uid in ./known_services.log, skipping
  - No uid in ./capture_loss.log, skipping
  - Retrofitted ./smb_mapping.log (overwrite)
  - Retrofitted ./files.log (overwrite)
  - No uid in ./telemetry.log, skipping
  - No uid in ./packet_filter.log, skipping
  - Retrofitted ./kerberos.log (overwrite)
  - No uid in ./known_hosts.log, skipping
  - Retrofitted ./dce_rpc.log (overwrite)

% head -n 1 files.log | jq
{
  "ts":1674054511.216466,
  "fuid":"FeKGpf3GkLluk8n3Ic",
  "uid":"CE20kl0Vp7bggrVdk",
  "community_id":"1:gks9G58UPyWtmm/Z1FKDEn5hKSg=",
  "id.orig_h":"172.16.6.11",
  ...
}
```

Note the addition of the `community_id` field in the resulting `files.log` file, files that did not contain a `uid` field, and that the `conn.log` file already contained the `community_id` field.

## Copyright and License

Copyright (C) 2025 by Lewes Technology Consulting, LLC

Contents of this repository are provided "as is" with no express or implied warranty for accuracy or accessibility.

See the LICENSE file for details on further use of this project.
