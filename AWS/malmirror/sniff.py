#!/usr/bin/env python3
import os
from sys import argv
from psutil import net_if_addrs
from scapy.all import sniff, wrpcap
from subprocess import check_output


usage = 'python3 sniff.py <s3 bucket name>'

s3_bucket_name = argv[1].rstrip()


def get_iface_name():
    ifaces = net_if_addrs()
    if 'lo' in ifaces:
        del ifaces['lo']

    if len(ifaces) == 0:
        # This means something went wrong
        return 'lo'
    else:
        # Not sure what to do if there are still multiple interfaces
        return list(ifaces)[0]


# print(f'S3 bucket name: {s3_bucket_name}')
my_iface_name = get_iface_name()
# print(f'Interface name: {my_iface_name}')


# /tmp/sniff should already exist, but why not be sure
os.makedirs('/tmp/sniff/', exist_ok=True)
global current_log_file, log_file_name, log_file_iteration
log_file_name = '/tmp/sniff/traffic'
log_file_iteration = 0
current_log_file = log_file_name + str(log_file_iteration) + '.pcap'


def packet_passthrough(packet):
    global current_log_file, log_file_name, log_file_iteration
    # Log to a single file until it is over 100MB, then move to a new file
    try:
        if os.stat(current_log_file).st_size > 100000000:  # If greater than 100MB
            file_to_upload = current_log_file
            log_file_iteration += 1
            current_log_file = log_file_name + str(log_file_iteration) + '.pcap'

            file_name_only = file_to_upload.split('/')[-1]

            # subprocess.check_output so that it blocks until the upload is done
            # and doesn't remove the file before the upload completes
            check_output(
                f'aws s3api put-object --key $(hostname)/{file_name_only} --bucket {s3_bucket_name} --body {file_to_upload}',
                shell=True
            )

            os.remove(file_to_upload)
    except FileNotFoundError:
        pass
    with open(current_log_file, 'ab+') as f:
        wrpcap(f, packet, append=True)


sniff(iface=my_iface_name, prn=packet_passthrough)
