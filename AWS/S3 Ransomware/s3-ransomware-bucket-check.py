#!/usr/bin/env python3

import argparse
import sys

from time import time

import boto3

from botocore.exceptions import ProfileNotFound
from botocore.exceptions import ClientError


def main(args):
    if args.profile is None:
        session = boto3.session.Session()
        print('No AWS CLI profile passed in, choose one below or rerun the script using the -p/--profile argument:')
        profiles = session.available_profiles
        for i in range(0, len(profiles)):
            print(f'[{i}] {profiles[i]}')
        profile_number = int(input('Choose a profile (Ctrl+C to exit): ').strip())
        profile_name = profiles[profile_number]
        session = boto3.session.Session(profile_name=profile_name)
    else:
        try:
            profile_name = args.profile
            session = boto3.session.Session(profile_name=profile_name)
        except ProfileNotFound as error:
            print(f'Did not find the specified AWS CLI profile: {args.profile}\n')

            session = boto3.session.Session()
            quit(f'Profiles that are available: {session.available_profiles}\n')

    client = session.client('s3')

    target_buckets = []
    if args.buckets:
        target_buckets.extend(args.buckets.split(','))
    else:
        print('Finding buckets...')
        try:
            listed_buckets = client.list_buckets()
            for bucket in listed_buckets.get('Buckets', []):
                target_buckets.append(bucket['Name'])
        except ClientError as error:
            quit(f'    Failed to list S3 buckets in the current account ({error.response["Error"]["Code"]}): {error.response["Error"]["Message"]}')

    if len(target_buckets) < 1:
        quit('    No buckets found in the target list.')

    print(f'Checking configuration of {len(target_buckets)} buckets...')

    csv_rows = [['Bucket Name', 'Object Versioning', 'MFA Delete', 'Note', 'Recommendation']]

    for bucket in target_buckets:
        try:
            response = client.get_bucket_versioning(Bucket=bucket)
            versioning = response.get('Status', 'Disabled')
            mfa_delete = response.get('MFADelete', 'Disabled')

            if args.enable_versioning:
                if versioning in ['Disabled', 'Suspended']:
                    try:
                        client.put_bucket_versioning(
                            Bucket=bucket,
                            VersioningConfiguration={
                                'Status': 'Enabled',
                                'MFADelete': 'Disabled'
                            }
                        )
                        versioning = 'Enabled'
                        print(f'    Enabled Object Versioning on bucket {bucket}')
                    except ClientError as error:
                        print(f'    {error.response["Error"]["Code"]} error running s3:PutBucketVersioning on bucket {bucket}: {error.response["Error"]["Message"]}')

            if versioning == 'Enabled' and mfa_delete == 'Enabled':
                csv_rows.append([
                    bucket,
                    versioning,
                    mfa_delete,
                    'Bucket is protected against ransomware attacks',
                    'None'
                ])
            elif versioning == 'Enabled' and mfa_delete != 'Enabled':
                csv_rows.append([
                    bucket,
                    versioning,
                    mfa_delete,
                    '"Bucket is protected against ransomware attacks, but an attacker may make the bucket vulnerable by disabling object versioning with the s3:PutBucketVersioning permission"',
                    'Enable MFA delete'
                ])
            else:
                csv_rows.append([
                    bucket,
                    versioning,
                    mfa_delete,
                    'Bucket is VULNERABLE to ransomware attacks',
                    'Enable object versioning and MFA delete'
                ])
        except ClientError as error:
            print(f'    {error.response["Error"]["Code"]} error running s3:GetBucketVersioning on bucket {bucket}: {error.response["Error"]["Message"]}')
            # Continue on anyways, doesn't mean every bucket will fail

    csv_file_name = f'{profile_name}_ransomware_bucket_scan_{str(time()).split(".")[0]}.csv'

    if len(csv_rows) > 1:
        with open(f'./{csv_file_name}', 'w+') as f:
            for row in csv_rows:
                f.write(','.join(row) + '\n')
        print(f'\nScan complete, successful results output to ./{csv_file_name}')
    else:
        print('\nScan complete, no successful results to output though...')


def quit(err_msg, err_code=1):
    print(err_msg)
    print('\nQuitting...')
    sys.exit(err_code)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script accepts AWS credentials and scans the target S3 buckets for their object versioning and MFA delete configurations, then outputs the results and a recommendation to a CSV file.')

    parser.add_argument('-p', '--profile', required=False, default=None, help='The AWS CLI profile to use for making API calls. This is usually stored under ~/.aws/credentials. You will be prompted by default.')
    parser.add_argument('-b', '--buckets', required=False, default=None, help='A comma-separated list of S3 buckets in the current account to check. By default, all buckets in the account will be checked.')
    parser.add_argument('-e', '--enable-versioning', required=False, action='store_true', default=False, help='Use the selected profile to try and enable Object Versioning for any buckets that are lacking it. If it succeeds, the output CSV file will show "Enabled", but if it fails, an error will be printed and it will stay as "Disabled". This will attempt to enable versioning for any buckets where it is disabled (including buckets that may have previously had it enabled in the past). NOTE: MFA delete will not be enabled through this process, because it requires the root AWS user to perform that action, so you will need to do that manually if you want to enable it.')

    args = parser.parse_args()

    main(args)
