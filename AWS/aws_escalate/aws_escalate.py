#!/usr/bin/env python3
import boto3
import argparse
import sys
import time
import re

from botocore.exceptions import ClientError, ProfileNotFound


def main(args):
    if args.profile is None:
        session = boto3.Session()
        print('No AWS CLI profile passed in, choose one below or rerun the script using the -p/--profile argument:')
        profiles = session.available_profiles
        for i in range(0, len(profiles)):
            print('[{}] {}'.format(i, profiles[i]))
        profile_number = int(input('Choose a profile (Ctrl+C to exit): ').strip())
        profile_name = profiles[profile_number]
        session = boto3.Session(profile_name=profile_name)
    else:
        try:
            profile_name = args.profile
            session = boto3.Session(profile_name=profile_name)
        except ProfileNotFound as error:
            print('Did not find the specified AWS CLI profile: {}\n'.format(args.profile))

            session = boto3.Session()
            print('Profiles that are available: {}\n'.format(session.available_profiles))
            print('Quitting...\n')
            sys.exit(1)

    users = []
    roles = []

    client = session.client('iam')

    # List users
    response = client.list_users()
    for user in response['Users']:
        users.append({'UserName': user['UserName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
    while response.get('IsTruncated'):
        response = client.list_users(
            Marker=response['Marker']
        )
        for user in response['Users']:
            users.append({'UserName': user['UserName'], 'Permissions': {'Allow': {}, 'Deny': {}}})

    # List roles
    response = client.list_roles()
    for role in response['Roles']:
        roles.append({'RoleName': role['RoleName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
    while response.get('IsTruncated'):
        response = client.list_roles(
            Marker=response['Marker']
        )
        for role in response['Roles']:
            roles.append({'RoleName': role['RoleName'], 'Permissions': {'Allow': {}, 'Deny': {}}})

    # Get user permissions
    print('Enumerating permissions for {} users...'.format(len(users)))
    for user in users:
        user['Groups'] = []
        user['Policies'] = []
        try:
            policies = []

            # Get groups that the user is in
            try:
                res = client.list_groups_for_user(
                    UserName=user['UserName']
                )
                user['Groups'] = res['Groups']
                while res.get('IsTruncated'):
                    res = client.list_groups_for_user(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    user['Groups'] += res['Groups']
            except ClientError as e:
                print('List groups for user failed: {}'.format(e))

            # Get inline and attached group policies
            for group in user['Groups']:
                group['Policies'] = []
                # Get inline group policies
                try:
                    res = client.list_group_policies(
                        GroupName=group['GroupName']
                    )
                    policies = res['PolicyNames']
                    while res.get('IsTruncated'):
                        res = client.list_group_policies(
                            GroupName=group['GroupName'],
                            Marker=res['Marker']
                        )
                        policies += res['PolicyNames']
                except ClientError as e:
                    print('List group policies failed: {}'.format(e))
                # Get document for each inline policy
                for policy in policies:
                    group['Policies'].append({  # Add policies to list of policies for this group
                        'PolicyName': policy
                    })
                    try:
                        document = client.get_group_policy(
                            GroupName=group['GroupName'],
                            PolicyName=policy
                        )['PolicyDocument']
                    except ClientError as e:
                        print('Get group policy failed: {}'.format(e))
                    user = parse_document(document, user)

                # Get attached group policies
                attached_policies = []
                try:
                    res = client.list_attached_group_policies(
                        GroupName=group['GroupName']
                    )
                    attached_policies = res['AttachedPolicies']
                    while res.get('IsTruncated'):
                        res = client.list_attached_group_policies(
                            GroupName=group['GroupName'],
                            Marker=res['Marker']
                        )
                        attached_policies += res['AttachedPolicies']
                    group['Policies'] += attached_policies
                except ClientError as e:
                    print('List attached group policies failed: {}'.format(e))
                user = parse_attached_policies(client, attached_policies, user)

            # Get inline user policies
            policies = []
            if 'Policies' not in user:
                user['Policies'] = []
            try:
                res = client.list_user_policies(
                    UserName=user['UserName']
                )
                policies = res['PolicyNames']
                while res.get('IsTruncated'):
                    res = client.list_user_policies(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    policies += res['PolicyNames']
                for policy in policies:
                    user['Policies'].append({
                        'PolicyName': policy
                    })
            except ClientError as e:
                print('List user policies failed: {}'.format(e))
            # Get document for each inline policy
            for policy in policies:
                try:
                    document = client.get_user_policy(
                        UserName=user['UserName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except ClientError as e:
                    print('Get user policy failed: {}'.format(e))
                user = parse_document(document, user)
            # Get attached user policies
            attached_policies = []
            try:
                res = client.list_attached_user_policies(
                    UserName=user['UserName']
                )
                attached_policies = res['AttachedPolicies']
                while res.get('IsTruncated'):
                    res = client.list_attached_user_policies(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    attached_policies += res['AttachedPolicies']
                user['Policies'] += attached_policies
            except ClientError as e:
                print('List attached user policies failed: {}'.format(e))
            user = parse_attached_policies(client, attached_policies, user)
            user.pop('Groups', None)
            user.pop('Policies', None)
        except Exception as e:
            print('Error, skipping user {}:\n{}'.format(user['UserName'], e))
        print('  {}... done!'.format(user['UserName']))

    # Get role permissions
    print('\nEnumerating permissions for {} roles...'.format(len(roles)))
    for role in roles:
        role['Policies'] = []
        try:
            policies = []

            # Get inline role policies
            policies = []
            if 'Policies' not in role:
                role['Policies'] = []
            try:
                res = client.list_role_policies(
                    RoleName=role['RoleName']
                )
                policies = res['PolicyNames']
                while res.get('IsTruncated'):
                    res = client.list_role_policies(
                        RoleName=role['RoleName'],
                        Marker=res['Marker']
                    )
                    policies += res['PolicyNames']
                for policy in policies:
                    role['Policies'].append({
                        'PolicyName': policy
                    })
            except ClientError as e:
                print('List role policies failed: {}'.format(e))
            # Get document for each inline policy
            for policy in policies:
                try:
                    document = client.get_role_policy(
                        RoleName=role['RoleName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except ClientError as e:
                    print('Get role policy failed: {}'.format(e))
                role = parse_document(document, role)
            # Get attached role policies
            attached_policies = []
            try:
                res = client.list_attached_role_policies(
                    RoleName=role['RoleName']
                )
                attached_policies = res['AttachedPolicies']
                while res.get('IsTruncated'):
                    res = client.list_attached_role_policies(
                        RoleName=role['RoleName'],
                        Marker=res['Marker']
                    )
                    attached_policies += res['AttachedPolicies']
                role['Policies'] += attached_policies
            except ClientError as e:
                print('List attached role policies failed: {}'.format(e))
            role = parse_attached_policies(client, attached_policies, role)
            role.pop('Policies', None)
        except Exception as e:
            print('Error, skipping role {}:\n{}'.format(role['RoleName'], e))
        print('  {}... done!'.format(role['RoleName']))

    # Begin privesc scanning
    all_user_permissions = [
        'cloudformation:CreateStack',
        'codestar:AssociateTeamMember',
        'codestar:CreateProject',
        'codestar:CreateProjectFromTemplate',
        'datapipeline:CreatePipeline',
        'datapipeline:PutPipelineDefinition',
        'dynamodb:CreateTable',
        'dynamodb:PutItem',
        'ec2:RunInstances',
        'glue:CreateDevEndpoint',
        'glue:GetDevEndpoint',
        'glue:UpdateDevEndpoint',
        'iam:AddUserToGroup',
        'iam:AttachGroupPolicy',
        'iam:AttachRolePolicy',
        'iam:AttachUserPolicy',
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'iam:CreatePolicyVersion',
        'iam:PassRole',
        'iam:PutGroupPolicy',
        'iam:PutRolePolicy',
        'iam:PutUserPolicy',
        'iam:SetDefaultPolicyVersion',
        'iam:UpdateAssumeRolePolicy',
        'iam:UpdateLoginProfile',
        'lambda:AddPermission',
        'lambda:CreateEventSourceMapping',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'lambda:UpdateFunctionCode',
        'lambda:UpdateFunctionConfiguration',
        'sagemaker:CreatePresignedNotebookInstanceUrl',
        'sagemaker:CreateNotebookInstance',
        'sts:AssumeRole'
    ]

    all_role_permissions = [
        'cloudformation:CreateStack',
        'codestar:CreateProject',
        'datapipeline:CreatePipeline',
        'datapipeline:PutPipelineDefinition',
        'dynamodb:CreateTable',
        'dynamodb:PutItem',
        'ec2:RunInstances',
        'glue:CreateDevEndpoint',
        'glue:GetDevEndpoint',
        'glue:UpdateDevEndpoint',
        'iam:AttachRolePolicy',
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'iam:CreatePolicyVersion',
        'iam:PassRole',
        'iam:PutRolePolicy',
        'iam:SetDefaultPolicyVersion',
        'iam:UpdateAssumeRolePolicy',
        'iam:UpdateLoginProfile',
        'lambda:AddPermission',
        'lambda:CreateEventSourceMapping',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'lambda:UpdateFunctionCode',
        'lambda:UpdateFunctionConfiguration',
        'sagemaker:CreatePresignedNotebookInstanceUrl',
        'sagemaker:CreateNotebookInstance'
    ]

    user_escalation_methods = {
        'CreateNewPolicyVersion': {
            'iam:CreatePolicyVersion': True  # Create new policy and set it as default
        },
        'SetExistingDefaultPolicyVersion': {
            'iam:SetDefaultPolicyVersion': True  # Set a different policy version as default
        },
        'CreateEC2WithExistingIP': {
            'iam:PassRole': True,  # Pass the instance profile/role to the EC2 instance
            'ec2:RunInstances': True  # Run the EC2 instance
        },
        'CreateAccessKey': {
            'iam:CreateAccessKey': True  # Create a new access key for some user
        },
        'CreateLoginProfile': {
            'iam:CreateLoginProfile': True  # Create a login profile for some user
        },
        'UpdateLoginProfile': {
            'iam:UpdateLoginProfile': True  # Update the password for an existing login profile
        },
        'AttachUserPolicy': {
            'iam:AttachUserPolicy': True  # Attach an existing policy to a user
        },
        'AttachGroupPolicy': {
            'iam:AttachGroupPolicy': True  # Attach an existing policy to a group
        },
        'AttachRolePolicy': {
            'iam:AttachRolePolicy': True,  # Attach an existing policy to a role
            'sts:AssumeRole': True  # Assume that role
        },
        'PutUserPolicy': {
            'iam:PutUserPolicy': True  # Alter an existing-attached inline user policy
        },
        'PutGroupPolicy': {
            'iam:PutGroupPolicy': True  # Alter an existing-attached inline group policy
        },
        'PutRolePolicy': {
            'iam:PutRolePolicy': True,  # Alter an existing-attached inline role policy
            'sts:AssumeRole': True  # Assume that role
        },
        'AddUserToGroup': {
            'iam:AddUserToGroup': True  # Add a user to a higher level group
        },
        'UpdateRolePolicyToAssumeIt': {
            'iam:UpdateAssumeRolePolicy': True  # Update the roles AssumeRolePolicyDocument to allow the user to assume it
        },
        'PassExistingRoleToNewLambdaThenInvoke': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:InvokeFunction': True  # Invoke the newly created function
        },
        'PassExistingRoleToNewLambdaThenInvokeCrossAccount': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:AddPermission': True  # Add cross-account invoke permissions to the function
        },
        'PassExistingRoleToNewLambdaThenTriggerWithNewDynamo': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:CreateEventSourceMapping': True,  # Create a trigger for the Lambda function
            'dynamodb:CreateTable': True,  # Create a new table to use as the trigger ^
            'dynamodb:PutItem': True  # Put a new item into the table to trigger the trigger
        },
        'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:CreateEventSourceMapping': True  # Create a trigger for the Lambda function
        },
        'PassExistingRoleToNewGlueDevEndpoint': {
            'iam:PassRole': True,  # Pass the role to the Glue Dev Endpoint
            'glue:CreateDevEndpoint': True,  # Create the new Glue Dev Endpoint
            'glue:GetDevEndpoint': True  # Get the public address of it after creation
        },
        'UpdateExistingGlueDevEndpoint': {
            'glue:UpdateDevEndpoint': True  # Update the associated SSH key for the Glue endpoint
        },
        'PassExistingRoleToNewCloudFormation': {
            'iam:PassRole': True,  # Pass role to the new stack
            'cloudformation:CreateStack': True  # Create the stack
        },
        'PassExistingRoleToNewDataPipeline': {
            'iam:PassRole': True,  # Pass roles to the Pipeline
            'datapipeline:CreatePipeline': True,  # Create the pipieline
            'datapipeline:PutPipelineDefinition': True  # Update the pipeline to do something
        },
        'EditExistingLambdaFunctionWithRole': {
            'lambda:UpdateFunctionCode': True  # Edit existing Lambda functions
        },
        'AddExistingLambdaLayerToLambdaFunctionWithRole': {
            'lambda:UpdateFunctionConfiguration': True  # Edit existing Lambda function configurations
        },
        'PassExistingRoleToNewCodeStarProject': {
            'codestar:CreateProject': True,  # Create the CodeStar project
            'iam:PassRole': True  # Pass the service role to CodeStar
        },
        'CodeStarCreateProjectFromTemplate': {
            'codestar:CreateProjectFromTemplate': True  # Create a project from a template
        },
        'CodeStarCreateProjectThenAssociateTeamMember': {
            'codestar:CreateProject': True,  # Create the CodeStar project
            'codestar:AssociateTeamMember': True  # Associate themselves with the project
        },
        'AccessExistingSageMakerJupyterNotebook': {
            'sagemaker:CreatePresignedNotebookInstanceUrl': True  # Create a pre-signed URL for the target notebook
        },
        'PassRoleToNewSageMakerJupyterNotebook': {
            'sagemaker:CreateNotebookInstance': True,  # Create a new Jupyter notebook
            'sagemaker:CreatePresignedNotebookInstanceUrl': True,  # Create a pre-signed URL for the new notebook
            'iam:PassRole': True  # Pass an IAM role to the new notebook
        }
    }

    role_escalation_methods = {
        'CreateNewPolicyVersion': {
            'iam:CreatePolicyVersion': True  # Create new policy and set it as default
        },
        'SetExistingDefaultPolicyVersion': {
            'iam:SetDefaultPolicyVersion': True  # Set a different policy version as default
        },
        'CreateEC2WithExistingIP': {
            'iam:PassRole': True,  # Pass the instance profile/role to the EC2 instance
            'ec2:RunInstances': True  # Run the EC2 instance
        },
        'CreateAccessKey': {
            'iam:CreateAccessKey': True  # Create a new access key for some user
        },
        'CreateLoginProfile': {
            'iam:CreateLoginProfile': True  # Create a login profile for some user
        },
        'UpdateLoginProfile': {
            'iam:UpdateLoginProfile': True  # Update the password for an existing login profile
        },
        'AttachRolePolicy': {
            'iam:AttachRolePolicy': True  # Attach an existing policy to a role
        },
        'PutRolePolicy': {
            'iam:PutRolePolicy': True  # Alter an existing-attached inline role policy
        },
        'UpdateRolePolicyToAssumeIt': {
            'iam:UpdateAssumeRolePolicy': True  # Update the roles AssumeRolePolicyDocument to allow the user to assume it
        },
        'PassExistingRoleToNewLambdaThenInvoke': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:InvokeFunction': True  # Invoke the newly created function
        },
        'PassExistingRoleToNewLambdaThenInvokeCrossAccount': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:AddPermission': True  # Add cross-account invoke permissions to the function
        },
        'PassExistingRoleToNewLambdaThenTriggerWithNewDynamo': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:CreateEventSourceMapping': True,  # Create a trigger for the Lambda function
            'dynamodb:CreateTable': True,  # Create a new table to use as the trigger ^
            'dynamodb:PutItem': True  # Put a new item into the table to trigger the trigger
        },
        'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo': {
            'iam:PassRole': True,  # Pass the role to the Lambda function
            'lambda:CreateFunction': True,  # Create a new Lambda function
            'lambda:CreateEventSourceMapping': True  # Create a trigger for the Lambda function
        },
        'PassExistingRoleToNewGlueDevEndpoint': {
            'iam:PassRole': True,  # Pass the role to the Glue Dev Endpoint
            'glue:CreateDevEndpoint': True,  # Create the new Glue Dev Endpoint
            'glue:GetDevEndpoint': True  # Get the public address of it after creation
        },
        'UpdateExistingGlueDevEndpoint': {
            'glue:UpdateDevEndpoint': True  # Update the associated SSH key for the Glue endpoint
        },
        'PassExistingRoleToNewCloudFormation': {
            'iam:PassRole': True,  # Pass role to the new stack
            'cloudformation:CreateStack': True  # Create the stack
        },
        'PassExistingRoleToNewDataPipeline': {
            'iam:PassRole': True,  # Pass roles to the Pipeline
            'datapipeline:CreatePipeline': True,  # Create the pipieline
            'datapipeline:PutPipelineDefinition': True  # Update the pipeline to do something
        },
        'EditExistingLambdaFunctionWithRole': {
            'lambda:UpdateFunctionCode': True  # Edit existing Lambda functions
        },
        'AddExistingLambdaLayerToLambdaFunctionWithRole': {
            'lambda:UpdateFunctionConfiguration': True  # Edit existing Lambda function configurations
        },
        'PassExistingRoleToNewCodeStarProject': {
            'codestar:CreateProject': True,  # Create the CodeStar project
            'iam:PassRole': True  # Pass the service role to CodeStar
        },
        'AccessExistingSageMakerJupyterNotebook': {
            'sagemaker:CreatePresignedNotebookInstanceUrl': True  # Create a pre-signed URL for the target notebook
        },
        'PassRoleToNewSageMakerJupyterNotebook': {
            'sagemaker:CreateNotebookInstance': True,  # Create a new Jupyter notebook
            'sagemaker:CreatePresignedNotebookInstanceUrl': True,  # Create a pre-signed URL for the new notebook
            'iam:PassRole': True  # Pass an IAM role to the new notebook
        }
    }

    for user in users:
        print('\nUser: {}'.format(user['UserName']))
        checked_perms = {'Allow': {}, 'Deny': {}}
        if 'Permissions' in user and 'Allow' in user['Permissions']:
            # Are they an admin already?
            if '*' in user['Permissions']['Allow'] and user['Permissions']['Allow']['*']['Resources'] == ['*']:
                if user['Permissions']['Deny'] == {} and user['Permissions']['Allow']['*']['Conditions'] == []:
                    user['CheckedMethods'] = {'admin': {}, 'Confirmed': {}, 'Potential': {}}
                    print('  Already an admin!')
                    continue
                else:
                    user['CheckedMethods'] = {'possible_admin': {}, 'Confirmed': {}, 'Potential': {}}
                    print('  Might already be an admin, check any explicit denies or policy condition keys!')
                    continue
            for perm in all_user_permissions:
                for effect in ['Allow', 'Deny']:
                    if perm in user['Permissions'][effect]:
                        checked_perms[effect][perm] = user['Permissions'][effect][perm]
                    else:
                        for user_perm in user['Permissions'][effect].keys():
                            if '*' in user_perm:
                                pattern = re.compile(user_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = user['Permissions'][effect][user_perm]

        checked_methods = {
            'Potential': [],
            'Confirmed': []
        }

        # Ditch each escalation method that has been confirmed not to be possible
        for method in user_escalation_methods:
            potential = True
            confirmed = True
            for perm in user_escalation_methods[method]:
                if perm not in checked_perms['Allow']:  # If this permission isn't Allowed, then this method won't work
                    potential = confirmed = False
                    break
                elif perm in checked_perms['Deny'] and perm in checked_perms['Allow']:  # Permission is both Denied and Allowed, leave as potential, not confirmed
                    confirmed = False
                elif perm in checked_perms['Allow'] and perm not in checked_perms['Deny']:  # It is Allowed and not Denied
                    if not checked_perms['Allow'][perm]['Resources'] == ['*']:
                        confirmed = False
            if confirmed is True:
                print('  CONFIRMED: {}'.format(method))
                checked_methods['Confirmed'].append(method)
            elif potential is True:
                print('  POTENTIAL: {}'.format(method))
                checked_methods['Potential'].append(method)
        user['CheckedMethods'] = checked_methods
        if checked_methods['Potential'] == [] and checked_methods['Confirmed'] == []:
            print('  No methods possible.')

    for role in roles:
        print('\nRole: {}'.format(role['RoleName']))
        checked_perms = {'Allow': {}, 'Deny': {}}
        if 'Permissions' in role and 'Allow' in role['Permissions']:
            # Are they an admin already?
            if '*' in role['Permissions']['Allow'] and role['Permissions']['Allow']['*']['Resources'] == ['*']:
                if role['Permissions']['Deny'] == {} and role['Permissions']['Allow']['*']['Conditions'] == []:
                    role['CheckedMethods'] = {'admin': {}, 'Confirmed': {}, 'Potential': {}}
                    print('  Already an admin!')
                    continue
                else:
                    role['CheckedMethods'] = {'possible_admin': {}, 'Confirmed': {}, 'Potential': {}}
                    print('  Might already be an admin, check any explicit denies or policy condition keys!')
                    continue
            for perm in all_role_permissions:
                for effect in ['Allow', 'Deny']:
                    if perm in role['Permissions'][effect]:
                        checked_perms[effect][perm] = role['Permissions'][effect][perm]
                    else:
                        for role_perm in role['Permissions'][effect].keys():
                            if '*' in role_perm:
                                pattern = re.compile(role_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = role['Permissions'][effect][role_perm]

        checked_methods = {
            'Potential': [],
            'Confirmed': []
        }

        # Ditch each escalation method that has been confirmed not to be possible
        for method in role_escalation_methods:
            potential = True
            confirmed = True
            for perm in role_escalation_methods[method]:
                if perm not in checked_perms['Allow']:  # If this permission isn't Allowed, then this method won't work
                    potential = confirmed = False
                    break
                elif perm in checked_perms['Deny'] and perm in checked_perms['Allow']:  # Permission is both Denied and Allowed, leave as potential, not confirmed
                    confirmed = False
                elif perm in checked_perms['Allow'] and perm not in checked_perms['Deny']:  # It is Allowed and not Denied
                    if not checked_perms['Allow'][perm]['Resources'] == ['*']:
                        confirmed = False
            if confirmed is True:
                print('  CONFIRMED: {}'.format(method))
                checked_methods['Confirmed'].append(method)
            elif potential is True:
                print('  POTENTIAL: {}'.format(method))
                checked_methods['Potential'].append(method)
        role['CheckedMethods'] = checked_methods
        if checked_methods['Potential'] == [] and checked_methods['Confirmed'] == []:
            print('  No methods possible.')

    # Generate and output the CSV
    now = time.time()

    # Combine user and role methods into one for the headers
    all_escalation_methods = list(user_escalation_methods) + list(role_escalation_methods)
    headers = ','.join(list(set(all_escalation_methods)))

    output_file_name = 'all_privesc_scan_results_{}.csv'.format(now)

    with open(output_file_name, 'w+') as file:
        for method in headers.split(','):
            file.write(',{}'.format(method))
        file.write('\n')

        for user in users:
            file.write('{},'.format(user['UserName']))
            for method in headers.split(','):
                if 'admin' in user['CheckedMethods']:
                    file.write('Already admin,')
                elif 'possible_admin' in user['CheckedMethods']:
                    file.write('Possibly admin,')
                elif method in user['CheckedMethods']['Confirmed']:
                    file.write('Confirmed,')
                elif method in user['CheckedMethods']['Potential']:
                    file.write('Potential,')
                else:
                    file.write(',')

            file.write('\n')

        for role in roles:
            file.write('{},'.format(role['RoleName']))
            for method in headers.split(','):
                if 'admin' in role['CheckedMethods']:
                    file.write('Already admin,')
                elif 'possible_admin' in role['CheckedMethods']:
                    file.write('Possibly admin,')
                elif method in role['CheckedMethods']['Confirmed']:
                    file.write('Confirmed,')
                elif method in role['CheckedMethods']['Potential']:
                    file.write('Potential,')
                else:
                    file.write(',')

            file.write('\n')

        print('\nPrivilege escalation check completed. Results stored to {}'.format(output_file_name))


# https://stackoverflow.com/a/24893252
def remove_empty_from_dict(d):
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d


# Pull permissions from each policy document
def parse_attached_policies(client, attached_policies, user):
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyArn'])
        user = parse_document(document, user)
    return user


# Get the policy document of an attached policy
def get_attached_policy(client, policy_arn):
    try:
        policy = client.get_policy(
            PolicyArn=policy_arn
        )['Policy']
        version = policy['DefaultVersionId']
        can_get = True
    except ClientError as e:
        print('Get policy failed: {}'.format(e))
        return False

    try:
        if can_get:
            document = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )['PolicyVersion']['Document']
            return document
    except ClientError as e:
        print('Get policy version failed: {}'.format(e))
        return False


# Loop permissions and the resources they apply to
def parse_document(document, user):
    if isinstance(document['Statement'], dict):
        document['Statement'] = [document['Statement']]

    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and isinstance(statement['Action'], list):  # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Allow']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow'][action]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][action]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Allow'][action] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow'][action]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][action]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                            user['Permissions']['Allow'][action]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Allow'][action]['Resources'] = list(set(user['Permissions']['Allow'][action]['Resources']))  # Remove duplicate resources
            elif 'Action' in statement and isinstance(statement['Action'], str):
                if statement['Action'] in user['Permissions']['Allow']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow'][statement['Action']]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Allow'][statement['Action']] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow'][statement['Action']]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Allow'][statement['Action']]['Conditions'].append(statement['Condition'])
                user['Permissions']['Allow'][statement['Action']]['Resources'] = list(set(user['Permissions']['Allow'][statement['Action']]['Resources']))  # Remove duplicate resources

            if 'NotAction' in statement and isinstance(statement['NotAction'], list):  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if '!{}'.format(not_action) in user['Permissions']['Allow']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Allow']['!{}'.format(not_action)] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Allow']['!{}'.format(not_action)]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Allow']['!{}'.format(not_action)]['Resources'] = list(set(user['Permissions']['Allow']['!{}'.format(not_action)]['Resources']))  # Remove duplicate resources
            elif 'NotAction' in statement and isinstance(statement['NotAction'], str):
                if '!{}'.format(statement['NotAction']) in user['Permissions']['Allow']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Conditions'].append(statement['Condition'])
                user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources'] = list(set(user['Permissions']['Allow']['!{}'.format(statement['NotAction'])]['Resources']))  # Remove duplicate resources

        if statement['Effect'] == 'Deny':
            if 'Action' in statement and isinstance(statement['Action'], list):
                statement['Action'] = list(set(statement['Action']))  # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Deny']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny'][action]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][action]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Deny'][action] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny'][action]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][action]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Deny'][action]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Deny'][action]['Resources'] = list(set(user['Permissions']['Deny'][action]['Resources']))  # Remove duplicate resources
            elif 'Action' in statement and isinstance(statement['Action'], str):
                if statement['Action'] in user['Permissions']['Deny']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny'][statement['Action']]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Deny'][statement['Action']] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny'][statement['Action']]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Deny'][statement['Action']]['Conditions'].append(statement['Condition'])
                user['Permissions']['Deny'][statement['Action']]['Resources'] = list(set(user['Permissions']['Deny'][statement['Action']]['Resources']))  # Remove duplicate resources

            if 'NotAction' in statement and isinstance(statement['NotAction'], list):  # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction']))  # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if '!{}'.format(not_action) in user['Permissions']['Deny']:
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] += statement['Resource']
                        else:
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'].append(statement['Resource'])
                    else:
                        user['Permissions']['Deny']['!{}'.format(not_action)] = {'Resources': [], 'Conditions': []}
                        if isinstance(statement['Resource'], list):
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = statement['Resource']
                        else:
                            user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = [statement['Resource']]
                    if 'Condition' in statement:
                        user['Permissions']['Deny']['!{}'.format(not_action)]['Conditions'].append(statement['Condition'])
                    user['Permissions']['Deny']['!{}'.format(not_action)]['Resources'] = list(set(user['Permissions']['Deny']['!{}'.format(not_action)]['Resources']))  # Remove duplicate resources
            elif 'NotAction' in statement and isinstance(statement['NotAction'], str):
                if '!{}'.format(statement['NotAction']) in user['Permissions']['Deny']:
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] += statement['Resource']
                    else:
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'].append(statement['Resource'])
                else:
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])] = {'Resources': [], 'Conditions': []}
                    if isinstance(statement['Resource'], list):
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = statement['Resource']
                    else:
                        user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = [statement['Resource']]  # Make sure that resources are always arrays
                if 'Condition' in statement:
                    user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Conditions'].append(statement['Condition'])
                user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources'] = list(set(user['Permissions']['Deny']['!{}'.format(statement['NotAction'])]['Resources']))  # Remove duplicate resources
    return user


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script will fetch permissions for all IAM users and roles and then scan for permission misconfigurations to see what privilege escalation methods each are vulnerable to. Available attack paths will be output to a .csv file in the same directory.')

    parser.add_argument('-p', '--profile', required=False, default=None, help='The AWS CLI profile to use for making API calls. This is usually stored under ~/.aws/credentials. You will be prompted by default.')

    args = parser.parse_args()
    main(args)
