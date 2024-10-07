#!/usr/bin/python

import boto3,botocore

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)



# ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

# response = ec2.delete_security_group(
#     #GroupId='string',
#     GroupName='my-security-group'
#     )
# print(response)



ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

response = ec2.terminate_instances(
    InstanceIds=[
        'i-0f78ad3ea0600b168',
    ],
)

print(response)

rds=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

response = rds.delete_db_instance(
    DBInstanceIdentifier='wordpressdbclixx-ecs',
    SkipFinalSnapshot=False,
    FinalDBSnapshotIdentifier='wordpressdbclixx-ecs-latest2',
    DeleteAutomatedBackups=False
)