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

response = client.terminate_instances(
    InstanceIds=[
        'i-093df4a3a15d7e3d3',
    ],
)

print(response)

rds=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

response = client.delete_db_instance(
    DBInstanceIdentifier='wordpressdbclixx-ecs',
    SkipFinalSnapshot=False,
    FinalDBSnapshotIdentifier='wordpressdbclixx-ecs-latest',
    DeleteAutomatedBackups=False
)