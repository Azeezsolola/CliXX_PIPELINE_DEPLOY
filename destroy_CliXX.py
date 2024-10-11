#!/usr/bin/python

import boto3,botocore,time

AWS_REGION='us-east-1'

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)







#Deleting RDS
rds_client=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = rds_client.delete_db_instance(
    DBInstanceIdentifier='wordpressdbclixx-ecs2',
    SkipFinalSnapshot=True
    )

time.sleep(200)

#Deleting Load Balancer
elb=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb.delete_load_balancer(
    LoadBalancerArn='arn:aws:elasticloadbalancing:us-east-1:495599767034:loadbalancer/app/autoscalinglb2-azeez/df262f1558270169'
)

time.sleep(60)

#Deleting target group
elb2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb2.delete_target_group(
    TargetGroupArn='arn:aws:elasticloadbalancing:us-east-1:495599767034:targetgroup/clixxautoscalingtg2/3b120c7a613dd6b9'
)



"""
#Deleting File system
efs=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = efs.delete_file_system(
    FileSystemId='string'
)



#Deleting Autoscaling group
autoscaling = boto3.client('autoscaling', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response =autoscaling.delete_auto_scaling_group(
    AutoScalingGroupName='string',
    ForceDelete=True
)

"""


