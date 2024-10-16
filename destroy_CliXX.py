#!/usr/bin/python

import boto3,botocore,time

AWS_REGION='us-east-1'

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)






"""
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
    LoadBalancerArn='arn:aws:elasticloadbalancing:us-east-1:495599767034:loadbalancer/app/autoscalinglb2-azeez/a910059e0c7ab8d3'
)

time.sleep(60)

#Deleting target group
elb2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb2.delete_target_group(
    TargetGroupArn='arn:aws:elasticloadbalancing:us-east-1:495599767034:targetgroup/clixxautoscalingtg2/5c333b72491a31fa'
)

time.sleep(60)

mounttarget=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
for x in ["fsmt-03e028c8bbf9d38c0","fsmt-0f6478a7a5cc0db5d"]:
    response=mounttarget.delete_mount_target(
    MountTargetId=x)



	
time.sleep(80)


#Deleting Autoscaling group
autoscaling = boto3.client('autoscaling', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response =autoscaling.delete_auto_scaling_group(
    AutoScalingGroupName='my-auto-scaling-group',
    ForceDelete=True
)
"""

#Deleting File system
efs=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = efs.delete_file_system(
    FileSystemId='fs-008157e9547d110c3'
)


#Delete subnet group
subgroup=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = subgroup.delete_db_subnet_group(
    DBSubnetGroupName='rdsdbsubgroup'
)


#Delete NAT 
natgate=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = natgate.delete_nat_gateway(
    DryRun=False,
    NatGatewayId='nat-0d9e3fd0f7936ced'
)

time.sleep(60)


#Delete VPC
vpc=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = vpc.delete_vpc(
    VpcId='vpc-0d8db213f182d71d0',
    DryRun=False
)




#Delete TEmplatae 
LT=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = LT.delete_launch_template(
    DryRun=False,
    LaunchTemplateId='lt-09b2a224d820f1645',
    LaunchTemplateName='oloyede'
)