#!/usr/bin/python

import boto3,botocore,time

AWS_REGION='us-east-1'

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)




"""
#--------------------Calling ssm to get value of RDS id -------------------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/rdsidentifier', WithDecryption=True)
rdsvalue=response['Parameter']['Value']
print(rdsvalue)

#Deleting RDS
rds_client=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = rds_client.delete_db_instance(
    DBInstanceIdentifier=rdsvalue,
    SkipFinalSnapshot=True
    )

time.sleep(400)



#---------------Caling ssm to get load balacer arn -------------------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/loadbalancer', WithDecryption=True)
loadbalancerarn=response['Parameter']['Value']
print(loadbalancerarn)

#Deleting Load Balancer
elb=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb.delete_load_balancer(
    LoadBalancerArn=loadbalancerarn
)

time.sleep(60)


#-----------------Calling ssm to get target group info----------------------------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/targetgroup', WithDecryption=True)
targetgroup=response['Parameter']['Value']
print(targetgroup)

#Deleting target group
elb2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb2.delete_target_group(
    TargetGroupArn=targetgroup
)

time.sleep(60)

mounttarget=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
for x in ["fsmt-0aee0138c576924f7","fsmt-0a917953edb97de19"]:
    response=mounttarget.delete_mount_target(
    MountTargetId=x)




time.sleep(80)
"""

#-----------calling ssm to get autos caling group info ------------------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/austoscaling', WithDecryption=True)
autoscaling_groupname=response['Parameter']['Value']
print(autoscaling)


#Deleting Autoscaling group
autoscaling = boto3.client('autoscaling', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response =autoscaling.delete_auto_scaling_group(
    AutoScalingGroupName=autoscaling_groupname,
    ForceDelete=True
)


#---------------------calling ssm to get file syatem info -------------------------------------------------------


ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/filesystem', WithDecryption=True)
filesystem=response['Parameter']['Value']
print(filesystem)

#Deleting File system
efs=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = efs.delete_file_system(
    FileSystemId=filesystem
)

"""
#Delete subnet group
subgroup=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = subgroup.delete_db_subnet_group(
    DBSubnetGroupName='rdsdbsubgroup'
)

"""


#---------calling ssm to get nat gateway info ------------------------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/natgateway', WithDecryption=True)
nat=response['Parameter']['Value']
print(nat)


#Delete NAT 
natgate=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = natgate.delete_nat_gateway(
    DryRun=False,
    NatGatewayId=nat
)

time.sleep(60)

"""
#Delete Subnets 
sub=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
for x in ["subnet-0f44a097b73f921f9","subnet-0a955d33be98b8cd0","subnet-040595dd91d9860da","subnet-05aaacd74b93ab16d"]:
    response = sub.delete_subnet(
    SubnetId=x,
    DryRun=False
)

time.sleep(60)


#Deleteing Route tablr
routetab=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
for x in ["rtb-01281a6b30ab260fa","rtb-05adba18a2f3d870e"]:
    response = routetab.delete_route_table(
        DryRun=False,
        RouteTableId=x
    )
    




#Delete SG
SG=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = SG.delete_security_group(
    GroupId='sg-0f7c765dabbc65bf0',
    GroupName='pubsubnetSG',
    DryRun=False
)



SG2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = SG2.delete_security_group(
    GroupId='sg-04fbcae0ecb5ed9fe',
    GroupName='privatesubnetSG',
    DryRun=False
)

"""

#------calling to get template info --------------------------------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/targetgroup', WithDecryption=True)
template=response['Parameter']['Value']
print(template)

#Delete TEmplatae 
LT=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = LT.delete_launch_template(
    DryRun=False,
    LaunchTemplateId=template
    
)


# #Deleting Internet Gateway
# igw=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
# response = igw.delete_internet_gateway(
#     DryRun=False,
#     InternetGatewayId='igw-0730a7a29d5b96635'
# )

time.sleep(300)

#-----------------calling ssm to vpc info ----------------------------------

ssm=boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = ssm.get_parameter(Name='/myapp/vpcid', WithDecryption=True)
vpc=response['Parameter']['Value']
print(vpc)

#Delete VPC
vpc=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = vpc.delete_vpc(
    VpcId=vpc,
    DryRun=False
)






