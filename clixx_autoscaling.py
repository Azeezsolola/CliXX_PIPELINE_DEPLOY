#!/usr/bin/python

import boto3,botocore,base64,time

AWS_REGION='us-east-1'


sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)






#Creating VPC
VPC=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = VPC.create_vpc(
    CidrBlock='10.0.0.0/16',
    TagSpecifications=[
        {
            'ResourceType': 'vpc',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'STACKVPC'
                }
            ]
        }
    ],
    DryRun=False,
    InstanceTenancy='default',
    AmazonProvidedIpv6CidrBlock=False
)

print(response)
vpcid=response['Vpc']['VpcId']
print(vpcid)


#Creating public subnet 

subnet=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = subnet.create_subnet(
    TagSpecifications=[
        {
            'ResourceType': 'subnet',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'publicsub'
                }
            ]
        }
    ],
    AvailabilityZone='us-east-1a',
    CidrBlock='10.0.0.0/24',
    VpcId=vpcid,
    DryRun=False
)
print(response)
publicsubnetid=response['Subnet']['SubnetId']
print(publicsubnetid)


#Creating private subnet 
subnetpub=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = subnetpub.create_subnet(
    TagSpecifications=[
        {
            'ResourceType': 'subnet',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'privatesub'
                }
            ]
        }
    ],
    AvailabilityZone='us-east-1a',
    CidrBlock='10.0.1.0/24',
    VpcId=vpcid,
    DryRun=False
)
print(response)
privatesubnetid=response['Subnet']['SubnetId']
print(privatesubnetid)


#Create internet Gateway
internetgateway=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response =internetgateway.create_internet_gateway(
    TagSpecifications=[
        {
            'ResourceType': 'internet-gateway',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'publicinternetgateway'
                }
            ]
        }
    ],
    DryRun=False
)

print(response)
intgwid=response['InternetGateway']['InternetGatewayId']
print(intgwid)







#internet gateway attachment to the vpc
internetattach=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = internetattach.attach_internet_gateway(
    DryRun=False,
    InternetGatewayId=intgwid,
    VpcId=vpcid
)
print(response)




#Creating Route table
RT=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = RT.create_route_table(
    TagSpecifications=[
        {
            'ResourceType': 'route-table',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'publicRT'
                }
            ]
        }
    ],
    DryRun=False,
    VpcId=vpcid
)

print(response)
routetableid=response['RouteTable']['RouteTableId']
print(routetableid)


#Putting Entry in the public route table
publicRTENTRY=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = publicRTENTRY.create_route(
    RouteTableId=routetableid,       
    DestinationCidrBlock='0.0.0.0/0',  
    GatewayId=intgwid                   
)
print(response)




#Creating NAT gateway
NAT=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = NAT.create_nat_gateway(
    AllocationId='eipalloc-04292754825061e16',
    DryRun=False,
    SubnetId=publicsubnetid,
    TagSpecifications=[
        {
            'ResourceType': 'natgateway',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'NATGW'
                }
            ]
        }
    ]
    
)
print(response)
natid=response['NatGateway']['NatGatewayId']
print(natid)


time.sleep(120)


#Creating private route table
RT2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = RT2.create_route_table(
    TagSpecifications=[
        {
            'ResourceType': 'route-table',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'privateRT'
                }
            ]
        }
    ],
    DryRun=False,
    VpcId=vpcid
)
print(response)
privateroutetableid=response['RouteTable']['RouteTableId']
print(privateroutetableid)


#Creating entry in the private route table
privateRTENTRY=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = privateRTENTRY.create_route(
    RouteTableId=privateroutetableid,       
    DestinationCidrBlock='0.0.0.0/0',  
    NatGatewayId=natid                  
)
print(response)


#Associating route table to public subnet  
igwass=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = igwass.associate_route_table(
    #GatewayId=intgwid,
    DryRun=False,
    SubnetId=publicsubnetid,
    RouteTableId=routetableid
)

print(response)



#Associating route tabel with private subnet 
igwass2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = igwass2.associate_route_table(
    #GatewayId=intgwid,
    DryRun=False,
    SubnetId=privatesubnetid,
    RouteTableId=privateroutetableid
)

print(response)




#Creating security group for instance in the public subnet 
pubsg=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = pubsg.create_security_group(
    Description='public_subnet_SG',
    GroupName='publicsubSG',
    VpcId=vpcid,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'pubsubnetSG'
                }
            ]
        }
    ],
    DryRun=False
)
print(response)
pubsgid=response['GroupId']
print(pubsgid)



#Adding Rules to security Group
pubrule1=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)

response=pubrule1.authorize_security_group_ingress(
    GroupId=pubsgid,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  
        }
    ]
)

pubrule2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response=pubrule2.authorize_security_group_ingress(
    GroupId=pubsgid,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  
        }
    ]
)



pubrule3=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)

response=pubrule3.authorize_security_group_ingress(
    GroupId=pubsgid,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 443,
            'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  
        }
    ]
)




#Creating security group for private subnet 
privsg=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = privsg.create_security_group(
    Description='private_subnet_SG',
    GroupName='privatesubSG',
    VpcId=vpcid,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'privatesubnetSG'
                }
            ]
        }
    ],
    DryRun=False
)
print(response)
privsgid=response['GroupId']
print(privsgid)


#Adding rules to the private security group
privrule1=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response=privrule1.authorize_security_group_ingress(
    GroupId=privsgid,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 3306,
            'ToPort': 3306,
            'IpRanges': [{'CidrIp': '10.0.0.0/24'}]  
        }
    ]
)

privrule2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response=privrule2.authorize_security_group_ingress(
    GroupId=privsgid,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 2049,
            'ToPort': 2049,
            'IpRanges': [{'CidrIp': '10.0.0.0/24'}]  
        }
    ]
)








