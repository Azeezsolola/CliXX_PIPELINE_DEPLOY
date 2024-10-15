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


#Enabling VPC DNS Resolution
vpcresolution=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = vpcresolution.modify_vpc_attribute(
    EnableDnsHostnames={
        'Value': True
    },
    VpcId=vpcid,
    
)
print(vpcresolution)

#Enabling DNS support in the VPC
vpcresolution2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = vpcresolution2.modify_vpc_attribute(
    EnableDnsSupport={
        'Value': True
     },
    VpcId=vpcid
)
    
print(vpcresolution2)




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



"""

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

"""

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




#Creating private subnet 2 for RDS
subnetpriv=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = subnetpriv.create_subnet(
    TagSpecifications=[
        {
            'ResourceType': 'subnet',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'privatesub2'
                }
            ]
        }
    ],
    AvailabilityZone='us-east-1b',
    CidrBlock='10.0.2.0/24',
    VpcId=vpcid,
    DryRun=False
)
print(response)
privatesubnetid2=response['Subnet']['SubnetId']
print(privatesubnetid2)




#Associating route tabel with private subnet 
igwass3=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = igwass3.associate_route_table(
    #GatewayId=intgwid,
    DryRun=False,
    SubnetId=privatesubnetid2,
    RouteTableId=privateroutetableid
)

print(response)



#Creating RDS group for RDS DB
rdsdbsub = boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = rdsdbsub.create_db_subnet_group(
    DBSubnetGroupName='rdsdbsubgroup',
    DBSubnetGroupDescription='Two private subnets',
    SubnetIds=[privatesubnetid2,privatesubnetid],
    Tags=[
            {
                'Key': 'Name',
                'Value': 'rdsdbsubnetgroup'
            }
            
        ]
)
print(response)



"""
# Create RDS DB
rds_client = boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
# Restore DB instance from snapshot
response = rds_client.restore_db_instance_from_db_snapshot(
    DBInstanceIdentifier='wordpressdbclixx-ecs2',
    DBSnapshotIdentifier='arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot',
    DBInstanceClass='db.m6gd.large',
    DBSubnetGroupName='rdsdbsubgroup',
    MultiAZ=True,
    PubliclyAccessible=True,
    VpcSecurityGroupIds=[privsgid]
    )
print(response)

time.sleep(600)
"""


#Creating public subnet 2 because of the load balancer 

subnet2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = subnet2.create_subnet(
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
    CidrBlock='10.0.3.0/24',
    VpcId=vpcid,
    DryRun=False
)
print(response)
publicsubnetid2=response['Subnet']['SubnetId']
print(publicsubnetid2)



#Associating route table to newly created public subnet  
igwass5=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = igwass5.associate_route_table(
    #GatewayId=intgwid,
    DryRun=False,
    SubnetId=publicsubnetid2,
    RouteTableId=routetableid
)

print(response)



#Creating Load balancer 
elb=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb.create_load_balancer(
    Name='autoscalinglb2-azeez',
    Subnets=[publicsubnetid2,publicsubnetid],
    SecurityGroups=[pubsgid],
    Scheme='internet-facing',
    
    Tags=[
        {
            'Key': 'OwnerEmail',
            'Value': 'azeezsolola14+development@outlook.com'
        },
    ],
    Type='application',
    IpAddressType='ipv4'
    )

print(response)
loadbalancerarn=response["LoadBalancers"][0]["LoadBalancerArn"]
print(loadbalancerarn)
LBDNS=response["LoadBalancers"][0]["DNSName"]
print(LBDNS)

ELBZONEID=response["LoadBalancers"][0]["CanonicalHostedZoneId"]
print(ELBZONEID)

time.sleep(300)


#Creating Target Group
response = elb.create_target_group(
    Name='clixxautoscalingtg2',
    Protocol='HTTP',
    ProtocolVersion='HTTP1',
    Port=80,
    VpcId=vpcid,
    HealthCheckProtocol='HTTP',
    HealthCheckEnabled=True,
    HealthCheckIntervalSeconds=300,
    HealthCheckTimeoutSeconds=120,
    HealthCheckPort='80',
    HealthCheckPath='/',
    HealthyThresholdCount=2,
    UnhealthyThresholdCount=5,
    TargetType='instance',
    Matcher={
        'HttpCode': "200,301"
        
    },
    
    IpAddressType='ipv4'
)

targetgrouparn=response['TargetGroups'][0]['TargetGroupArn']
print(targetgrouparn)


#Creating listner on load balancer and attaching taregt group
elb1 = boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb1.create_listener(
    LoadBalancerArn=loadbalancerarn, 
    Port=443,
    Protocol='HTTPS',
    Certificates=[  
        {
            'CertificateArn': 'arn:aws:acm:us-east-1:495599767034:certificate/c4b0e3bc-b06f-42f5-b26b-e631e9720f8a'  
        }
    ],
    DefaultActions=[
        {
            'Type': 'forward',
            'TargetGroupArn': targetgrouparn  
        }
    ]
)
listener_arn = response['Listeners'][0]['ListenerArn']
print(listener_arn)