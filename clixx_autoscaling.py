#!/usr/bin/python

import boto3,botocore,base64,time

AWS_REGION='us-east-1'


sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)


 # Create RDS client 
rds_client = boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
# Restore DB instance from snapshot
response = rds_client.restore_db_instance_from_db_snapshot(
    DBInstanceIdentifier='wordpressdbclixx-ecs',
    DBSnapshotIdentifier='arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot',
    DBInstanceClass='db.m6gd.large',
    AvailabilityZone='us-east-1a',
    MultiAZ=False,
    PubliclyAccessible=True,
    VpcSecurityGroupIds=['sg-0fef030fc2befbb1e']
    )
print(response)

#time.sleep(300)










#Creating Load balancer 

elb=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = elb.create_load_balancer(
    Name='autoscalinglb',
    Subnets=['subnet-018e197bd500d943a','subnet-0ecd44e7315ae879d'],
    SecurityGroups=['sg-0fef030fc2befbb1e'],
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
output=response["LoadBalancers"][0]["LoadBalancerArn"]
print(output)

#time.sleep(300)



#Creating Target Group
response = elb.create_target_group(
    Name='clixxautoscalingtg',
    Protocol='HTTP',
    ProtocolVersion='HTTP1',
    Port=80,
    VpcId='vpc-0c6460b8c3c8fe62f',
    HealthCheckProtocol='HTTP',
    HealthCheckEnabled=True,
    HealthCheckIntervalSeconds=300,
    HealthCheckTimeoutSeconds=120,
    HealthyThresholdCount=2,
    UnhealthyThresholdCount=5,
    TargetType='instance',
    
    IpAddressType='ipv4'
)

targetgrouparn=response['TargetGroups'][0]['TargetGroupArn']
print(targetgrouparn)



elb1 = boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response= elb1.create_listener(
    LoadBalancerArn=output, 
    Port=80,
    Protocol='HTTP',
    DefaultActions=[
        {
            'Type': 'forward',
            'TargetGroupArn': targetgrouparn  
        }
    ]
)

listener_arn = response['Listeners'][0]['ListenerArn']
print(listener_arn)




#Creating Launch Template 

AWS_REGION='us-east-1'
USER_DATA="""#!/bin/bash
##Install the needed packages and enable the services(MariaDb, Apache)
sudo yum update -y

#Get Ipaddress
#IP_ADDRESS=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

#Mounting 
sudo yum install -y nfs-utils
FILE_SYSTEM_ID=fs-07640ca8a3d9ca32f
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone )
REGION=${AVAILABILITY_ZONE:0:-1}
MOUNT_POINT=/var/www/html
sudo mkdir -p ${MOUNT_POINT}
sudo chown ec2-user:ec2-user ${MOUNT_POINT}
sudo echo ${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0 >> /etc/fstab
sudo mount -a -t nfs4
sudo chmod -R 755 /var/www/html

sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl is-enabled httpd
 
##Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;
cd /var/www/html
 
#Install wordpress and unzip it/copy the sample php conf to wp-config
##sudo wget https://wordpress.org/latest.tar.gz
##sudo tar -xzf latest.tar.gz
##cp wordpress/wp-config-sample.php wordpress/wp-config.php
##start the mariadb and create a database/user and grant priv
 
 if [ -f /var/www/html/wp-config.php ]
 then
    echo "wp-config.php already exists"
    
else
    echo "wp-config.php does not exist"
    git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
fi
        


#git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
cp -r CliXX_Retail_Repository/* /var/www/html
 
## set Wordpress to run in an alternative directory
#sudo mkdir /var/www/html/blog
#sudo cp -r wordpress/* /var/www/html/
 
## Allow wordpress to use Permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf
sudo sed -i 's/wordpress-db.cc5iigzknvxd.us-east-1.rds.amazonaws.com/wordpressdbclixx-ecs.cn2yqqwoac4e.us-east-1.rds.amazonaws.com/' /var/www/html/wp-config.php
if [ $? == 0 ]
then
    echo "sed was done"
else
    echo "sed was not done"
fi

DNS=$(curl http://169.254.169.254/latest/meta-data/public-hostname)
echo $DNS

output_variable=$(mysql -u wordpressuser -p -h wordpressdbclixx-ecs.cn2yqqwoac4e.us-east-1.rds.amazonaws.com -D wordpressdb -pW3lcome123 -sse "select option_value from wp_options where option_value like 'CliXX-APP-%';")
echo $output_variable

if [ output_variable == ${DNS} ]
then
    echo "DNS Address in the the table"
else
    echo "DNS Address is not in the table"
    #Logging DB
    mysql -u wordpressuser -p -h wordpressdbclixx-ecs.cn2yqqwoac4e.us-east-1.rds.amazonaws.com -D wordpressdb -pW3lcome123<<EOF
    UPDATE wp_options SET option_value ='${DNS}' WHERE option_value LIKE 'CliXX-APP-%';
EOF
fi

##Grant file ownership of /var/www & its contents to apache user
sudo chown -R apache /var/www
 
##Grant group ownership of /var/www & contents to apache group
sudo chgrp -R apache /var/www
 
##Change directory permissions of /var/www & its subdir to add group write 
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
 
##Recursively change file permission of /var/www & subdir to add group write perm
sudo find /var/www -type f -exec sudo chmod 0664 {} \;
 
##Restart Apache
sudo systemctl restart httpd
sudo service httpd restart
 
##Enable httpd 
sudo systemctl enable httpd 
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5
"""

encoded_user_data = base64.b64encode(USER_DATA.encode('utf-8')).decode('utf-8')

ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response=ec2.create_launch_template(
    DryRun=False,
    LaunchTemplateName='codebuild',
    VersionDescription='webserver1',
    LaunchTemplateData={
        'EbsOptimized': True,     
        'ImageId': 'ami-00f251754ac5da7f0',
        'InstanceType': 't2.micro',       
        'UserData': encoded_user_data,
        'SecurityGroupIds': ['sg-0fef030fc2befbb1e'],
    }
    )

    
print(response)
launchtempid=response["LaunchTemplate"]["LaunchTemplateId"]
print(launchtempid)

launchtempname=response["LaunchTemplate"]["LaunchTemplateName"]
print(launchtempname)




autoscaling = boto3.client('autoscaling', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name=AWS_REGION)
response = autoscaling.create_auto_scaling_group(
    AutoScalingGroupName='codebuild',
    
    LaunchTemplate={
        'LaunchTemplateId': launchtempid
        
       
    },
    
    
    MinSize=1,
    MaxSize=3,
    DesiredCapacity=1,
    DefaultCooldown=300,
 
    LoadBalancerNames=['autoscalinglb'],
    TargetGroupARNs=[targetgrouparn],
  
    HealthCheckGracePeriod=300,
   
   
    Tags=[
        {
           
            'Key': 'Name',
            'Value': 'codebuild',
            'PropagateAtLaunch': True
        }
    ],
   
    
   
    DefaultInstanceWarmup=300,
     VPCZoneIdentifier='subnet-014c00ad60d4e3316,subnet-018e197bd500d943a'

 
)


print(response)
