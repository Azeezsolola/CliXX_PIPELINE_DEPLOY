#!/usr/bin/python

import boto3,botocore,base64,time

AWS_REGION='us-east-1'


sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)

"""
#Registering Domain Name 
register=boto3.client('route53domains',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
response = register.register_domain(
    DomainName='codebuild-azeez.com',
    
    DurationInYears=1,
    AutoRenew=False,
    AdminContact={
        'FirstName': 'Azeez',
        'LastName': 'solola',
        'ContactType': 'PERSON',
        'OrganizationName': 'codebuild',
        'AddressLine1': '8500 charnwood ct',
        
        'City': 'manassass',
        'State': 'VA',
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+1.2407964613',
        'Email': 'ifeoluwsolola@gmail.com'},
        

    RegistrantContact={
        'FirstName': 'Azeez',
        'LastName': 'Solola',
        'ContactType': 'PERSON',
        'OrganizationName': 'codebuild',
        'AddressLine1': '8500 charnwood ct',
       
        'City': 'manassas',
        'State': 'VA',
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+1.2407964613',
        'Email': 'ifeoluwsolola@gmail.com'},
        

    TechContact={
        'FirstName': 'Azeez',
        'LastName': 'solola',
        'ContactType': 'PERSON',
        'OrganizationName': 'codebuild',
        'AddressLine1': '8500 charnwood ct',
        
        'City': 'manassas',
        'State': 'VA',
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+1.2407964613',
        'Email': 'ifeoluwsolola@gmail.com'},
        

    PrivacyProtectAdminContact=True,
    PrivacyProtectRegistrantContact=True,
    PrivacyProtectTechContact=True,
    BillingContact={
        'FirstName': 'Azeez',
        'LastName': 'solola',
        'ContactType': 'PERSON',
        'OrganizationName': 'codebuild',
        'AddressLine1': '8500 charnwood ct',
 
        'City': 'manassas',
        'State': 'VA',
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+1.2407964613',
        'Email': 'ifeoluwasolola@gmail.com'},
        

    PrivacyProtectBillingContact=True
)

print(response)
"""


hosted_zone=boto3.client('route53',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
response=hosted_zone.list_hosted_zones()
print(response)
output=response["HostedZones"]
print(output)

for zone in output:
    print(f"ID: {zone['Id']}, Name: {zone['Name']}")


domain_name = 'codebuild-azeez.com.'
for zone in response['HostedZones']:
    if zone['Name'] == domain_name:
        print(f"Found hosted zone ID for {domain_name}: {zone['Id']}")
        output2=zone['Id']
        print(output2)