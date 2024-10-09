#!/usr/bin/python

import boto3,botocore,base64,time

AWS_REGION='us-east-1'


sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)


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
        
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+12407964613',
        'Email': 'ifeoluwsolola@gmail.com'},
        

    RegistrantContact={
        'FirstName': 'Azeez',
        'LastName': 'Solola',
        'ContactType': 'PERSON',
        'OrganizationName': 'codebuild',
        'AddressLine1': '8500 charnwood ct',
       
        'City': 'manassas',
       
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+12407964613',
        'Email': 'ifeoluwsolola@gmail.com'},
        

    TechContact={
        'FirstName': 'Azeez',
        'LastName': 'solola',
        'ContactType': 'PERSON',
        'OrganizationName': 'codebuild',
        'AddressLine1': '8500 charnwood ct',
        
        'City': 'manassas',
        
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+12407964613',
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
       
        'CountryCode': 'US',
        'ZipCode': '20111',
        'PhoneNumber': '+12407964613',
        'Email': 'ifeoluwasolola@gmail.com'},
        

    PrivacyProtectBillingContact=True
)

print(response)