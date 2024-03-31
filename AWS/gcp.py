#!/usr/bin/env python3
#
# This code must run on a VM instance with a service account associated with it.
# The service account must be granted the 'Service Account Token Creator' IAM Role

import requests
import boto3

# Set up the URL to request
AUDIENCE = 'potato'
METADATA_HEADERS = { 'Metadata-Flavor': 'Google' }

# Construct a URL with the audience and format
url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=" + AUDIENCE + "&format=full"

# Get the service token
r = requests.get(url, headers=METADATA_HEADERS)
token = r.text


# Add the the IAM Role Name as command line argument

# Turn the token into AWS credentials
sts = boto3.client('sts')
response = sts.assume_role_with_web_identity(RoleArn="<IAM Role ARN that would be Assumed>", WebIdentityToken=token, RoleSessionName='crosscloudauthentication')

new_session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'], aws_secret_access_key=response['Credentials']['SecretAccessKey'], aws_session_token=response['Credentials']['SessionToken'])
s3 = new_session.client("s3")
response = s3.list_buckets()

# Output the bucket names
print('Existing buckets:')
for bucket in response['Buckets']:
    print(f'  {bucket["Name"]}')