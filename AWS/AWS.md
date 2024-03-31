IAM Roles to be used to authenticate with AWS instead of Access Keys and their permissions to be managed by Terraform/CloudFormation. Roles would be attached to AWS resources (ECS, EC2, Lambda, CloudFormation, k8s Service, etc.) after which the AWS resources can get temporary credentials which are valid upto 12 hours, based on the configuration. This is transparent to the workloads and can be used for cross account access as well. This is already being used in a lot of places such as EKS Pod Role for Containers, Instance Profile for EC2, etc. Access Keys to be used on exception basis where using IAM Roles is not possible and it would cause business impact.

This example works if your infrastructure is within GCP and you want to access some resource that is within AWS. We are familiar with AWS IAM and how it can be used to grant access to different accounts via AssumeRole API call. Similar to this API call there is another one called `AssumeRoleWithWebIdentity` which allows someone to use get credentials from OAuth 2.0 / OpenID Identity Providers.

1. GCP Service Account Creation
Similar to above command we ned to create a service account withWe need to add “Service Account Token Creator” Role for the service
account top be able to create tokens. Once the Service Account is created, copy the numeric Client ID – you’ll need it for creating the
IAM Identity Provider in AWS step.
2. AWS IAM Role Creation
Now we need to create an AWS IAM role that the GCP CopyCat application will assume while running on an EC2 instance. This role will
be what we use to exchange tokens with GCP. The Unique ID that was copied from above need to be passed while creating a role in the
trust policy for the IAM Role.
The AWS IAM Role Trust Policy would look something like this -
This is an example of how you can get credentials for AWS from GCP and use those to perform actions -
```
    {
        "Version": "2012-10-17",
        "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "accounts.google.com"
            },
            "Condition": {
                "StringEquals": 
                {
                    "accounts.google.com:aud": [ "<Unique ID of the GCP Service Account>" ]
                }
            }
        }]
    }
```

```
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
    url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience="

    # Get the service token
    r = requests.get(url, headers=METADATA_HEADERS)
    token = r.text

    # Turn the token into AWS credentials
    sts = boto3.client('sts')
    response = sts.assume_role_with_web_identity(RoleArn=<IAM Role ARN that would be Assumed>, WebIdentityToken=toke
    new_session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'], aws_secret_access_key=resp
    
    s3 = new_session.client("s3")
    response = s3.list_buckets()

    # Output the bucket names
    print('Existing buckets:')
    for bucket in response['Buckets']:
        print(f' {bucket["Name"]}')
```