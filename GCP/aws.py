#!/usr/bin/env python3

import json
import urllib
import boto3
import re
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import google.auth

def main():
    project_number = "my-project-number"
    pool_id = "my-pool-id"
    provider_id = "my-provider-id"
    
    credentials, project_id = google.auth.default()

    # Prepare a GetCallerIdentity request.
    request = AWSRequest(method="POST", url="https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", headers={
            "Host": "sts.amazonaws.com",
            "x-goog-cloud-target-resource": f"//iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}",
        },
    )
    SigV4Auth(boto3.Session().get_credentials(), "sts", "us-east-1").add_auth(request)

    # Create token from signed request.
    token = {"url": request.url, "method": request.method, "headers": []}
    for key, value in request.headers.items():
        token["headers"].append({"key": key, "value": value})

    # The token lets workload identity federation verify the identity without revealing the AWS secret access key.
    print("Token:\n%s" % json.dumps(token, indent=2, sort_keys=True))
    print("URL encoded token:\n%s" % urllib.parse.quote(json.dumps(token)))


if __name__ == "__main__":
    main()