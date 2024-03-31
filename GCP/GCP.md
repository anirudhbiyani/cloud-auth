This example works if your infrastructure is hosted in GCP and you need to access some resource within AWS.
Before we dive into the AWS specifics of authenticating to GCP using workload identity federation, we first need to understand how the
service operates. Workload identity federation contains two components:
Workload identity pools and workload identity providers. Workload identity pools, as the name suggests, is a logical container of external
identities (AWS roles, Azure managed identities, etc.).
Workload identity providers are the entities that contain the relative metadata about the relationship between the external identity
provider (AWS, Azure. etc.) and GCP. For example, providers can contain information like AWS account IDs, IAM role ARNs, etc.
In addition to the above components, there is also the concept of Attribute mappings. Attributes are metadata attached to the external
identity token (more on the tokens below) that supply information to GCP via attribute mappings. Attributes can be combined with conditions
to secure your tokens so that they can only be used by approved external identities during the Workload identity federation process.
Examples of attributes include name, email, or user ID. Complex attribute conditions are outside of the scope of this blog but we do provide
an example to get you started.
This section provides an overview of how you can assign credentials and authenticate to GCP from Amazon Web Services (AWS) without
the use of service account keys. For our example we’ll be using a fictional application called “GCP CopyCat” that is running on an EC2
instance in AWS that copies files from a GCS bucket for analysis.
Before we can dive into our token exchange process we need to configure our AWS and GCP resources. We will be using the gcloud CLI for
the next sections.
1. GCP Service Account Creation
The GCP service account will be what our AWS application will authenticate with in order to access GCS objects. For the below
command substitute your own values where it has a $.
For GCP CopyCat we have added the Storage Object Viewer role to our GCP bucket for the newly created service account.
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31

1
2
3
gcloud iam service-accounts create $SERVICE_ACCOUNT_ID --description="$DESCRIPTION" --display-name="$DISPLAY_NAME
For example: gcloud iam service-accounts create gcp-copycat --description="AWS application that copies GCS object
2. AWS IAM Role Creation
Now we need to create an AWS IAM role that the GCP CopyCat application will assume while running on an EC2 instance. This role will
be what we use to exchange tokens with GCP and access our GCS bucket. For the below command substitute your own values where it
has a $.
3. Workload Identity Pool Creation
Next is our workload identity pool creation. As explained earlier, workload identity pools are logical containers for external identities, like
AWS roles. It is recommended to isolate your pools by AWS environment. For example, one GCP workload identity pool for your AWS
development environment and a separate isolated pool for your production environment.
For the below command substitute your own values where it has a $.
4. Workload Identity Provider Creation
Now that we have our workload identity pool, GCP service account, and AWS IAM role, we need to create our AWS identity provider in
GCP. The below example contains the flag --attribute-condition and is not required to create an identity pool provider. We have included
this additional security configuration as an example of one way to restrict GCP token generation.
5. GCP Service Account Impersonation Binding
The next step in our configuration is to provide the AWS role the ability to impersonate our GCP service account. We do this by binding
the IAM role roles/iam.workloadIdentityUser to the GCP service account. Keep in mind that the below gcloud command expects the GCP
Project NUMBER which is different from your PROJECT ID.
6. Enable Required GCP Services
Finally, we need to enable the Google Security Token Service and the IAM credentials service in our GCP project.
After this has been setup., you can interact from AWS to GCP with short lived token.
This is an example of how you can get credentials for GCP from AWS and use those to perform actions - https://github.com/ScaleSec/gcp-
workload-identity-federation/tree/main/scalesec
_gcp_
workload
_
identity
Workload Identity Federation Token Flow
1 aws iam create-role --role-name $ROLE-NAME --assume-role-policy-document $FILE-LOCATION --description "$DESCRIPT
1 gcloud iam workload-identity-pools create $POOL-ID --location="global" --description="$DESCRIPTION" --display-nam
1 gcloud iam workload-identity-pools providers create-aws $PROVIDER_NAME --location="global" --workload-identity-po
1 gcloud iam service-accounts add-iam-policy-binding $workload_sa_email --role roles/iam.workloadIdentityUser --mem
1 gcloud services enable sts.googleapis.com && gcloud services enable iamcredentials.googleapis.com
1. To begin the token exchange process you first need to generate temporary security credentials for AWS. This can be done with the
AssumeRole or GetSessionToken APIs depending on your use case. We are using an AWS role for our example so we need to use the
AssumeRole API.
Note: Typically you do not need to explicitly generate temporary credentials. The AWS SDK, CLI, etc. automatically get the credentials
for you from the instance metadata. This is only required in this instance to use Workload identity federation to authenticate to GCP.
2. Using the credentials returned by AssumeRole, we can create a GetCallerIdentity token. This token is similar to what we send in a
request with the STS GetCallerIdentity() method. You do not need to call GetCallerIdentity() from your code because we are sending the
token to GCP’s Security token service in the next step.
3. Now that we have our GetCallerIdentity token, we can exchange this for a GCP federated access token. This is done via a HTTP POST
call to the STS URL: https://sts.googleapis.com/v1/token
The GCP STS returns a federated access token which can only be used for a limited number of GCP services for authorization. In order
to interact with all of the GCP services and API endpoints, we need a service account access token.
4. The service account access token is an OAuth 2.0 credential that can be used for GCP authorization in our GCP CopyCat application.
We exchange our federated access token via a HTTP POST to the Cloud IAM URL:
https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA-NAME@$PROJECT-
ID.iam.gserviceaccount.com:generateAccessToken
5. Now that our
_
GCP CopyCa
_
t application has an ephemeral service account access token, we can make calls to the GCS API without
the need of a static downloaded service account key! GCP CopyCat only needs to include the newly acquired access token in our
authorization header for the API requests in order to copy files from GCS.
1 curl -H "Authorization: Bearer $OAUTH_TOKEN" "https://storage.googleapis.com/s