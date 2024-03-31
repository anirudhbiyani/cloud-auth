> **_NOTE:_**: While the tools works, there is a need to needs to be revamped to provide more consistency and larger set of features and coverage.

# cross-cloud

cloud-auth helps in setting up and using Session based access between major Cloud Service Providers (CSPs) like Amazon Web Services, Microsoft Azure and Google Cloud Platform rather than relying on standing credentials to access workloads sor data sources in a multi-cloud infrastructure.

#### Why?
In a infrastructure where a single Cloud Service Providers is used, it is fairly easy to use session based credetnials to perform authZ and authN within the cloud infrastructure but the equation changes when there are mutliple cloud service providers at play. For instance, we can use IAM Roles in AWS, Service Accounts in GCP and Service Principal in Azure but these Identity and Access Management features are limited to a single cloud provider and are not available outside their boundaries. In order to achieve authentication between various cloud service providers, we need to rely on AWS IAM Access Key, GCP Service Account Keys, Azure Service Account Principals. 

While they do solve the problem but also gives rise to array of other problems such as - 
- Credential Rotation - It becomes harded to rotate credentials as corodination with various teams is needed. While automated rotation is possible, ensureing there is no breakage of any of systems needs to go through a manual process.
- Hard-coded credentials - The credetials might get hardcoded in configuration files, source code, etc.
- Trackability - It would become difficult to track where the credentials are being used, like some of these scenarios
    - Users can export these variables and use it from workstations or within different within environments within our cloud infrastructure. 
    - Ex exmployees can still have access these credentials.
- Invardent Exposure - The risk of credentials being exposed in places like application logs, environment problems, etc. becomes a lot higher and accidental commit in git repositories, not limited to company owner repos, but in personal repositories.
- RBAC in Secret Manager - There are no restrictions around which services can access whihc services credentials and all services can read credentials for all the services. 
- Shared Accounts - Since there aren't any restrictions around which services can use which credentials, one set of Access Keys is being shared between multiple microservices. This is happening at the moment, where one set of credentials are being used in 100+ microservices in the AWS environment. This issue is more aggregated as two access keys can be generated for a single user.
- Technical Debt - This method has not been a best practices for quite a few years now and becomes an debt that needs to be solved into future.

While there are risks that are present, there are times when access keys are needed such as vendors who do not support usage of IAM Role 


### How?

Majority of the Cloud Service Providers have some mechanism of some mechanisdm to grant temporary credentials as described above which can be extended to generate credentails across various cloud provider. The various method are listed below -

- Amazon Web Service - You can allow IAM Role to trust any OIDC/SAML based Identity Provider. This can be used any application like Facebook Appl or custom application and is not just limited to other cloud provider

- Google Cloud Plaform  - Workload Identity needs to be configured. 


Whiile the above discusses the literature, the directory for CSP contain all the resources to setup and use the above mentioned mechanism. Each of these directory represent the method to access the mentioned Cloud Service Provider from other cloud provider like if you want to access GCP from AWS, you would have to look into the GCP directory and look the aws.(py|tf) file. Each of the directory contains another README to gice a more detailed technical understanding.

### Usage

### Limitations

### Contributing
You can contribute to the project in many ways either by reporting bugs, writting documentation, or adding code.

Contributions are welcome! If you would like to contribute, please follow these steps:

    Fork the repository.
    Create a new branch: $ git checkout -b feature/your-feature-name
    Make your changes and commit them: $ git commit -m "Add your feature description"
    Push your changes to the forked repository: $ git push origin feature/your-feature-name
    Open a pull request to the main repository.

### Feedback
have any questions? hit it me on GitHub or Email.


