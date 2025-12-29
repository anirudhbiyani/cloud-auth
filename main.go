// Package main is the entry point for cloud-auth CLI.
//
// The CLI provides lifecycle management for cross-cloud authentication
// mechanisms including setup, validation, and deletion with state tracking.
//
// For the legacy CLI, use: go run ./cmd/legacy
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/anirudhbiyani/cloud-auth/pkg/cloudauth"

	// Import providers to register them
	_ "github.com/anirudhbiyani/cloud-auth/pkg/providers/aws"
	_ "github.com/anirudhbiyani/cloud-auth/pkg/providers/azure"
	_ "github.com/anirudhbiyani/cloud-auth/pkg/providers/cloudflare"
	_ "github.com/anirudhbiyani/cloud-auth/pkg/providers/gcp"
	_ "github.com/anirudhbiyani/cloud-auth/pkg/providers/vault"
)

const (
	exitError           = 1
	exitValidationError = 2
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitError)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "setup":
		return cmdSetup(ctx, cmdArgs)
	case "validate":
		return cmdValidate(ctx, cmdArgs)
	case "delete":
		return cmdDelete(ctx, cmdArgs)
	case "list":
		return cmdList(ctx, cmdArgs)
	case "describe":
		return cmdDescribe(ctx, cmdArgs)
	case "providers":
		return cmdProviders(ctx, cmdArgs)
	case "version":
		return cmdVersion()
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s\nRun 'cloud-auth help' for usage", cmd)
	}
}

func printUsage() {
	fmt.Println(`cloud-auth - Cross-cloud authentication lifecycle management

Usage:
  cloud-auth <command> [options]

Commands:
  setup       Create or update a cross-cloud authentication mechanism
  validate    Validate an existing mechanism configuration
  delete      Delete a mechanism and its resources
  list        List all managed mechanisms
  describe    Show details of a specific mechanism
  providers   List available providers and their capabilities
  version     Show version information
  help        Show this help message

Setup Options (File-based):
  -f, --file <path>       Spec file (YAML or JSON)

Setup Options (Flag-based):
  --type <type>           Mechanism type (aws-oidc, gcp-wif, azure-federated, k8s-federation)
  
  AWS OIDC Role Trust (--type aws-oidc):
    --role-name <name>      AWS IAM role name to create/update
    --account-id <id>       AWS account ID (12 digits)
    --oidc-url <url>        OIDC provider URL (e.g., https://token.actions.githubusercontent.com)
    --audience <aud>        Expected audience claim (default: sts.amazonaws.com)
    --subject <sub>         Subject claim pattern (e.g., repo:org/repo:*)
    --source <provider>     Source identity provider (github, gcp, azure, k8s, okta)
    --policy-arns <arns>    Comma-separated policy ARNs to attach

  GCP Workload Identity (--type gcp-wif):
    --project-id <id>       GCP project ID
    --project-number <num>  GCP project number
    --pool-id <id>          Workload Identity Pool ID
    --provider-id <id>      Provider ID within the pool
    --provider-type <type>  Provider type (aws, oidc)
    --aws-account-id <id>   AWS account ID (for aws provider type)
    --oidc-url <url>        OIDC issuer URL (for oidc provider type)
    --service-account <sa>  GCP service account email to impersonate
    --source <provider>     Source identity provider

  Azure Federated Credential (--type azure-federated):
    --tenant-id <id>        Azure AD tenant ID
    --identity-type <type>  Identity type (app, managed-identity)
    --app-name <name>       Application display name (for app type)
    --app-id <id>           Existing application ID (for app type)
    --identity-name <name>  Managed identity name (for managed-identity type)
    --resource-group <rg>   Resource group (for managed-identity type)
    --subscription-id <id>  Subscription ID (for managed-identity type)
    --credential-name <n>   Federated credential name
    --issuer <url>          OIDC issuer URL
    --subject <sub>         Subject claim
    --source <provider>     Source identity provider

  K8s Service Account Federation (--type k8s-federation):
    --cluster-name <name>   Kubernetes cluster name
    --k8s-namespace <ns>    Kubernetes namespace (default: default)
    --k8s-sa-name <name>    Kubernetes ServiceAccount name
    --create-k8s-sa         Create ServiceAccount if it doesn't exist
    --oidc-url <url>        Cluster OIDC issuer URL (e.g., EKS OIDC endpoint)
    --target-cloud <cloud>  Target cloud provider (aws, gcp, azure)
    
    For --target-cloud aws:
      --role-name <name>    AWS IAM role name
      --account-id <id>     AWS account ID
      --policy-arns <arns>  Comma-separated policy ARNs
    
    For --target-cloud gcp:
      --project-id <id>       GCP project ID
      --project-number <num>  GCP project number
      --service-account <sa>  GCP service account email
    
    For --target-cloud azure:
      --tenant-id <id>        Azure AD tenant ID
      --subscription-id <id>  Azure subscription ID
      --identity-type <type>  Identity type (app, managed-identity)
      --app-id <id>           Application ID (for app type)

Common Options:
  --dry-run               Show what would be done without making changes
  --force                 Overwrite existing resources
  --state <path>          State file path (default: ~/.cloud-auth/state.json)
  -v, --verbose           Verbose output

Validate Options:
  --ref <id>              Mechanism reference ID
  --include-token-test    Attempt actual token acquisition
  --timeout <duration>    Validation timeout (e.g., 30s, 1m)

Delete Options:
  --ref <id>              Mechanism reference ID
  --dry-run               Show what would be deleted without making changes
  --force                 Delete even non-owned resources
  --yes                   Skip confirmation prompt

Examples:
  # Setup AWS role trusting GitHub Actions (flag-based)
  cloud-auth setup --type aws-oidc \
    --role-name github-deploy-role \
    --account-id 123456789012 \
    --oidc-url https://token.actions.githubusercontent.com \
    --audience sts.amazonaws.com \
    --subject "repo:myorg/myrepo:*" \
    --source github

  # Setup GCP Workload Identity for AWS (flag-based)
  cloud-auth setup --type gcp-wif \
    --project-id my-project \
    --project-number 123456789012 \
    --pool-id aws-pool \
    --provider-id aws-provider \
    --provider-type aws \
    --aws-account-id 987654321098 \
    --service-account my-sa@my-project.iam.gserviceaccount.com \
    --source aws

  # Setup Azure federated credential for Kubernetes (flag-based)
  cloud-auth setup --type azure-federated \
    --tenant-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
    --identity-type app \
    --app-name k8s-workload \
    --credential-name eks-federation \
    --issuer https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE \
    --subject "system:serviceaccount:default:my-sa" \
    --source k8s

  # Setup K8s ServiceAccount to AWS federation (flag-based)
  cloud-auth setup --type k8s-federation \
    --cluster-name my-eks-cluster \
    --k8s-namespace default \
    --k8s-sa-name my-app-sa \
    --oidc-url https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE \
    --target-cloud aws \
    --role-name k8s-workload-role \
    --account-id 123456789012 \
    --policy-arns arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

  # Setup K8s ServiceAccount to GCP federation (flag-based)
  cloud-auth setup --type k8s-federation \
    --cluster-name my-gke-cluster \
    --k8s-namespace default \
    --k8s-sa-name my-app-sa \
    --oidc-url https://container.googleapis.com/v1/projects/my-proj/locations/us-central1/clusters/my-cluster \
    --target-cloud gcp \
    --project-id my-project \
    --project-number 123456789012 \
    --service-account my-sa@my-project.iam.gserviceaccount.com

  # Setup using a spec file
  cloud-auth setup -f aws-github-oidc.json

  # Dry-run to preview changes
  cloud-auth setup --type aws-oidc --role-name test --account-id 123456789012 \
    --oidc-url https://token.actions.githubusercontent.com --source github --dry-run

  # Validate a mechanism
  cloud-auth validate --ref aws_role_trust_oidc-aws-abc123

  # Delete a mechanism
  cloud-auth delete --ref aws_role_trust_oidc-aws-abc123 --yes

  # List all mechanisms
  cloud-auth list

For more information, visit: https://github.com/anirudhbiyani/cloud-auth`, )}

// CLI options for setup
type setupOpts struct {
	// Input mode
	specFile string

	// Common options
	dryRun    bool
	force     bool
	statePath string
	verbose   bool

	// Mechanism type
	mechType string

	// Common identity options
	source   string
	audience string
	subject  string
	issuer   string

	// AWS OIDC options
	roleName   string
	accountID  string
	oidcURL    string
	policyARNs string

	// GCP WIF options
	projectID      string
	projectNumber  string
	poolID         string
	providerID     string
	providerType   string
	awsAccountID   string
	serviceAccount string

	// Azure options
	tenantID       string
	identityType   string
	appName        string
	appID          string
	identityName   string
	resourceGroup  string
	subscriptionID string
	credentialName string

	// K8s federation options
	clusterName        string
	k8sNamespace       string
	k8sSAName          string
	createK8sSA        bool
	targetCloud        string
}

func parseSetupOpts(args []string) (*setupOpts, error) {
	opts := &setupOpts{
		statePath: cloudauth.DefaultStateStorePath(),
		audience:  "sts.amazonaws.com", // Default for AWS
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		// File input
		case "-f", "--file":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--file requires a path argument")
			}
			opts.specFile = args[i+1]
			i++

		// Common options
		case "--dry-run":
			opts.dryRun = true
		case "--force":
			opts.force = true
		case "--state":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--state requires a path argument")
			}
			opts.statePath = args[i+1]
			i++
		case "-v", "--verbose":
			opts.verbose = true

		// Mechanism type
		case "--type":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--type requires an argument")
			}
			opts.mechType = args[i+1]
			i++

		// Common identity options
		case "--source":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--source requires an argument")
			}
			opts.source = args[i+1]
			i++
		case "--audience":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--audience requires an argument")
			}
			opts.audience = args[i+1]
			i++
		case "--subject":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--subject requires an argument")
			}
			opts.subject = args[i+1]
			i++
		case "--issuer":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--issuer requires an argument")
			}
			opts.issuer = args[i+1]
			i++

		// AWS OIDC options
		case "--role-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--role-name requires an argument")
			}
			opts.roleName = args[i+1]
			i++
		case "--account-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--account-id requires an argument")
			}
			opts.accountID = args[i+1]
			i++
		case "--oidc-url":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--oidc-url requires an argument")
			}
			opts.oidcURL = args[i+1]
			i++
		case "--policy-arns":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--policy-arns requires an argument")
			}
			opts.policyARNs = args[i+1]
			i++

		// GCP WIF options
		case "--project-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--project-id requires an argument")
			}
			opts.projectID = args[i+1]
			i++
		case "--project-number":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--project-number requires an argument")
			}
			opts.projectNumber = args[i+1]
			i++
		case "--pool-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--pool-id requires an argument")
			}
			opts.poolID = args[i+1]
			i++
		case "--provider-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--provider-id requires an argument")
			}
			opts.providerID = args[i+1]
			i++
		case "--provider-type":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--provider-type requires an argument")
			}
			opts.providerType = args[i+1]
			i++
		case "--aws-account-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--aws-account-id requires an argument")
			}
			opts.awsAccountID = args[i+1]
			i++
		case "--service-account":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--service-account requires an argument")
			}
			opts.serviceAccount = args[i+1]
			i++

		// Azure options
		case "--tenant-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--tenant-id requires an argument")
			}
			opts.tenantID = args[i+1]
			i++
		case "--identity-type":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--identity-type requires an argument")
			}
			opts.identityType = args[i+1]
			i++
		case "--app-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--app-name requires an argument")
			}
			opts.appName = args[i+1]
			i++
		case "--app-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--app-id requires an argument")
			}
			opts.appID = args[i+1]
			i++
		case "--identity-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--identity-name requires an argument")
			}
			opts.identityName = args[i+1]
			i++
		case "--resource-group":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--resource-group requires an argument")
			}
			opts.resourceGroup = args[i+1]
			i++
		case "--subscription-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--subscription-id requires an argument")
			}
			opts.subscriptionID = args[i+1]
			i++
		case "--credential-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--credential-name requires an argument")
			}
			opts.credentialName = args[i+1]
			i++

		// K8s federation options
		case "--cluster-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--cluster-name requires an argument")
			}
			opts.clusterName = args[i+1]
			i++
		case "--k8s-namespace":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--k8s-namespace requires an argument")
			}
			opts.k8sNamespace = args[i+1]
			i++
		case "--k8s-sa-name":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--k8s-sa-name requires an argument")
			}
			opts.k8sSAName = args[i+1]
			i++
		case "--create-k8s-sa":
			opts.createK8sSA = true
		case "--target-cloud":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--target-cloud requires an argument")
			}
			opts.targetCloud = args[i+1]
			i++

		default:
			return nil, fmt.Errorf("unknown option: %s", args[i])
		}
	}

	// Validate input mode
	if opts.specFile == "" && opts.mechType == "" {
		return nil, fmt.Errorf("either --file or --type is required")
	}
	if opts.specFile != "" && opts.mechType != "" {
		return nil, fmt.Errorf("--file and --type are mutually exclusive")
	}

	return opts, nil
}

// buildSpecFromFlags creates a MechanismSpec from command-line flags
func buildSpecFromFlags(opts *setupOpts) (cloudauth.MechanismSpec, error) {
	sourceProvider := parseSourceProvider(opts.source)

	switch opts.mechType {
	case "aws-oidc", "aws_role_trust_oidc":
		return buildAWSSpec(opts, sourceProvider)
	case "gcp-wif", "gcp_workload_identity_pool":
		return buildGCPSpec(opts, sourceProvider)
	case "azure-federated", "azure_federated_credential":
		return buildAzureSpec(opts, sourceProvider)
	case "k8s-federation", "k8s_service_account_federation":
		return buildK8sSpec(opts)
	default:
		return nil, fmt.Errorf("unknown mechanism type: %s\nValid types: aws-oidc, gcp-wif, azure-federated, k8s-federation", opts.mechType)
	}
}

func parseSourceProvider(source string) cloudauth.CloudProvider {
	switch strings.ToLower(source) {
	case "github", "github-actions", "github_oidc":
		return cloudauth.ProviderGitHubOIDC
	case "aws":
		return cloudauth.ProviderAWS
	case "gcp", "google":
		return cloudauth.ProviderGCP
	case "azure":
		return cloudauth.ProviderAzure
	case "k8s", "kubernetes":
		return cloudauth.ProviderKubernetes
	case "okta":
		return cloudauth.ProviderOkta
	case "vault":
		return cloudauth.ProviderVault
	default:
		return cloudauth.CloudProvider(source)
	}
}

func buildAWSSpec(opts *setupOpts, source cloudauth.CloudProvider) (*cloudauth.AWSRoleTrustOIDCSpec, error) {
	if opts.roleName == "" {
		return nil, fmt.Errorf("--role-name is required for aws-oidc")
	}
	if opts.accountID == "" {
		return nil, fmt.Errorf("--account-id is required for aws-oidc")
	}
	if opts.oidcURL == "" {
		return nil, fmt.Errorf("--oidc-url is required for aws-oidc")
	}
	if opts.source == "" {
		return nil, fmt.Errorf("--source is required for aws-oidc")
	}

	spec := &cloudauth.AWSRoleTrustOIDCSpec{
		RoleName:        opts.roleName,
		AccountID:       opts.accountID,
		OIDCProviderURL: opts.oidcURL,
		Audience:        opts.audience,
		Subject:         opts.subject,
		Source:          source,
	}

	// Set subject condition based on wildcards
	if strings.Contains(opts.subject, "*") {
		spec.SubjectCondition = "StringLike"
	} else if opts.subject != "" {
		spec.SubjectCondition = "StringEquals"
	}

	// Parse policy ARNs
	if opts.policyARNs != "" {
		spec.PolicyARNs = strings.Split(opts.policyARNs, ",")
		for i, arn := range spec.PolicyARNs {
			spec.PolicyARNs[i] = strings.TrimSpace(arn)
		}
	}

	return spec, nil
}

func buildGCPSpec(opts *setupOpts, source cloudauth.CloudProvider) (*cloudauth.GCPWorkloadIdentityPoolSpec, error) {
	if opts.projectID == "" {
		return nil, fmt.Errorf("--project-id is required for gcp-wif")
	}
	if opts.projectNumber == "" {
		return nil, fmt.Errorf("--project-number is required for gcp-wif")
	}
	if opts.poolID == "" {
		return nil, fmt.Errorf("--pool-id is required for gcp-wif")
	}
	if opts.providerID == "" {
		return nil, fmt.Errorf("--provider-id is required for gcp-wif")
	}
	if opts.serviceAccount == "" {
		return nil, fmt.Errorf("--service-account is required for gcp-wif")
	}
	if opts.providerType == "" {
		return nil, fmt.Errorf("--provider-type is required for gcp-wif (aws or oidc)")
	}

	spec := &cloudauth.GCPWorkloadIdentityPoolSpec{
		ProjectID:           opts.projectID,
		ProjectNumber:       opts.projectNumber,
		PoolID:              opts.poolID,
		ProviderID:          opts.providerID,
		ProviderType:        opts.providerType,
		ServiceAccountEmail: opts.serviceAccount,
		Source:              source,
	}

	switch opts.providerType {
	case "aws":
		if opts.awsAccountID == "" {
			return nil, fmt.Errorf("--aws-account-id is required for gcp-wif with provider-type=aws")
		}
		spec.AWSAccountID = opts.awsAccountID
	case "oidc":
		if opts.oidcURL == "" {
			return nil, fmt.Errorf("--oidc-url is required for gcp-wif with provider-type=oidc")
		}
		spec.OIDCIssuerURL = opts.oidcURL
		if opts.audience != "" {
			spec.AllowedAudiences = []string{opts.audience}
		}
	}

	return spec, nil
}

func buildAzureSpec(opts *setupOpts, source cloudauth.CloudProvider) (*cloudauth.AzureFederatedCredentialSpec, error) {
	if opts.tenantID == "" {
		return nil, fmt.Errorf("--tenant-id is required for azure-federated")
	}
	if opts.issuer == "" && opts.oidcURL == "" {
		return nil, fmt.Errorf("--issuer is required for azure-federated")
	}
	if opts.subject == "" {
		return nil, fmt.Errorf("--subject is required for azure-federated")
	}
	if opts.credentialName == "" {
		return nil, fmt.Errorf("--credential-name is required for azure-federated")
	}

	issuer := opts.issuer
	if issuer == "" {
		issuer = opts.oidcURL
	}

	spec := &cloudauth.AzureFederatedCredentialSpec{
		TenantID:                opts.tenantID,
		Issuer:                  issuer,
		Subject:                 opts.subject,
		FederatedCredentialName: opts.credentialName,
		Source:                  source,
	}

	// Determine identity type
	identityType := opts.identityType
	if identityType == "" {
		if opts.appName != "" || opts.appID != "" {
			identityType = "app"
		} else if opts.identityName != "" {
			identityType = "managed-identity"
		}
	}

	switch identityType {
	case "app", "app_registration":
		spec.IdentityType = "app_registration"
		if opts.appID != "" {
			spec.ApplicationID = opts.appID
		} else if opts.appName != "" {
			spec.ApplicationDisplayName = opts.appName
		} else {
			return nil, fmt.Errorf("--app-id or --app-name is required for azure-federated with identity-type=app")
		}
	case "managed-identity", "mi":
		spec.IdentityType = "managed_identity"
		if opts.identityName == "" {
			return nil, fmt.Errorf("--identity-name is required for azure-federated with identity-type=managed-identity")
		}
		if opts.resourceGroup == "" {
			return nil, fmt.Errorf("--resource-group is required for azure-federated with identity-type=managed-identity")
		}
		if opts.subscriptionID == "" {
			return nil, fmt.Errorf("--subscription-id is required for azure-federated with identity-type=managed-identity")
		}
		spec.ManagedIdentityName = opts.identityName
		spec.ResourceGroup = opts.resourceGroup
		spec.SubscriptionID = opts.subscriptionID
	default:
		return nil, fmt.Errorf("--identity-type must be 'app' or 'managed-identity'")
	}

	return spec, nil
}

func buildK8sSpec(opts *setupOpts) (*cloudauth.K8sServiceAccountFederationSpec, error) {
	// Validate required fields
	if opts.oidcURL == "" {
		return nil, fmt.Errorf("--oidc-url is required for k8s-federation")
	}
	if opts.targetCloud == "" {
		return nil, fmt.Errorf("--target-cloud is required for k8s-federation (aws, gcp, or azure)")
	}

	// Set defaults
	namespace := opts.k8sNamespace
	if namespace == "" {
		namespace = "default"
	}
	saName := opts.k8sSAName
	if saName == "" {
		return nil, fmt.Errorf("--k8s-sa-name is required for k8s-federation")
	}

	spec := &cloudauth.K8sServiceAccountFederationSpec{
		ClusterName:          opts.clusterName,
		Namespace:            namespace,
		ServiceAccountName:   saName,
		CreateServiceAccount: opts.createK8sSA,
		OIDCIssuerURL:        opts.oidcURL,
	}

	// Parse target cloud and build cloud-specific config
	switch strings.ToLower(opts.targetCloud) {
	case "aws":
		spec.TargetCloud = cloudauth.ProviderAWS
		if opts.roleName == "" {
			return nil, fmt.Errorf("--role-name is required for k8s-federation with target-cloud=aws")
		}
		if opts.accountID == "" {
			return nil, fmt.Errorf("--account-id is required for k8s-federation with target-cloud=aws")
		}
		spec.AWSConfig = &cloudauth.K8sToAWSConfig{
			RoleName:  opts.roleName,
			AccountID: opts.accountID,
		}
		// Parse policy ARNs
		if opts.policyARNs != "" {
			arns := strings.Split(opts.policyARNs, ",")
			for i, arn := range arns {
				arns[i] = strings.TrimSpace(arn)
			}
			spec.AWSConfig.PolicyARNs = arns
		}

	case "gcp", "google":
		spec.TargetCloud = cloudauth.ProviderGCP
		if opts.projectID == "" {
			return nil, fmt.Errorf("--project-id is required for k8s-federation with target-cloud=gcp")
		}
		if opts.projectNumber == "" {
			return nil, fmt.Errorf("--project-number is required for k8s-federation with target-cloud=gcp")
		}
		if opts.serviceAccount == "" {
			return nil, fmt.Errorf("--service-account is required for k8s-federation with target-cloud=gcp")
		}
		spec.GCPConfig = &cloudauth.K8sToGCPConfig{
			ProjectID:           opts.projectID,
			ProjectNumber:       opts.projectNumber,
			ServiceAccountEmail: opts.serviceAccount,
		}

	case "azure":
		spec.TargetCloud = cloudauth.ProviderAzure
		if opts.tenantID == "" {
			return nil, fmt.Errorf("--tenant-id is required for k8s-federation with target-cloud=azure")
		}
		if opts.subscriptionID == "" {
			return nil, fmt.Errorf("--subscription-id is required for k8s-federation with target-cloud=azure")
		}
		identityType := opts.identityType
		if identityType == "" {
			identityType = "app"
		}
		spec.AzureConfig = &cloudauth.K8sToAzureConfig{
			TenantID:       opts.tenantID,
			SubscriptionID: opts.subscriptionID,
			IdentityType:   identityType,
			ApplicationID:  opts.appID,
		}

	default:
		return nil, fmt.Errorf("--target-cloud must be 'aws', 'gcp', or 'azure', got: %s", opts.targetCloud)
	}

	return spec, nil
}

func cmdSetup(ctx context.Context, args []string) error {
	opts, err := parseSetupOpts(args)
	if err != nil {
		return err
	}

	var spec cloudauth.MechanismSpec

	// Load spec from file or build from flags
	if opts.specFile != "" {
		spec, err = loadSpec(opts.specFile)
		if err != nil {
			return fmt.Errorf("failed to load spec: %w", err)
		}
	} else {
		spec, err = buildSpecFromFlags(opts)
		if err != nil {
			return err
		}
	}

	// Validate spec
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("invalid spec: %w", err)
	}

	// Create state store
	stateStore, err := cloudauth.NewFileStateStore(opts.statePath)
	if err != nil {
		return fmt.Errorf("failed to initialize state store: %w", err)
	}

	// Create manager
	manager := cloudauth.NewManager(
		cloudauth.WithStateStore(stateStore),
	)

	// Setup options
	setupOpts := cloudauth.SetupOptions{
		DryRun: opts.dryRun,
		Force:  opts.force,
	}

	if opts.verbose {
		fmt.Printf("Setting up mechanism: %s\n", spec.Type())
		fmt.Printf("Source: %s -> Target: %s\n", spec.SourceProvider(), spec.TargetProvider())
		if opts.dryRun {
			fmt.Println("Dry-run mode: no changes will be made")
		}
	}

	// Execute setup
	outputs, err := manager.Setup(ctx, spec, setupOpts)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}

	// Print results
	if opts.dryRun {
		fmt.Println("\n=== Dry-run Results ===")
		if plan, ok := outputs.Values["plan"]; ok {
			fmt.Println(plan)
		}
	} else {
		fmt.Println("\n=== Setup Complete ===")
		fmt.Printf("Mechanism ID: %s\n", outputs.Ref.ID)
		fmt.Printf("Type: %s\n", outputs.Ref.Type)
		fmt.Printf("Provider: %s\n", outputs.Ref.Provider)

		if len(outputs.Values) > 0 {
			fmt.Println("\nOutputs:")
			for k, v := range outputs.Values {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		if len(outputs.Instructions) > 0 {
			fmt.Println("\nInstructions:")
			for _, inst := range outputs.Instructions {
				fmt.Printf("  - %s\n", inst)
			}
		}
	}

	return nil
}

type validateOpts struct {
	refID            string
	includeTokenTest bool
	timeout          time.Duration
	statePath        string
}

func parseValidateOpts(args []string) (*validateOpts, error) {
	opts := &validateOpts{
		statePath: cloudauth.DefaultStateStorePath(),
		timeout:   30 * time.Second,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ref":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--ref requires an ID argument")
			}
			opts.refID = args[i+1]
			i++
		case "--include-token-test":
			opts.includeTokenTest = true
		case "--timeout":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--timeout requires a duration argument")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("invalid timeout duration: %w", err)
			}
			opts.timeout = d
			i++
		case "--state":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--state requires a path argument")
			}
			opts.statePath = args[i+1]
			i++
		default:
			return nil, fmt.Errorf("unknown option: %s", args[i])
		}
	}

	if opts.refID == "" {
		return nil, fmt.Errorf("--ref is required")
	}

	return opts, nil
}

func cmdValidate(ctx context.Context, args []string) error {
	opts, err := parseValidateOpts(args)
	if err != nil {
		return err
	}

	// Create state store
	stateStore, err := cloudauth.NewFileStateStore(opts.statePath)
	if err != nil {
		return fmt.Errorf("failed to initialize state store: %w", err)
	}

	// Get mechanism reference from state
	ref, err := stateStore.Get(ctx, opts.refID)
	if err != nil {
		return fmt.Errorf("mechanism not found: %w", err)
	}

	// Create manager
	manager := cloudauth.NewManager(
		cloudauth.WithStateStore(stateStore),
	)

	// Validate options
	validateOpts := cloudauth.ValidateOptions{
		IncludeTokenTest: opts.includeTokenTest,
		Timeout:          opts.timeout,
	}

	fmt.Printf("Validating mechanism: %s\n", ref.ID)

	// Execute validation
	report, err := manager.Validate(ctx, *ref, validateOpts)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Print results
	fmt.Println("\n=== Validation Report ===")
	fmt.Printf("Mechanism: %s\n", report.Ref.ID)
	fmt.Printf("Valid: %t\n", report.IsValid())
	fmt.Printf("Checks: %d passed, %d failed, %d skipped\n",
		report.Summary.PassedChecks,
		report.Summary.FailedChecks,
		report.Summary.SkippedChecks)

	for _, check := range report.Checks {
		status := "✓"
		switch check.Status {
case cloudauth.CheckStatusFailed:
			status = "✗"
		case cloudauth.CheckStatusSkipped:
			status = "○"
		}

		fmt.Printf("\n%s %s [%s]\n", status, check.Name, check.Severity)
		if check.Status == cloudauth.CheckStatusFailed && check.Remediation != "" {
			fmt.Printf("  Remediation: %s\n", check.Remediation)
		}
	}

	if !report.IsValid() {
		os.Exit(exitValidationError)
	}

	return nil
}

type deleteOpts struct {
	refID     string
	dryRun    bool
	force     bool
	yes       bool
	statePath string
}

func parseDeleteOpts(args []string) (*deleteOpts, error) {
	opts := &deleteOpts{
		statePath: cloudauth.DefaultStateStorePath(),
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ref":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--ref requires an ID argument")
			}
			opts.refID = args[i+1]
			i++
		case "--dry-run":
			opts.dryRun = true
		case "--force":
			opts.force = true
		case "--yes", "-y":
			opts.yes = true
		case "--state":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--state requires a path argument")
			}
			opts.statePath = args[i+1]
			i++
		default:
			return nil, fmt.Errorf("unknown option: %s", args[i])
		}
	}

	if opts.refID == "" {
		return nil, fmt.Errorf("--ref is required")
	}

	return opts, nil
}

func cmdDelete(ctx context.Context, args []string) error {
	opts, err := parseDeleteOpts(args)
	if err != nil {
		return err
	}

	// Create state store
	stateStore, err := cloudauth.NewFileStateStore(opts.statePath)
	if err != nil {
		return fmt.Errorf("failed to initialize state store: %w", err)
	}

	// Get mechanism reference from state
	ref, err := stateStore.Get(ctx, opts.refID)
	if err != nil {
		return fmt.Errorf("mechanism not found: %w", err)
	}

	// Confirmation
	if !opts.yes && !opts.dryRun {
		fmt.Printf("About to delete mechanism: %s\n", ref.ID)
		fmt.Printf("Type: %s, Provider: %s\n", ref.Type, ref.Provider)
		fmt.Printf("Resources: %v\n", ref.ResourceIDs)
		fmt.Print("\nAre you sure? [y/N]: ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	// Create manager
	manager := cloudauth.NewManager(
		cloudauth.WithStateStore(stateStore),
	)

	// Delete options
	deleteOpts := cloudauth.DeleteOptions{
		DryRun:    opts.dryRun,
		Force:     opts.force,
		OwnedOnly: !opts.force,
	}

	if opts.dryRun {
		fmt.Println("Dry-run mode: no changes will be made")
	}

	// Execute deletion
	if err := manager.Delete(ctx, *ref, deleteOpts); err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}

	if opts.dryRun {
		fmt.Println("Would delete mechanism and associated resources")
	} else {
		fmt.Printf("Successfully deleted mechanism: %s\n", ref.ID)
	}

	return nil
}

type listOpts struct {
	mechType  string
	provider  string
	output    string
	statePath string
}

func parseListOpts(args []string) (*listOpts, error) {
	opts := &listOpts{
		statePath: cloudauth.DefaultStateStorePath(),
		output:    "table",
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--type":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--type requires an argument")
			}
			opts.mechType = args[i+1]
			i++
		case "--provider":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--provider requires an argument")
			}
			opts.provider = args[i+1]
			i++
		case "--output", "-o":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--output requires an argument")
			}
			opts.output = args[i+1]
			i++
		case "--state":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--state requires a path argument")
			}
			opts.statePath = args[i+1]
			i++
		default:
			return nil, fmt.Errorf("unknown option: %s", args[i])
		}
	}

	return opts, nil
}

func cmdList(ctx context.Context, args []string) error {
	opts, err := parseListOpts(args)
	if err != nil {
		return err
	}

	// Create state store
	stateStore, err := cloudauth.NewFileStateStore(opts.statePath)
	if err != nil {
		return fmt.Errorf("failed to initialize state store: %w", err)
	}

	// Build filter
	filter := cloudauth.ListFilter{}
	if opts.mechType != "" {
		filter.Type = cloudauth.MechanismType(opts.mechType)
	}
	if opts.provider != "" {
		filter.Provider = cloudauth.CloudProvider(opts.provider)
	}

	// List mechanisms
	refs, err := stateStore.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list mechanisms: %w", err)
	}

	if len(refs) == 0 {
		fmt.Println("No mechanisms found")
		return nil
	}

	switch opts.output {
	case "json":
		data, _ := json.MarshalIndent(refs, "", "  ")
		fmt.Println(string(data))
	case "table":
		fmt.Printf("%-40s %-30s %-12s %-6s %s\n", "ID", "TYPE", "PROVIDER", "OWNED", "CREATED")
		fmt.Println(string(make([]byte, 100)))
		for _, ref := range refs {
			owned := "no"
			if ref.Owned {
				owned = "yes"
			}
			fmt.Printf("%-40s %-30s %-12s %-6s %s\n",
				truncate(ref.ID, 40),
				truncate(string(ref.Type), 30),
				ref.Provider,
				owned,
				ref.CreatedAt.Format("2006-01-02"),
			)
		}
	default:
		return fmt.Errorf("unknown output format: %s", opts.output)
	}

	return nil
}

func cmdDescribe(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("mechanism ID required")
	}

	refID := args[0]
	statePath := cloudauth.DefaultStateStorePath()

	// Check for --state flag
	for i := 1; i < len(args); i++ {
		if args[i] == "--state" && i+1 < len(args) {
			statePath = args[i+1]
			break
		}
	}

	// Create state store
	stateStore, err := cloudauth.NewFileStateStore(statePath)
	if err != nil {
		return fmt.Errorf("failed to initialize state store: %w", err)
	}

	// Get mechanism
	ref, err := stateStore.Get(ctx, refID)
	if err != nil {
		return fmt.Errorf("mechanism not found: %w", err)
	}

	fmt.Println("=== Mechanism Details ===")
	fmt.Printf("ID: %s\n", ref.ID)
	fmt.Printf("Type: %s\n", ref.Type)
	fmt.Printf("Provider: %s\n", ref.Provider)
	fmt.Printf("Owned: %t\n", ref.Owned)
	fmt.Printf("Created: %s\n", ref.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Version: %d\n", ref.Version)

	if len(ref.ResourceIDs) > 0 {
		fmt.Println("\nResources:")
		for k, v := range ref.ResourceIDs {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	return nil
}

func cmdProviders(_ context.Context, _ []string) error {
	providers := cloudauth.DescribeProviders()

	fmt.Println("=== Available Providers ===")
	fmt.Printf("%-15s %-10s %-12s %s\n", "NAME", "TOKEN", "LIFECYCLE", "CAPABILITIES")
	fmt.Println(string(make([]byte, 80)))

	for _, p := range providers {
		token := "no"
		if p.IsToken {
			token = "yes"
		}
		lifecycle := "no"
		if p.IsLifecycle {
			lifecycle = "yes"
		}

		caps := ""
		for i, c := range p.Capabilities {
			if i > 0 {
				caps += ", "
			}
			caps += string(c)
		}

		fmt.Printf("%-15s %-10s %-12s %s\n", p.Name, token, lifecycle, caps)
	}

	return nil
}

func cmdVersion() error {
	fmt.Println("cloud-auth version 0.2.0")
	fmt.Println("  Core: lifecycle management support")
	fmt.Println("  Providers: aws, gcp, azure, cloudflare, vault")
	return nil
}

// Helper functions

func loadSpec(path string) (cloudauth.MechanismSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to detect spec type from content
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse spec (JSON): %w", err)
	}

	mechType, ok := raw["type"].(string)
	if !ok {
		return nil, fmt.Errorf("spec must include 'type' field")
	}

	var spec cloudauth.MechanismSpec

	switch cloudauth.MechanismType(mechType) {
	case cloudauth.MechanismAWSRoleTrustOIDC:
		var s cloudauth.AWSRoleTrustOIDCSpec
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("failed to parse AWSRoleTrustOIDCSpec: %w", err)
		}
		spec = &s
	case cloudauth.MechanismGCPWorkloadIdentityPool:
		var s cloudauth.GCPWorkloadIdentityPoolSpec
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("failed to parse GCPWorkloadIdentityPoolSpec: %w", err)
		}
		spec = &s
	case cloudauth.MechanismAzureFederatedCredential:
		var s cloudauth.AzureFederatedCredentialSpec
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("failed to parse AzureFederatedCredentialSpec: %w", err)
		}
		spec = &s
	case cloudauth.MechanismK8sServiceAccountFederation:
		var s cloudauth.K8sServiceAccountFederationSpec
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("failed to parse K8sServiceAccountFederationSpec: %w", err)
		}
		spec = &s
	default:
		return nil, fmt.Errorf("unknown mechanism type: %s", mechType)
	}

	return spec, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
