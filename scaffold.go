package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
)

// scaffoldInput is the resolved information a trust scaffold is generated from.
type scaffoldInput struct {
	target core.Target
	// issuer is the source OIDC issuer URL (from the detected runtime, if any).
	issuer string
	// subject is the source subject/principal (from the detected runtime).
	subject string
}

// scaffoldTrust returns the print-only, target-side trust setup (Terraform and
// native CLI) needed for the exchange to succeed. It NEVER applies changes; it
// only emits artifacts. The result is deterministic per target cloud.
func scaffoldTrust(in scaffoldInput) (string, error) {
	issuer := in.issuer
	if issuer == "" {
		issuer = "<SOURCE_OIDC_ISSUER_URL>"
	}
	subject := in.subject
	if subject == "" {
		subject = "<SOURCE_SUBJECT>"
	}
	switch t := in.target.(type) {
	case core.AWSTarget:
		return scaffoldAWS(t, issuer, subject), nil
	case core.GCPTarget:
		return scaffoldGCP(t, issuer, subject), nil
	case core.AzureTarget:
		return scaffoldAzure(t, issuer, subject), nil
	default:
		return "", fmt.Errorf("init: unsupported target %T", in.target)
	}
}

func scaffoldAWS(t core.AWSTarget, issuer, subject string) string {
	aud := t.Audience()
	if aud == "" {
		aud = "sts.amazonaws.com"
	}
	return fmt.Sprintf(`# AWS target trust — IAM OIDC provider + role trust policy (print-only)
#
# Terraform:
resource "aws_iam_openid_connect_provider" "source" {
  url             = "%[1]s"
  client_id_list  = ["%[2]s"]
  thumbprint_list = ["<OIDC_TLS_THUMBPRINT>"]
}

# Attach this trust policy to role %[3]q so it accepts the source token:
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.source.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "%[4]s:aud"
      values   = ["%[2]s"]
    }
    condition {
      test     = "StringEquals"
      variable = "%[4]s:sub"
      values   = ["%[5]s"]
    }
  }
}

# Native CLI equivalent:
aws iam create-open-id-connect-provider \
  --url "%[1]s" \
  --client-id-list "%[2]s" \
  --thumbprint-list "<OIDC_TLS_THUMBPRINT>"
# then update the trust policy of role %[3]q with the aud/sub conditions above.
`,
		issuer, aud, t.RoleARN, oidcHost(issuer), subject)
}

func scaffoldGCP(t core.GCPTarget, issuer, subject string) string {
	pool := t.WorkloadIdentityPool
	if pool == "" {
		pool = "<WORKLOAD_IDENTITY_POOL>"
	}
	impersonate := t.ImpersonateServiceAccount
	if impersonate == "" {
		impersonate = "<SERVICE_ACCOUNT_EMAIL>"
	}
	return fmt.Sprintf(`# GCP target trust — Workload Identity pool/provider + principal binding (print-only)
#
# Terraform:
resource "google_iam_workload_identity_pool_provider" "source" {
  workload_identity_pool_id          = "<POOL_ID>"
  workload_identity_pool_provider_id = "<PROVIDER_ID>"
  oidc {
    issuer_uri        = "%[1]s"
    allowed_audiences = ["%[2]s"]
  }
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
}

# Bind the source principal to impersonate %[4]q:
resource "google_service_account_iam_member" "bind" {
  service_account_id = "%[4]s"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/%[3]s/subject/%[5]s"
}

# Native CLI equivalent:
gcloud iam workload-identity-pools providers create-oidc "<PROVIDER_ID>" \
  --workload-identity-pool="<POOL_ID>" \
  --issuer-uri="%[1]s" \
  --allowed-audiences="%[2]s" \
  --attribute-mapping="google.subject=assertion.sub"
gcloud iam service-accounts add-iam-policy-binding "%[4]s" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/%[3]s/subject/%[5]s"
`,
		issuer, t.Audience(), pool, impersonate, subject)
}

func scaffoldAzure(t core.AzureTarget, issuer, subject string) string {
	aud := t.Audience()
	if aud == "" {
		aud = "api://AzureADTokenExchange"
	}
	return fmt.Sprintf(`# Azure target trust — federated identity credential (print-only)
# NOTE: Azure matches issuer/subject/audience EXACTLY (case-sensitive).
#
# Terraform:
resource "azuread_application_federated_identity_credential" "source" {
  application_id = "<APPLICATION_OBJECT_ID>"  # client id %[4]q
  display_name   = "cloud-auth-source"
  issuer         = "%[1]s"
  subject        = "%[2]s"
  audiences      = ["%[3]s"]
}

# Native CLI equivalent:
az ad app federated-credential create \
  --id "<APPLICATION_OBJECT_ID>" \
  --parameters '{
    "name": "cloud-auth-source",
    "issuer": "%[1]s",
    "subject": "%[2]s",
    "audiences": ["%[3]s"]
  }'
# Tenant: %[5]s
`,
		issuer, subject, aud, t.ClientID, t.Tenant)
}

// oidcHost strips the scheme from an issuer URL for use in IAM condition keys
// (AWS condition variables are keyed on the host without scheme).
func oidcHost(issuer string) string {
	s := issuer
	for _, prefix := range []string{"https://", "http://"} {
		if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
			return s[len(prefix):]
		}
	}
	return s
}

func cmdInit(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	getTarget := targetFlags(fs)
	fs.Parse(args)

	target, err := getTarget()
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("--to is required")
	}

	in := scaffoldInput{target: target}
	// Best-effort: enrich with the detected source issuer/subject. Absence is
	// fine — placeholders are emitted. This performs no writes.
	if _, rt, err := source.Default().Detect(ctx); err == nil && rt != nil {
		in.issuer = rt.Issuer
		in.subject = rt.Subject
	}

	out, err := scaffoldTrust(in)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "# cloud-auth init — print-only trust scaffold. Review and apply manually.")
	fmt.Fprint(w, out)
	return nil
}

// cmdInitStdout is the run()-facing wrapper writing to stdout.
func cmdInitStdout(ctx context.Context, args []string) error {
	return cmdInit(ctx, args, os.Stdout)
}
