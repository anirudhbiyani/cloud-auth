# GCP stage 2 — GCP as a federation TARGET.
#
# Three ways in, one pool:
#
#   aws-oidc   OIDC provider trusting the AWS EKS cluster's OIDC issuer.
#              Source: a pod using IRSA (EKS-projected service account token).
#   azure-oidc OIDC provider trusting the AKS cluster's OIDC issuer.
#              Source: a pod using Azure AD Workload Identity.
#   aws-sigv4  AWS-TYPE provider (not OIDC). The subject token is not a JWT at
#              all: it is a SigV4-signed, pre-signed sts:GetCallerIdentity
#              request that Google replays against AWS STS to learn the caller's
#              ARN. This is the path an EC2 instance uses, since EC2 has no
#              OIDC identity document. Note the different block: `aws { ... }`
#              instead of `oidc { ... }`.
#
# Access model: DIRECT RESOURCE ACCESS. IAM roles are bound straight to the
# federated principal (principal:// or principalSet://). There is deliberately
# no service account impersonation here — in cloud-auth, impersonation is the
# opt-in fallback for services that still cannot consume external_account
# credentials, not the default path under test.

data "google_project" "this" {}

locals {
  project_id     = data.google_project.this.project_id
  project_number = data.google_project.this.number

  # GCP label values: lowercase letters, digits, '-' and '_', max 63 chars.
  run_id_label = substr(lower(replace(var.run_id, "/[^A-Za-z0-9_-]/", "-")), 0, 63)

  # Resource ids are stricter than labels: no underscores.
  run_id_slug = lower(replace(var.run_id, "/[^A-Za-z0-9-]/", "-"))

  common_labels = {
    "managed-by" = "cloud-auth-harness"
    "run-id"     = local.run_id_label
  }

  # WIF pools and providers have no `labels` field, so provenance goes into
  # `description` (256 chars) where a sweep script can still grep for it.
  provenance = "managed-by=cloud-auth-harness run-id=${local.run_id_label}"

  # Pool ids: 4-32 chars of [a-z0-9-], must not start with "gcp-".
  # run_id is folded in by default because a deleted pool id is reserved for
  # ~30 days and cannot be recreated until purged.
  pool_id_derived = var.include_run_id_in_pool_id ? "${var.name_prefix}-${local.run_id_slug}" : var.name_prefix
  pool_id_raw     = var.pool_id != "" ? var.pool_id : local.pool_id_derived
  pool_id         = trim(substr(local.pool_id_raw, 0, min(32, length(local.pool_id_raw))), "-")

  bucket_name_raw = "${var.name_prefix}-${local.run_id_slug}"
  bucket_name     = trim(substr(local.bucket_name_raw, 0, min(63, length(local.bucket_name_raw))), "-")

  pool_resource = "//iam.googleapis.com/projects/${local.project_number}/locations/global/workloadIdentityPools/${local.pool_id}"

  # For an OIDC provider with no explicit allowed_audiences, Google accepts the
  # provider's own full resource name as the audience — in both the
  # "//iam.googleapis.com/..." and "https://iam.googleapis.com/..." spellings.
  # The contract's audience_* outputs are the "//" form, so allowed_audiences is
  # intentionally left unset rather than overridden.
  audience_aws_oidc   = "${local.pool_resource}/providers/aws-oidc"
  audience_azure_oidc = "${local.pool_resource}/providers/azure-oidc"
  audience_aws_sigv4  = "${local.pool_resource}/providers/aws-sigv4"

  # Principal identifiers for direct resource access.
  #
  # A principal:// identifier is scoped to the POOL, not to the provider: the
  # subject string alone decides who you are. Both k8s sources in this harness
  # present the identical `sub`
  # ("system:serviceaccount:cloud-auth-test:verifier"), so mapping
  # google.subject straight from assertion.sub would collapse the AWS and Azure
  # workloads into one principal. Each OIDC provider therefore namespaces
  # google.subject with a literal prefix (a documented Google pattern) and the
  # bindings below address the namespaced subjects.
  principal_aws_oidc   = "principal://iam.googleapis.com/projects/${local.project_number}/locations/global/workloadIdentityPools/${local.pool_id}/subject/aws-eks::${var.aws_irsa_subject}"
  principal_azure_oidc = "principal://iam.googleapis.com/projects/${local.project_number}/locations/global/workloadIdentityPools/${local.pool_id}/subject/azure-aks::${var.azure_subject}"

  # SigV4: the EC2 caller arrives as arn:aws:sts::ACCT:assumed-role/ROLE/i-xxxx,
  # where the trailing session component is the instance id and therefore
  # changes per instance. Bind the stable role attribute, not the raw subject.
  principal_aws_sigv4 = "principalSet://iam.googleapis.com/projects/${local.project_number}/locations/global/workloadIdentityPools/${local.pool_id}/attribute.aws_role/${var.aws_ec2_role_name}"

  federated_principals = {
    "aws-oidc"   = local.principal_aws_oidc
    "azure-oidc" = local.principal_azure_oidc
    "aws-sigv4"  = local.principal_aws_sigv4
  }

  required_apis = [
    "iam.googleapis.com",
    "sts.googleapis.com",
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = var.enable_apis ? toset(local.required_apis) : toset([])

  project = local.project_id
  service = each.value

  disable_on_destroy         = false
  disable_dependent_services = false
}

# ---------------------------------------------------------------------------
# Workload Identity Pool
# ---------------------------------------------------------------------------

resource "google_iam_workload_identity_pool" "this" {
  project                   = local.project_id
  workload_identity_pool_id = local.pool_id
  display_name              = substr("cloud-auth ${local.run_id_slug}", 0, 32)
  description               = substr("cloud-auth cross-cloud federation harness. ${local.provenance}", 0, 256)

  # Safety rule #1: destroy must always be possible.
  deletion_policy = "DELETE"

  depends_on = [google_project_service.required]
}

# --- 1. AWS EKS-IRSA source (OIDC) -----------------------------------------

resource "google_iam_workload_identity_pool_provider" "aws_oidc" {
  project                            = local.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.this.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-oidc"
  display_name                       = "aws-eks-irsa"
  description                        = substr("Trusts AWS EKS OIDC issuer for IRSA pods. ${local.provenance}", 0, 256)
  deletion_policy                    = "DELETE"

  attribute_mapping = {
    # Namespaced so the EKS pod and the AKS pod are distinct pool principals
    # even though both present the same k8s `sub`.
    "google.subject"           = "'aws-eks::' + assertion.sub"
    "attribute.source_subject" = "assertion.sub"
  }

  # Scoped, not wide open. Without this, ANY service account in the EKS cluster
  # could exchange its projected token for GCP access — a confused deputy.
  attribute_condition = "assertion.sub == '${var.aws_irsa_subject}'"

  oidc {
    issuer_uri = var.aws_eks_oidc_issuer_url
    # allowed_audiences intentionally unset: see local.audience_aws_oidc.
  }
}

# --- 2. Azure AKS workload-identity source (OIDC) --------------------------

resource "google_iam_workload_identity_pool_provider" "azure_oidc" {
  project                            = local.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.this.workload_identity_pool_id
  workload_identity_pool_provider_id = "azure-oidc"
  display_name                       = "azure-aks-wi"
  description                        = substr("Trusts Azure AKS OIDC issuer for workload-identity pods. ${local.provenance}", 0, 256)
  deletion_policy                    = "DELETE"

  attribute_mapping = {
    "google.subject"           = "'azure-aks::' + assertion.sub"
    "attribute.source_subject" = "assertion.sub"
  }

  attribute_condition = "assertion.sub == '${var.azure_subject}'"

  oidc {
    issuer_uri = var.azure_aks_oidc_issuer_url
  }
}

# --- 3. AWS EC2 source (SigV4 / AWS-type provider) -------------------------

resource "google_iam_workload_identity_pool_provider" "aws_sigv4" {
  project                            = local.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.this.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-sigv4"
  display_name                       = "aws-ec2-sigv4"
  description                        = substr("Trusts SigV4 GetCallerIdentity from AWS account ${var.aws_account_id}. ${local.provenance}", 0, 256)
  deletion_policy                    = "DELETE"

  attribute_mapping = {
    # For AWS-type providers the assertion is the *result* of the replayed
    # sts:GetCallerIdentity call, so the available claims are arn / account /
    # userid, not OIDC claims.
    "google.subject"     = "assertion.arn"
    "attribute.account"  = "assertion.account"
    "attribute.aws_role" = "assertion.arn.extract('assumed-role/{role_name}/')"
  }

  # The aws{} block already pins the account; this additionally pins the single
  # EC2 role, so an unrelated principal in the same AWS account cannot federate.
  attribute_condition = "assertion.account == '${var.aws_account_id}' && attribute.aws_role == '${var.aws_ec2_role_name}'"

  # NOTE: this is the AWS provider type, not OIDC. There is no issuer_uri.
  aws {
    account_id = var.aws_account_id
  }
}

# ---------------------------------------------------------------------------
# Probe resource — proves the minted credential actually works
# ---------------------------------------------------------------------------

resource "google_storage_bucket" "test" {
  project       = local.project_id
  name          = local.bucket_name
  location      = var.bucket_location
  force_destroy = var.bucket_force_destroy
  labels        = local.common_labels

  # Uniform bucket-level access is required for IAM-only (principal://)
  # authorization; legacy ACLs cannot express federated principals.
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  depends_on = [google_project_service.required]
}

# Something for the verifier to actually read, so "objectViewer works" is
# observable rather than inferred from an empty listing.
resource "google_storage_bucket_object" "probe" {
  bucket       = google_storage_bucket.test.name
  name         = "cloud-auth-probe.txt"
  content      = "cloud-auth harness probe object. run-id=${local.run_id_label}\n"
  content_type = "text/plain"
}

# Direct resource access: the federated principal itself holds the role. No
# service account is impersonated anywhere in this module.
resource "google_storage_bucket_iam_member" "object_viewer" {
  for_each = local.federated_principals

  bucket = google_storage_bucket.test.name
  role   = "roles/storage.objectViewer"
  member = each.value

  depends_on = [
    google_iam_workload_identity_pool_provider.aws_oidc,
    google_iam_workload_identity_pool_provider.azure_oidc,
    google_iam_workload_identity_pool_provider.aws_sigv4,
  ]
}
