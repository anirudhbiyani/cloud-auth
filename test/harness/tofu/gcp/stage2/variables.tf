# ---------------------------------------------------------------------------
# Local (GCP) settings — all defaulted.
# ---------------------------------------------------------------------------

variable "project_id" {
  description = <<-EOT
    GCP project that will act as the federation TARGET. Leave empty to use the
    ambient project from GOOGLE_PROJECT or `gcloud config get-value project`.
  EOT
  type        = string
  default     = ""
}

variable "region" {
  description = "Default region for the google provider."
  type        = string
  default     = "us-central1"
}

variable "name_prefix" {
  description = "Prefix for every resource name created by this module."
  type        = string
  default     = "cloud-auth-test"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{1,24})[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be lowercase, start with a letter, end alphanumeric, 3-26 chars."
  }
}

variable "run_id" {
  description = <<-EOT
    Unique id for this harness run (e.g. "20260705-abc123"). Recorded as the
    `run-id` label, folded into the bucket name, and — by default — into the
    Workload Identity Pool id, because a deleted pool id stays reserved for
    ~30 days (see README, "WIF soft delete").
  EOT
  type        = string
  default     = "local"

  validation {
    condition     = length(var.run_id) > 0 && length(var.run_id) <= 48
    error_message = "run_id must be 1-48 characters."
  }
}

variable "pool_id" {
  description = <<-EOT
    Explicit Workload Identity Pool id. Empty (the default) derives
    "<name_prefix>-<run_id>", truncated to the 32-char API limit. Only set this
    if you know the id is not currently soft-deleted.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.pool_id == "" || can(regex("^[a-z][a-z0-9-]{3,31}$", var.pool_id))
    error_message = "pool_id must be 4-32 chars of [a-z0-9-], starting with a letter."
  }
}

variable "include_run_id_in_pool_id" {
  description = <<-EOT
    Append run_id to the derived pool id. Keep this true: WIF pools are
    soft-deleted for ~30 days and their id cannot be reused until purged, so a
    fixed pool id makes back-to-back harness runs fail on create.
  EOT
  type        = bool
  default     = true
}

variable "enable_apis" {
  description = <<-EOT
    Enable the Google APIs this module needs (iam, sts, iamcredentials,
    storage). Requires roles/serviceusage.serviceUsageAdmin. APIs are never
    disabled on destroy.
  EOT
  type        = bool
  default     = true
}

variable "bucket_location" {
  description = "Location for the probe bucket the verifier reads through federated credentials."
  type        = string
  default     = "US"
}

variable "bucket_force_destroy" {
  description = "Delete objects with the bucket. Must stay true — destroy has to succeed unattended."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Cross-cloud stage-1 facts.
#
# Deliberately NOT defaulted: these are foreign trust anchors and a wrong or
# stale value is a confused-deputy hole, not an inconvenience. The driver
# generates harness.auto.tfvars in this directory from
# test/harness/state/aws-stage1.json and test/harness/state/azure-stage1.json.
# This module never reads another cloud's tofu state.
# ---------------------------------------------------------------------------

variable "aws_account_id" {
  description = "AWS account id (aws-stage1.account_id). Anchors the aws-sigv4 WIF provider."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account id."
  }
}

variable "aws_eks_oidc_issuer_url" {
  description = "AWS EKS OIDC issuer URL (aws-stage1.eks_oidc_issuer_url), e.g. https://oidc.eks.us-east-1.amazonaws.com/id/ABC123."
  type        = string

  validation {
    condition     = can(regex("^https://", var.aws_eks_oidc_issuer_url))
    error_message = "aws_eks_oidc_issuer_url must be an https:// URL."
  }
}

variable "aws_irsa_subject" {
  description = "IRSA subject (aws-stage1.irsa_subject), e.g. system:serviceaccount:cloud-auth-test:verifier."
  type        = string

  validation {
    condition     = length(var.aws_irsa_subject) > 0
    error_message = "aws_irsa_subject must not be empty."
  }
}

variable "aws_ec2_role_name" {
  description = <<-EOT
    Name (not ARN) of the IAM role on the AWS EC2 source instance
    (aws-stage1.ec2_role_name). The aws-sigv4 provider is scoped to it.
  EOT
  type        = string

  validation {
    condition     = length(var.aws_ec2_role_name) > 0 && !can(regex("^arn:", var.aws_ec2_role_name))
    error_message = "aws_ec2_role_name must be a bare role name, not an ARN."
  }
}

variable "azure_aks_oidc_issuer_url" {
  description = "Azure AKS OIDC issuer URL (azure-stage1.aks_oidc_issuer_url)."
  type        = string

  validation {
    condition     = can(regex("^https://", var.azure_aks_oidc_issuer_url))
    error_message = "azure_aks_oidc_issuer_url must be an https:// URL."
  }
}

variable "azure_subject" {
  description = "Azure workload-identity subject (azure-stage1.subject), e.g. system:serviceaccount:cloud-auth-test:verifier."
  type        = string

  validation {
    condition     = length(var.azure_subject) > 0
    error_message = "azure_subject must not be empty."
  }
}
