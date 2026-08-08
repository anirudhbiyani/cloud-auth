variable "run_id" {
  description = "Unique identifier for this harness run; applied to every resource as the `run-id` tag. Must match the run_id used for stage1."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", var.run_id))
    error_message = "run_id must be 1-63 chars of alphanumerics, dot, underscore or hyphen, starting with an alphanumeric."
  }
}

variable "name_prefix" {
  description = "Name prefix for the trust roles. Produces \"<name_prefix>-from-gcp\" and \"<name_prefix>-from-azure\", matching test/harness/CONTRACT.md."
  type        = string
  default     = "cloud-auth-test"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,37}$", var.name_prefix))
    error_message = "name_prefix must be 2-38 lowercase alphanumerics/hyphens starting with an alphanumeric."
  }
}

variable "region" {
  description = "AWS region for the provider. IAM is global, so this only affects which regional endpoint is called; use the same region as stage1."
  type        = string
  default     = "us-east-1"
}

variable "audience" {
  description = <<-EOT
    The audience the source clouds mint their tokens for, and the client id
    registered on each IAM OIDC provider. "sts.amazonaws.com" is the value AWS
    STS expects for AssumeRoleWithWebIdentity and is emitted verbatim as the
    `audience` key of state/aws-stage2.json.
  EOT
  type        = string
  default     = "sts.amazonaws.com"

  validation {
    condition     = length(var.audience) > 0 && !strcontains(var.audience, "*")
    error_message = "audience must be non-empty and must not contain a wildcard."
  }
}

variable "extra_tags" {
  description = "Additional tags merged onto every resource, on top of managed-by and run-id."
  type        = map(string)
  default     = {}
}

variable "session_duration_seconds" {
  description = "Maximum session duration for the federated roles. One hour is plenty for a verification run and keeps the blast radius small."
  type        = number
  default     = 3600

  validation {
    condition     = var.session_duration_seconds >= 3600 && var.session_duration_seconds <= 43200
    error_message = "session_duration_seconds must be between 3600 and 43200 (the IAM-enforced range)."
  }
}

# ---------------------------------------------------------------------------
# GCP source facts (from state/gcp-stage1.json)
# ---------------------------------------------------------------------------

variable "gcp_issuer_url" {
  description = "Issuer of the GCP source's ID tokens. Google service-account ID tokens are always issued by https://accounts.google.com."
  type        = string
  default     = "https://accounts.google.com"

  validation {
    condition     = startswith(var.gcp_issuer_url, "https://")
    error_message = "gcp_issuer_url must start with https://."
  }
}

# No default, on purpose. A default here would be a confused-deputy hole: the
# role's entire security boundary is this one value.
variable "gcp_source_sa_unique_id" {
  description = <<-EOT
    Numeric unique id of the GCP service account attached to the source GCE VM
    (`source_sa_unique_id` in state/gcp-stage1.json). This is the `sub` claim of
    the ID token and the ONLY thing scoping the AWS role to that one workload.
    Deliberately has no default.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[0-9]{1,32}$", var.gcp_source_sa_unique_id))
    error_message = "gcp_source_sa_unique_id must be the service account's numeric unique id (digits only) -- not its email address, and never a wildcard."
  }
}

variable "create_google_oidc_provider" {
  description = <<-EOT
    Whether to register https://accounts.google.com as an IAM OIDC provider.

    Default false, which departs from a literal reading of CONTRACT.md for a
    documented reason: Google is one of the three IdPs already built into AWS
    STS, and the IAM docs specify the principal for it as the bare string
    "accounts.google.com" rather than an OIDC-provider ARN. Registering it
    separately is redundant and may be rejected outright. Flip to true only if
    you have confirmed your account needs an explicit provider; the trust policy
    switches to that provider's ARN automatically.
  EOT
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Azure source facts (from state/azure-stage1.json)
# ---------------------------------------------------------------------------

variable "azure_aks_oidc_issuer_url" {
  description = <<-EOT
    The AKS cluster's OIDC issuer URL (`aks_oidc_issuer_url` in
    state/azure-stage1.json), e.g.
    "https://eastus.oic.prod-aks.azure.com/<tenant>/<uuid>/". Pass it exactly as
    Azure reported it, trailing slash included -- it must equal the `iss` claim
    character for character.
  EOT
  type        = string

  validation {
    condition     = startswith(var.azure_aks_oidc_issuer_url, "https://") && !strcontains(var.azure_aks_oidc_issuer_url, "*")
    error_message = "azure_aks_oidc_issuer_url must start with https:// and must not contain a wildcard."
  }
}

variable "azure_subject" {
  description = <<-EOT
    The `sub` claim of the AKS workload-identity token (`subject` in
    state/azure-stage1.json), i.e.
    "system:serviceaccount:cloud-auth-test:verifier". This is the only thing
    scoping the AWS role to that one pod identity. Deliberately has no default.
  EOT
  type        = string

  validation {
    condition     = startswith(var.azure_subject, "system:serviceaccount:") && !strcontains(var.azure_subject, "*")
    error_message = "azure_subject must be a fully-qualified \"system:serviceaccount:<namespace>:<name>\" subject with no wildcard."
  }
}
