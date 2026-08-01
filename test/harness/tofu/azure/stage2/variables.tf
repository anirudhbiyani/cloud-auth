# ---------------------------------------------------------------------------
# Harness-wide knobs
# ---------------------------------------------------------------------------

variable "name_prefix" {
  description = <<-EOT
    Prefix for every resource name created by this module. User-assigned managed
    identity names allow 3-128 chars of alphanumerics/hyphens/underscores and
    federated identity credential names allow 3-120, so the derived names have
    plenty of headroom -- but keep this short anyway.
  EOT
  type        = string
  default     = "cloud-auth-test"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.name_prefix))
    error_message = "name_prefix must be 2-24 chars, lowercase letters/digits/hyphens, starting with a letter."
  }
}

variable "run_id" {
  description = <<-EOT
    Unique id for this harness run. Stamped onto every resource as the `run-id`
    tag and baked into resource names, so a failed `down` leaves orphans that
    can be found and swept by tag.
  EOT
  type        = string
  default     = "local"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,23}$", var.run_id))
    error_message = "run_id must be 1-24 chars, lowercase letters/digits/hyphens, starting with a letter or digit."
  }
}

variable "location" {
  description = <<-EOT
    Azure region for the trust resource group and the managed identities.
    Managed identities are regional resources but the federation itself is
    tenant-global, so this only affects where the (free) identity objects live.
  EOT
  type        = string
  default     = "eastus"
}

variable "subscription_id" {
  description = <<-EOT
    Azure subscription id. Empty string means "use ARM_SUBSCRIPTION_ID or the az
    CLI's current subscription", which azurerm 4.x accepts.
  EOT
  type        = string
  default     = ""
}

variable "resource_provider_registrations" {
  description = <<-EOT
    Passed straight to the azurerm provider. "legacy" (default) auto-registers
    resource providers and needs subscription-level write; use "none" when
    running as a narrowly scoped principal.
  EOT
  type        = string
  default     = "legacy"

  validation {
    condition     = contains(["all", "core", "extended", "legacy", "none"], var.resource_provider_registrations)
    error_message = "Must be one of: all, core, extended, legacy, none."
  }
}

variable "audience" {
  description = <<-EOT
    The audience Entra ID requires in an inbound client assertion. For workload
    identity federation this is always `api://AzureADTokenExchange` -- the
    source cloud must mint its OIDC token with EXACTLY this `aud` value.

    Case-sensitive. `api://azureadtokenexchange` will not match.
  EOT
  type        = string
  default     = "api://AzureADTokenExchange"
}

variable "role_definition_name" {
  description = <<-EOT
    Built-in Azure role granted to each federated identity, scoped to this
    module's own resource group. `Reader` is deliberately harmless: it lets the
    verifier prove the exchanged token really carries authority (it can list the
    resource group) without letting it change anything.
  EOT
  type        = string
  default     = "Reader"
}

variable "extra_tags" {
  description = "Additional tags merged onto every resource, on top of managed-by and run-id."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Facts imported from the OTHER clouds' stage 1
#
# The driver generates a tfvars file from test/harness/state/gcp-stage1.json and
# test/harness/state/aws-stage1.json. This module NEVER reads another cloud's
# tofu state -- stage-1 JSON is the only interface.
#
# !!! Everything below is copied verbatim into a federated identity credential.
# !!! Entra ID matches issuer, subject and audience CASE-SENSITIVELY and
# !!! EXACTLY. Do not lowercase, do not trim or append a trailing slash, do not
# !!! url-normalize. A mismatch produces AADSTS70021 ("No matching federated
# !!! identity record found") at exchange time, never at apply time.
# ---------------------------------------------------------------------------

variable "gcp_issuer_url" {
  description = <<-EOT
    `issuer_url` from state/gcp-stage1.json. Google's OIDC issuer, which is
    always exactly `https://accounts.google.com` -- no trailing slash, no
    `/.well-known/...` suffix.
  EOT
  type        = string
  default     = "https://accounts.google.com"

  validation {
    condition     = can(regex("^https://[^[:space:]]+$", var.gcp_issuer_url))
    error_message = "gcp_issuer_url must be an https URL with no whitespace."
  }
}

variable "gcp_source_sa_unique_id" {
  description = <<-EOT
    `source_sa_unique_id` from state/gcp-stage1.json: the GCP service account's
    NUMERIC unique id (21 digits, e.g. "109876543210987654321"). This -- not the
    SA email -- is the `sub` claim in a Google-minted identity token, and so it
    is what the federated identity credential must match.

    Has no useful default; the driver must supply it.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[0-9]{1,32}$", var.gcp_source_sa_unique_id))
    error_message = "gcp_source_sa_unique_id must be supplied and must be the SA's numeric unique id (digits only) -- not the SA email."
  }
}

variable "aws_eks_oidc_issuer_url" {
  description = <<-EOT
    `eks_oidc_issuer_url` from state/aws-stage1.json, e.g.
    https://oidc.eks.us-east-1.amazonaws.com/id/ABC123

    Copied verbatim into the federated identity credential's issuer. The `id/`
    segment is case-sensitive and EKS issuer URLs have NO trailing slash --
    take the value exactly as stage 1 reported it.

    Has no useful default; the driver must supply it.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^https://[^[:space:]]+$", var.aws_eks_oidc_issuer_url))
    error_message = "aws_eks_oidc_issuer_url must be supplied and must be an https URL with no whitespace (copy eks_oidc_issuer_url from aws-stage1.json verbatim)."
  }
}

variable "aws_irsa_subject" {
  description = <<-EOT
    `irsa_subject` from state/aws-stage1.json: the `sub` claim of the EKS
    projected service-account token, i.e.
    system:serviceaccount:<namespace>:<serviceaccount>.

    Case-sensitive and exact.
  EOT
  type        = string
  default     = "system:serviceaccount:cloud-auth-test:verifier"

  validation {
    condition     = can(regex("^system:serviceaccount:[a-z0-9][a-z0-9.-]*:[a-z0-9][a-z0-9.-]*$", var.aws_irsa_subject))
    error_message = "aws_irsa_subject must look like system:serviceaccount:<namespace>:<serviceaccount>."
  }
}
