variable "name_prefix" {
  description = <<-EOT
    Prefix for every resource name created by this module. Keep it short: it is
    combined with run_id and a per-resource suffix, and several Azure resource
    types cap names well below the 90-char resource-group limit (AKS cluster
    name is 63, DNS prefix is 54).
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
    Unique id for this harness run (the driver passes something like
    "20260705-abc123"). Stamped onto every resource as the `run-id` tag and
    baked into resource names so concurrent runs do not collide, and so orphans
    from a failed `down` can be swept by tag.
  EOT
  type        = string
  default     = "local"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,23}$", var.run_id))
    error_message = "run_id must be 1-24 chars, lowercase letters/digits/hyphens, starting with a letter or digit."
  }
}

variable "location" {
  description = "Azure region for the resource group and the AKS cluster."
  type        = string
  default     = "eastus"
}

variable "subscription_id" {
  description = <<-EOT
    Azure subscription id. Empty string means "use the ARM_SUBSCRIPTION_ID
    environment variable or the az CLI's current subscription", which is what
    azurerm 4.x requires when the provider block does not set it explicitly.
  EOT
  type        = string
  default     = ""
}

variable "resource_provider_registrations" {
  description = <<-EOT
    Passed straight to the azurerm provider. "legacy" (default) auto-registers a
    batch of resource providers and needs subscription-level write. Use "none"
    when running as a narrowly scoped principal on a subscription where the
    needed providers are already registered.
  EOT
  type        = string
  default     = "legacy"

  validation {
    condition     = contains(["all", "core", "extended", "legacy", "none"], var.resource_provider_registrations)
    error_message = "Must be one of: all, core, extended, legacy, none."
  }
}

variable "kubernetes_namespace" {
  description = <<-EOT
    Kubernetes namespace the verifier pod runs in. Fixed by the harness contract
    to `cloud-auth-test`. This module does not create the namespace (the
    verifier deployment does) -- it only exports the resulting subject string.
  EOT
  type        = string
  default     = "cloud-auth-test"
}

variable "kubernetes_service_account" {
  description = <<-EOT
    Kubernetes service account the verifier pod runs as. Fixed by the harness
    contract to `verifier`. Created by the verifier deployment, not here.
  EOT
  type        = string
  default     = "verifier"
}

variable "node_vm_size" {
  description = <<-EOT
    VM SKU for the single-node system pool. Standard_B2s (2 vCPU / 4 GiB) is the
    cheapest SKU that still satisfies the AKS system-pool minimum. If a region
    rejects burstable SKUs for system pools, fall back to Standard_B2ms or
    Standard_D2s_v5 (roughly 2x the hourly cost).
  EOT
  type        = string
  default     = "Standard_B2s"
}

variable "node_count" {
  description = "Node count for the system pool. One node is enough to run the verifier."
  type        = number
  default     = 1
}

variable "node_os_disk_size_gb" {
  description = "OS disk size in GiB. 30 is the AKS minimum; 32 maps to the cheapest managed-disk tier."
  type        = number
  default     = 32
}

variable "kubernetes_version" {
  description = <<-EOT
    AKS Kubernetes version, e.g. "1.30". Empty string means "let AKS pick its
    current default for the region", which is what the harness normally wants.
  EOT
  type        = string
  default     = ""
}

variable "extra_tags" {
  description = "Additional tags merged onto every resource, on top of managed-by and run-id."
  type        = map(string)
  default     = {}
}
