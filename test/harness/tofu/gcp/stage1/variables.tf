variable "project_id" {
  description = <<-EOT
    GCP project to create the source workload in. Leave empty to use the
    ambient project from GOOGLE_PROJECT or `gcloud config get-value project`.
  EOT
  type        = string
  default     = ""
}

variable "region" {
  description = "Region for the source workload. Reported verbatim as the `region` output."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone for the GCE source VM. Must be inside var.region."
  type        = string
  default     = "us-central1-a"
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
    `run-id` label on every label-capable resource so orphans are sweepable.
    The driver always passes a real value; "local" is only a manual-use default.
  EOT
  type        = string
  default     = "local"

  validation {
    condition     = length(var.run_id) > 0 && length(var.run_id) <= 48
    error_message = "run_id must be 1-48 characters."
  }
}

variable "enable_apis" {
  description = <<-EOT
    Enable the Google APIs this module needs (compute, iam, iamcredentials).
    Requires roles/serviceusage.serviceUsageAdmin. Set false if the APIs are
    already enabled or the caller cannot manage service usage. APIs are never
    disabled on destroy.
  EOT
  type        = bool
  default     = true
}

variable "machine_type" {
  description = "Machine type for the source VM. e2-micro is the cheapest general-purpose shape."
  type        = string
  default     = "e2-micro"
}

variable "boot_image" {
  description = "Boot image for the source VM."
  type        = string
  default     = "debian-cloud/debian-12"
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB. 10 GB is the practical minimum for the Debian image."
  type        = number
  default     = 10

  validation {
    condition     = var.boot_disk_size_gb >= 10 && var.boot_disk_size_gb <= 100
    error_message = "boot_disk_size_gb must be between 10 and 100."
  }
}

variable "boot_disk_type" {
  description = "Boot disk type. pd-standard is the cheapest per GB."
  type        = string
  default     = "pd-standard"
}

variable "network" {
  description = <<-EOT
    VPC network for the source VM. "default" uses the auto-mode default network,
    which already carries a default-allow-ssh firewall rule.
  EOT
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Optional subnetwork name. Empty means let GCE pick the subnet for var.zone."
  type        = string
  default     = ""
}

variable "assign_external_ip" {
  description = <<-EOT
    Attach an ephemeral external IPv4 address so the driver can `gcloud compute ssh`
    directly. Costs ~$0.005/hour. Set false and use IAP TCP forwarding to save it
    (requires a firewall rule allowing 35.235.240.0/20 on tcp:22).
  EOT
  type        = bool
  default     = true
}

variable "preemptible" {
  description = <<-EOT
    Run the source VM as a Spot instance (~70-90% cheaper). Off by default: a
    preemption mid-verify would produce a spurious harness failure.
  EOT
  type        = bool
  default     = false
}

variable "service_account_scopes" {
  description = <<-EOT
    OAuth scopes on the attached service account. cloud-platform is the modern
    recommendation; actual authority still comes from IAM roles, and the harness
    grants the source SA no project roles at all.
  EOT
  type        = list(string)
  default     = ["https://www.googleapis.com/auth/cloud-platform"]
}

variable "startup_script" {
  description = "Optional startup script for the source VM (the driver may use it to stage the verifier)."
  type        = string
  default     = ""
}

variable "extra_metadata" {
  description = "Extra GCE instance metadata merged on top of the module defaults."
  type        = map(string)
  default     = {}
}
