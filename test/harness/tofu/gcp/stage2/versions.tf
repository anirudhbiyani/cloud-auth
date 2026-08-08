# cloud-auth integration harness — GCP stage 2 (GCP as a TARGET cloud).
#
# Tooling: OpenTofu. Run everything with `tofu`, never `terraform`:
#   tofu -chdir=test/harness/tofu/gcp/stage2 init
#   tofu -chdir=test/harness/tofu/gcp/stage2 apply
#
# State is local (terraform.tfstate in this directory) and gitignored.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.0.0, < 8.0.0"
    }
  }
}

provider "google" {
  project = var.project_id != "" ? var.project_id : null
  region  = var.region
}
