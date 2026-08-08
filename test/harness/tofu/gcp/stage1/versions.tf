# cloud-auth integration harness — GCP stage 1 (GCP as a SOURCE runtime).
#
# Tooling: OpenTofu. Run everything with `tofu`, never `terraform`:
#   tofu -chdir=test/harness/tofu/gcp/stage1 init
#   tofu -chdir=test/harness/tofu/gcp/stage1 apply
#
# State is local (terraform.tfstate in this directory) and gitignored. There is
# deliberately no remote backend: the harness is ephemeral and must be
# destroyable from the machine that created it.

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
  # Falls back to the ambient project (GOOGLE_PROJECT / gcloud config) when
  # var.project_id is empty.
  project = var.project_id != "" ? var.project_id : null
  region  = var.region
  zone    = var.zone
}
