# GCP stage 1 — the GCP SOURCE runtime.
#
# What "GCP as a source" means for cloud-auth:
#
#   A GCE VM runs as a dedicated service account. The VM's metadata server will
#   hand any process on the box a Google-signed OIDC ID token for an arbitrary
#   audience:
#
#     curl -H 'Metadata-Flavor: Google' \
#       'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=AUD&format=full'
#
#   That token's issuer is https://accounts.google.com and its `sub` claim is
#   the service account's **numeric unique id** — NOT the email. Foreign trusts
#   (an AWS IAM role trust policy, an Azure federated identity credential) must
#   be scoped to that numeric id, which is why `source_sa_unique_id` is exported.
#
# GKE is intentionally not provisioned: for v1 of the harness the GCE VM is the
# GCP source runtime, and a cluster would dominate the cost of the whole run.

data "google_project" "this" {}

locals {
  project_id     = data.google_project.this.project_id
  project_number = data.google_project.this.number

  # GCP label values: lowercase letters, digits, '-' and '_', max 63 chars.
  run_id_label = substr(lower(replace(var.run_id, "/[^A-Za-z0-9_-]/", "-")), 0, 63)

  common_labels = {
    "managed-by" = "cloud-auth-harness"
    "run-id"     = local.run_id_label
  }

  # Resources that carry no `labels` field (service accounts) get the same
  # facts stamped into free-text so a sweep can still find them.
  provenance = "managed-by=cloud-auth-harness run-id=${local.run_id_label}"

  # Service account ids are 6-30 chars, ^[a-z][-a-z0-9]*[a-z0-9]$.
  # The contract fixes this at "<name_prefix>-src" (e.g. cloud-auth-test-src).
  source_sa_account_id = "${var.name_prefix}-src"
  instance_name        = "${var.name_prefix}-src"

  required_apis = [
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = var.enable_apis ? toset(local.required_apis) : toset([])

  project = local.project_id
  service = each.value

  # Never turn an API back off on destroy: other things in the project may
  # depend on it, and safety rule #1 says destroy must always succeed.
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ---------------------------------------------------------------------------
# Source identity
# ---------------------------------------------------------------------------

# No project-level IAM roles are granted to this service account. Its only job
# is to be an identity: the numeric unique id below is the `sub` of every OIDC
# token the metadata server mints for the VM.
resource "google_service_account" "source" {
  project      = local.project_id
  account_id   = local.source_sa_account_id
  display_name = "cloud-auth harness source (${local.run_id_label})"
  description  = "cloud-auth cross-cloud federation harness source workload. ${local.provenance}"

  depends_on = [google_project_service.required]
}

# ---------------------------------------------------------------------------
# Source runtime
# ---------------------------------------------------------------------------

resource "google_compute_instance" "source" {
  project      = local.project_id
  name         = local.instance_name
  zone         = var.zone
  machine_type = var.machine_type
  labels       = local.common_labels
  tags         = ["cloud-auth-harness"]

  # Safety rule #1: destroy must always be possible.
  deletion_protection       = false
  allow_stopping_for_update = true

  boot_disk {
    auto_delete = true

    initialize_params {
      image  = var.boot_image
      size   = var.boot_disk_size_gb
      type   = var.boot_disk_type
      labels = local.common_labels
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork != "" ? var.subnetwork : null

    # An empty access_config block requests an ephemeral external IPv4.
    dynamic "access_config" {
      for_each = var.assign_external_ip ? [1] : []
      content {}
    }
  }

  # Attaching this SA is what makes the metadata server mint tokens whose `sub`
  # is google_service_account.source.unique_id.
  service_account {
    email  = google_service_account.source.email
    scopes = var.service_account_scopes
  }

  scheduling {
    preemptible        = var.preemptible
    automatic_restart  = !var.preemptible
    provisioning_model = var.preemptible ? "SPOT" : "STANDARD"
    # Spot instances may not live-migrate; GCE rejects MIGRATE for SPOT.
    on_host_maintenance = var.preemptible ? "TERMINATE" : null
  }

  metadata = merge(
    {
      enable-oslogin       = "TRUE"
      managed-by           = "cloud-auth-harness"
      run-id               = local.run_id_label
      cloud-auth-oidc-path = "/computeMetadata/v1/instance/service-accounts/default/identity"
    },
    var.extra_metadata,
  )

  metadata_startup_script = var.startup_script != "" ? var.startup_script : null

  depends_on = [google_project_service.required]
}
