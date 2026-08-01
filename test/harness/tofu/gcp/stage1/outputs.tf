# These outputs are the CONTRACT (test/harness/CONTRACT.md -> state/gcp-stage1.json).
# The key set here must stay exactly these eight names — the driver serialises
# them with:
#
#   tofu -chdir=test/harness/tofu/gcp/stage1 output -json \
#     | jq 'map_values(.value)' > test/harness/state/gcp-stage1.json
#
# so any extra output would leak an extra key into the state file.

output "project_id" {
  description = "GCP project id hosting the source workload."
  value       = local.project_id
}

output "project_number" {
  description = "GCP project number. Used to build WIF resource names."
  value       = local.project_number
}

output "region" {
  description = "Region of the source workload."
  value       = var.region
}

output "zone" {
  description = "Zone of the GCE source VM."
  value       = var.zone
}

output "source_sa_email" {
  description = "Email of the service account the source VM runs as."
  value       = google_service_account.source.email
}

output "source_sa_unique_id" {
  description = <<-EOT
    Numeric unique id of the source service account. This — not the email — is
    the `sub` claim of the OIDC tokens the GCE metadata server issues, so AWS
    role trust policies and Azure federated identity credentials must be scoped
    to this value.
  EOT
  value       = google_service_account.source.unique_id
}

output "issuer_url" {
  description = "OIDC issuer of Google-signed instance identity tokens."
  value       = "https://accounts.google.com"
}

output "gce_instance_name" {
  description = "Name of the GCE source VM."
  value       = google_compute_instance.source.name
}
