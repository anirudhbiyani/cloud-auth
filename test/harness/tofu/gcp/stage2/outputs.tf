# These outputs are the CONTRACT (test/harness/CONTRACT.md -> state/gcp-stage2.json).
# Exactly these eight keys, no more — the driver serialises them with:
#
#   tofu -chdir=test/harness/tofu/gcp/stage2 output -json \
#     | jq 'map_values(.value)' > test/harness/state/gcp-stage2.json
#
# provider_* and audience_* are the same full resource names. They are separate
# keys because they play different roles at exchange time: provider_* names the
# trust object, audience_* is the value the SOURCE cloud must put in the `aud`
# claim (or in the STS `audience` parameter) before the exchange will be
# accepted.

output "pool_id" {
  description = "Workload Identity Pool id (includes run_id by default; see README on soft delete)."
  value       = google_iam_workload_identity_pool.this.workload_identity_pool_id
}

output "provider_for_aws_oidc" {
  description = "Full resource name of the OIDC provider trusting the AWS EKS issuer (EKS-IRSA source)."
  value       = local.audience_aws_oidc
}

output "provider_for_azure_oidc" {
  description = "Full resource name of the OIDC provider trusting the Azure AKS issuer."
  value       = local.audience_azure_oidc
}

output "provider_for_aws_sigv4" {
  description = "Full resource name of the AWS-type provider for the EC2 SigV4 path."
  value       = local.audience_aws_sigv4
}

output "audience_for_aws_oidc" {
  description = "Audience the EKS-IRSA token must carry when exchanging at sts.googleapis.com."
  value       = local.audience_aws_oidc
}

output "audience_for_azure_oidc" {
  description = "Audience the AKS workload-identity token must carry when exchanging at sts.googleapis.com."
  value       = local.audience_azure_oidc
}

output "audience_for_aws_sigv4" {
  description = "Audience for the SigV4 exchange; also the value signed into the x-goog-cloud-target-resource header."
  value       = local.audience_aws_sigv4
}

output "test_bucket" {
  description = "GCS bucket the federated principals hold roles/storage.objectViewer on."
  value       = google_storage_bucket.test.name
}
