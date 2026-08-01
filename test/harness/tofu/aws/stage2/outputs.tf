# Outputs -- these keys ARE the contract.
#
# test/harness/CONTRACT.md pins the exact shape of state/aws-stage2.json. This
# module deliberately declares no other outputs, so the driver can produce that
# file verbatim with:
#
#   tofu -chdir=test/harness/tofu/aws/stage2 output -json \
#     | jq 'map_values(.value)' > test/harness/state/aws-stage2.json
#
# These feed rows 1 and 3 of the pair matrix.

output "audience" {
  description = "Audience the source clouds must mint their tokens for when targeting AWS."
  value       = var.audience
}

output "role_arn_for_gcp_source" {
  description = "Role the GCP GCE source runtime assumes (pair matrix row 1)."
  value       = aws_iam_role.from_gcp.arn
}

output "role_arn_for_azure_source" {
  description = "Role the Azure AKS workload-identity source runtime assumes (pair matrix row 3)."
  value       = aws_iam_role.from_azure.arn
}
