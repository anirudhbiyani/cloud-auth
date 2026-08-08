# These output names are fixed by test/harness/CONTRACT.md ("state/azure-stage2.json").
# The driver merges them into state/targets.json for the verifier:
#
#   tofu -chdir=test/harness/tofu/azure/stage2 output -json \
#     | jq 'map_values(.value)' > test/harness/state/azure-stage2.json
#
# so the set of outputs here is exactly the set of keys in that JSON. Do not add
# extra outputs to this file -- they would show up as extra keys.

output "audience" {
  description = <<-EOT
    The `aud` claim the source cloud must mint into its OIDC token, and the
    audience registered on both federated identity credentials. Case-sensitive.
  EOT
  value       = var.audience
}

output "tenant_id" {
  description = "Entra ID tenant to POST the client assertion to (/{tenant_id}/oauth2/v2.0/token)."
  value       = data.azurerm_client_config.current.tenant_id
}

output "client_id_for_gcp_source" {
  description = <<-EOT
    CLIENT id of the managed identity federated to the GCP source (pair-matrix
    row 2). This is the value the client-assertion flow presents as `client_id`
    -- it is NOT the principal id / object id and NOT the resource id. Sending
    the principal id here fails with AADSTS700016 (application not found).
  EOT
  value       = azurerm_user_assigned_identity.source["gcp"].client_id
}

output "client_id_for_aws_source" {
  description = <<-EOT
    CLIENT id of the managed identity federated to the AWS EKS-IRSA source
    (pair-matrix row 6). Again: client id, not principal/object id.
  EOT
  value       = azurerm_user_assigned_identity.source["aws"].client_id
}
