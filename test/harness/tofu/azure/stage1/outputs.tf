# These output names are fixed by test/harness/CONTRACT.md ("state/azure-stage1.json").
# Other clouds' stage-2 modules and the driver read these exact keys -- do not
# rename, add, or reorder-into-a-nested-object. The driver writes the file with:
#
#   tofu -chdir=test/harness/tofu/azure/stage1 output -json \
#     | jq 'map_values(.value)' > test/harness/state/azure-stage1.json
#
# so the set of outputs here is exactly the set of keys in that JSON.

output "tenant_id" {
  description = "Entra ID (Azure AD) tenant id of the subscription this cluster lives in."
  value       = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  description = "Azure subscription id the harness resources were created in."
  value       = data.azurerm_client_config.current.subscription_id
}

output "location" {
  description = "Azure region of the resource group and AKS cluster."
  value       = azurerm_resource_group.harness.location
}

output "resource_group" {
  description = "Name of the resource group holding the AKS cluster."
  value       = azurerm_resource_group.harness.name
}

output "aks_cluster_name" {
  description = "Name of the AKS cluster acting as the source runtime."
  value       = azurerm_kubernetes_cluster.source.name
}

output "aks_oidc_issuer_url" {
  description = <<-EOT
    The cluster's OIDC issuer URL, e.g.
    https://eastus.oic.prod-aks.azure.com/<tenant>/<uuid>/

    This is the exact `iss` claim in the projected service-account token and it
    normally ENDS WITH A TRAILING SLASH. Foreign clouds must trust it verbatim:
    AWS IAM OIDC providers and Azure federated identity credentials both match
    the issuer case-sensitively and character-for-character. Never trim the
    slash, lowercase it, or otherwise "clean it up" downstream.
  EOT
  value       = azurerm_kubernetes_cluster.source.oidc_issuer_url
}

output "namespace" {
  description = "Kubernetes namespace the verifier runs in (created by the verifier deployment, not by tofu)."
  value       = var.kubernetes_namespace
}

output "service_account" {
  description = "Kubernetes service account the verifier runs as (created by the verifier deployment, not by tofu)."
  value       = var.kubernetes_service_account
}

output "subject" {
  description = <<-EOT
    The `sub` claim foreign clouds must match:
    system:serviceaccount:<namespace>:<service_account>.
    Case-sensitive and exact -- emit verbatim into AWS trust policies, GCP
    attribute conditions, and Azure federated identity credentials.
  EOT
  value       = local.subject
}
