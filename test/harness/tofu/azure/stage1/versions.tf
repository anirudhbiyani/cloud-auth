# cloud-auth test harness -- Azure stage 1 (SOURCE runtime)
#
# Tooling: OpenTofu. Run everything with `tofu`, never `terraform`:
#   tofu -chdir=test/harness/tofu/azure/stage1 init
#   tofu -chdir=test/harness/tofu/azure/stage1 apply
#
# Local state only -- there is deliberately no backend block, so state lands in
# ./terraform.tfstate next to this file and is gitignored.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # Pinned to the 4.x line on purpose. azurerm 5.x makes
      # `node_provisioning_profile` mandatory on azurerm_kubernetes_cluster and
      # removes `parent_id` from azurerm_federated_identity_credential; this
      # harness is written and validated against 4.x.
      version = "~> 4.40"
    }
  }
}

provider "azurerm" {
  features {}

  # Required by azurerm 4.x. Leave var.subscription_id empty to fall back to the
  # ARM_SUBSCRIPTION_ID environment variable / `az account set` default.
  subscription_id = var.subscription_id != "" ? var.subscription_id : null

  # "legacy" (the default) registers a batch of resource providers on the
  # subscription, which needs subscription-level write access. Set this to
  # "none" if you are running as a scoped principal and the providers
  # (Microsoft.ContainerService, Microsoft.ManagedIdentity, Microsoft.Network,
  # Microsoft.Compute) are already registered.
  resource_provider_registrations = var.resource_provider_registrations
}
