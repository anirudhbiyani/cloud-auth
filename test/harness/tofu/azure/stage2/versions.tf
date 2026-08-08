# cloud-auth test harness -- Azure stage 2 (Azure as TARGET)
#
# Tooling: OpenTofu. Run everything with `tofu`, never `terraform`:
#   tofu -chdir=test/harness/tofu/azure/stage2 init
#   tofu -chdir=test/harness/tofu/azure/stage2 apply -var-file=azure-stage2.auto.tfvars
#
# Local state only -- no backend block, state lands in ./terraform.tfstate.
#
# Note there is NO azuread provider here, on purpose. Everything is done with
# user-assigned managed identities (ARM plane, azurerm only) rather than Entra
# app registrations, so running this needs no Entra ID directory-write
# permission. See ../README.md for the tradeoff.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # 4.x line. In azurerm 5.x the deprecated `parent_id` argument on
      # azurerm_federated_identity_credential is removed; we already use the
      # non-deprecated `user_assigned_identity_id`, but the pin keeps the rest
      # of the harness on a schema this module was validated against.
      version = "~> 4.40"
    }
  }
}

provider "azurerm" {
  features {}

  subscription_id                 = var.subscription_id != "" ? var.subscription_id : null
  resource_provider_registrations = var.resource_provider_registrations
}
