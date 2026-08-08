# Azure as a SOURCE runtime.
#
# The workload identity we are proving out is an AKS pod that mounts a projected
# service-account token signed by the cluster's own OIDC issuer. Foreign clouds
# (AWS IAM OIDC provider, GCP workload identity pool) must be configured to
# trust `aks_oidc_issuer_url` with subject
# `system:serviceaccount:cloud-auth-test:verifier`.
#
# Nothing here creates the namespace or service account -- the verifier
# deployment does that. This module only stands up the cluster and exports the
# facts the other clouds' stage-2 modules need.

data "azurerm_client_config" "current" {}

locals {
  base_name = "${var.name_prefix}-${var.run_id}"

  tags = merge(
    {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
      "stage"      = "stage1"
      "cloud-role" = "source"
    },
    var.extra_tags,
  )

  # Resource-group names allow up to 90 chars of alphanumerics, underscore,
  # parentheses, hyphen and period -- local.base_name is <= 49 so this is safe.
  resource_group_name = local.base_name

  # AKS cluster name: 1-63 chars, must start and end alphanumeric.
  aks_cluster_name = local.base_name

  # DNS prefix: 1-54 chars, alphanumerics and hyphens, alphanumeric at both ends.
  aks_dns_prefix = substr(local.base_name, 0, 54)

  # AKS puts the node VMs, NICs, disks, NSG and load balancer in a *separate*
  # resource group that it manages. Naming it explicitly keeps orphan sweeping
  # predictable; note that Azure does not propagate our tags into it, so sweep
  # by name as well as by tag (see README).
  node_resource_group = "${local.base_name}-nodes"

  subject = "system:serviceaccount:${var.kubernetes_namespace}:${var.kubernetes_service_account}"
}

resource "azurerm_resource_group" "harness" {
  name     = local.resource_group_name
  location = var.location
  tags     = local.tags
}

resource "azurerm_kubernetes_cluster" "source" {
  name                = local.aks_cluster_name
  location            = azurerm_resource_group.harness.location
  resource_group_name = azurerm_resource_group.harness.name
  dns_prefix          = local.aks_dns_prefix
  node_resource_group = local.node_resource_group

  # Free tier: no control-plane charge and no uptime SLA. Do not switch to
  # "Standard" for the harness -- that adds ~$0.10/hr for nothing we need.
  sku_tier = "Free"

  kubernetes_version = var.kubernetes_version != "" ? var.kubernetes_version : null

  # THE two flags that make this cluster usable as a federation source.
  # oidc_issuer_enabled publishes the cluster's OIDC discovery document at a
  # public HTTPS URL (exported below as aks_oidc_issuer_url); foreign clouds
  # fetch its JWKS from there. workload_identity_enabled installs the mutating
  # webhook that projects a token with the caller-chosen audience into pods
  # annotated for workload identity.
  #
  # Toggling oidc_issuer_enabled off later forces cluster replacement.
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  # Cheapest viable system pool: one burstable node, minimum-size managed OS
  # disk. This is the only line item in the harness that costs real money per
  # hour -- see the cost table in ../README.md.
  default_node_pool {
    name                 = "sys"
    vm_size              = var.node_vm_size
    node_count           = var.node_count
    os_disk_size_gb      = var.node_os_disk_size_gb
    os_disk_type         = "Managed"
    auto_scaling_enabled = false
    max_pods             = 30

    # Pinned so plans stay clean across provider upgrades.
    upgrade_settings {
      max_surge = "10%"
    }

    tags = local.tags
  }

  # System-assigned identity keeps this module free of any Entra ID (Azure AD)
  # directory-write requirement: no app registration, no service principal to
  # create by hand. See the RBAC section of ../README.md.
  identity {
    type = "SystemAssigned"
  }

  tags = local.tags

  lifecycle {
    precondition {
      condition     = length(local.aks_cluster_name) <= 63
      error_message = "Derived AKS cluster name '${local.aks_cluster_name}' exceeds Azure's 63-character limit; shorten name_prefix or run_id."
    }
  }
}
