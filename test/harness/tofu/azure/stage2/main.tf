# Azure as a TARGET.
#
# Covers pair-matrix rows 2 (GCP GCE -> Azure) and 6 (AWS EKS-IRSA -> Azure).
#
# Shape of the flow this provisions:
#
#   1. the workload in the source cloud mints a native OIDC token whose `aud` is
#      `api://AzureADTokenExchange`
#   2. it POSTs that token to Entra ID's /oauth2/v2.0/token endpoint as a
#      client_assertion, naming `client_id_for_<source>_source` and `tenant_id`
#   3. Entra ID looks for a federated identity credential on that managed
#      identity whose (issuer, subject, audience) triple matches the token's
#      (iss, sub, aud) EXACTLY and CASE-SENSITIVELY
#   4. on a match it returns an Azure access token for the managed identity,
#      which carries the `Reader` role assignment created below
#
# Step 3 is the whole ballgame and it is where this integration silently breaks.
# Entra ID does no normalization: no case folding, no trailing-slash tolerance,
# no URL canonicalization. `https://Accounts.Google.com` != the real issuer, and
# an EKS issuer with a slash appended != the real issuer. A mismatch surfaces at
# token-exchange time as AADSTS70021 "No matching federated identity record
# found for presented assertion" -- never at apply time, and the error does not
# tell you which of the three fields was wrong. Hence: every issuer/subject/
# audience below is passed through verbatim from the stage-1 inputs, with no
# lower(), trimsuffix(), trimspace() or format() in the path.
#
# Capacity note: Entra ID allows a maximum of 20 federated identity credentials
# per user-assigned managed identity (the same cap applies to app
# registrations). This module creates exactly one FIC per identity, so there is
# no risk here -- but if you extend the matrix with more source runtimes, add a
# new managed identity rather than piling FICs onto an existing one.

data "azurerm_client_config" "current" {}

locals {
  base_name = "${var.name_prefix}-${var.run_id}"

  tags = merge(
    {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
      "stage"      = "stage2"
      "cloud-role" = "target"
    },
    var.extra_tags,
  )

  # Stage 2 owns its own resource group so it can be destroyed independently of
  # (and before) the Azure stage-1 cluster, and so the harmless Reader grant has
  # a tightly scoped target that contains nothing sensitive.
  resource_group_name = "${local.base_name}-trust"

  # One entry per foreign source runtime. Adding a source means adding a key
  # here plus a matching output; the identity/FIC/role-assignment resources fan
  # out over this map.
  #
  # `issuer` and `subject` are references, never expressions -- see the
  # case-sensitivity note above.
  sources = {
    gcp = {
      identity_suffix = "from-gcp"
      issuer          = var.gcp_issuer_url
      subject         = var.gcp_source_sa_unique_id
      note            = "GCE VM identity token; sub is the service account's numeric unique id."
    }
    aws = {
      identity_suffix = "from-aws"
      issuer          = var.aws_eks_oidc_issuer_url
      subject         = var.aws_irsa_subject
      note            = "EKS IRSA projected service-account token; sub is system:serviceaccount:<ns>:<sa>."
    }
  }
}

resource "azurerm_resource_group" "trust" {
  name     = local.resource_group_name
  location = var.location
  tags     = local.tags
}

# One user-assigned managed identity per foreign source.
#
# Deliberately a managed identity and not an Entra app registration: managed
# identities are ARM resources, so creating them needs only Azure RBAC on the
# subscription, whereas app registrations are directory objects that need Entra
# permissions (Application.ReadWrite.OwnedBy or an admin role) that most orgs
# lock down. The client-assertion flow is identical either way. The tradeoff is
# documented in ../README.md.
resource "azurerm_user_assigned_identity" "source" {
  for_each = local.sources

  name                = "${local.base_name}-${each.value.identity_suffix}"
  location            = azurerm_resource_group.trust.location
  resource_group_name = azurerm_resource_group.trust.name
  tags                = local.tags

  lifecycle {
    precondition {
      condition     = length("${local.base_name}-${each.value.identity_suffix}") <= 128
      error_message = "Derived managed identity name exceeds Azure's 128-character limit; shorten name_prefix or run_id."
    }
  }
}

# The trust object itself.
#
# azurerm_federated_identity_credential attaches to the identity via
# `user_assigned_identity_id` (the 4.x replacement for the deprecated
# `parent_id`; `parent_id` is gone entirely in azurerm 5.x).
#
# `audience` is a LIST even though Entra ID only ever honours a single value.
resource "azurerm_federated_identity_credential" "source" {
  for_each = local.sources

  name                      = "${local.base_name}-${each.value.identity_suffix}"
  user_assigned_identity_id = azurerm_user_assigned_identity.source[each.key].id

  # ---- verbatim passthrough; do not transform any of these three ----
  issuer   = each.value.issuer
  subject  = each.value.subject
  audience = [var.audience]
  # -------------------------------------------------------------------
}

# Prove the exchanged token actually carries authority: Reader on this module's
# own (empty, harmless) resource group. Without a role assignment the verifier
# could obtain a token but could not distinguish a working credential from an
# inert one.
#
# principal_type = "ServicePrincipal" tells azurerm to skip the Entra existence
# pre-check, which otherwise flakes on identities created seconds earlier
# (directory replication lag -> "PrincipalNotFound").
resource "azurerm_role_assignment" "source_reader" {
  for_each = local.sources

  scope                = azurerm_resource_group.trust.id
  role_definition_name = var.role_definition_name
  principal_id         = azurerm_user_assigned_identity.source[each.key].principal_id
  principal_type       = "ServicePrincipal"
  description          = "cloud-auth harness ${var.run_id}: proves a federated token from ${each.key} can act in Azure."
}
