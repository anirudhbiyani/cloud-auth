locals {
  common_tags = merge(
    {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    },
    var.extra_tags,
  )
}

data "aws_caller_identity" "current" {}

# ===========================================================================
# Shared probe policy
# ===========================================================================
#
# sts:GetCallerIdentity needs no permission at all, so on its own it cannot
# distinguish "credentials minted correctly" from "credentials minted but
# inert". s3:ListAllMyBuckets is the smallest action that actually requires an
# authorized principal, so it is what the verifier calls to prove the exchange
# produced usable credentials. It reads bucket names and nothing else -- no
# object access, no writes.

data "aws_iam_policy_document" "probe" {
  statement {
    sid       = "ProveMintedCredentialsWork"
    effect    = "Allow"
    actions   = ["s3:ListAllMyBuckets"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "probe" {
  name        = "${var.name_prefix}-probe"
  description = "Read-only probe for the cloud-auth harness (run ${var.run_id}): lists bucket names, nothing more."
  policy      = data.aws_iam_policy_document.probe.json
}

# ===========================================================================
# GCP source -> AWS target        (pair matrix row 1)
# ===========================================================================

locals {
  # "https://accounts.google.com" -> "accounts.google.com"
  gcp_issuer_host_path = trimsuffix(replace(var.gcp_issuer_url, "https://", ""), "/")

  # Google is one of the IdPs AWS STS has built in. When it is the issuer, the
  # Google-specific condition keys (:oaud) are available and the federated
  # principal is the bare host string.
  gcp_is_google_builtin = local.gcp_issuer_host_path == "accounts.google.com"

  gcp_federated_principal = var.create_google_oidc_provider ? one(aws_iam_openid_connect_provider.google[*].arn) : local.gcp_issuer_host_path
}

# Off by default -- see the create_google_oidc_provider variable description.
resource "aws_iam_openid_connect_provider" "google" {
  count = var.create_google_oidc_provider ? 1 : 0

  url            = var.gcp_issuer_url
  client_id_list = [var.audience]

  tags = {
    Name = "${var.name_prefix}-google-oidc"
  }
}

# The trust policy. This is the security boundary for row 1 of the matrix, so
# it is worth spelling out how the claims map, because it is NOT the obvious
# 1:1 mapping.
#
# A Google service-account ID token minted for audience "sts.amazonaws.com"
# carries: sub=<sa unique id>, aud=sts.amazonaws.com, azp=<sa unique id>.
#
# Per the IAM condition-key reference, AWS maps those to context keys as:
#   accounts.google.com:sub  <- sub                              (the SA)
#   accounts.google.com:oaud <- aud                              (sts.amazonaws.com)
#   accounts.google.com:aud  <- azp if azp is set, else aud
#
# So conditioning `:aud` on "sts.amazonaws.com" alone -- the intuitive reading
# -- fails whenever Google emits azp, which it does for service accounts. The
# audience is therefore pinned via `:oaud`, and `:aud` accepts either of the two
# values it can legitimately hold. Nothing is loosened: `:sub` still pins the
# exact service account, and both `:aud` candidates are exact strings.
data "aws_iam_policy_document" "from_gcp" {
  statement {
    sid     = "GcpSourceAssumesViaWebIdentity"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.gcp_federated_principal]
    }

    # The subject scope. Without this any Google identity could assume the role.
    condition {
      test     = "StringEquals"
      variable = "${local.gcp_issuer_host_path}:sub"
      values   = [var.gcp_source_sa_unique_id]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.gcp_issuer_host_path}:aud"
      values = local.gcp_is_google_builtin ? distinct([
        var.audience,
        var.gcp_source_sa_unique_id,
      ]) : [var.audience]
    }

    # The real audience check, for Google issuers.
    dynamic "condition" {
      for_each = local.gcp_is_google_builtin ? [1] : []

      content {
        test     = "StringEquals"
        variable = "${local.gcp_issuer_host_path}:oaud"
        values   = [var.audience]
      }
    }
  }
}

resource "aws_iam_role" "from_gcp" {
  name                 = "${var.name_prefix}-from-gcp"
  description          = "Assumed by the GCP GCE source runtime via AssumeRoleWithWebIdentity (cloud-auth harness run ${var.run_id})."
  assume_role_policy   = data.aws_iam_policy_document.from_gcp.json
  max_session_duration = var.session_duration_seconds
}

resource "aws_iam_role_policy_attachment" "from_gcp_probe" {
  role       = aws_iam_role.from_gcp.name
  policy_arn = aws_iam_policy.probe.arn
}

# ===========================================================================
# Azure source -> AWS target      (pair matrix row 3)
# ===========================================================================

locals {
  # AKS issuer URLs end in a slash, e.g.
  # "https://eastus.oic.prod-aks.azure.com/<tenant>/<uuid>/".
  azure_issuer_host_path = replace(var.azure_aks_oidc_issuer_url, "https://", "")

  # IAM condition keys are prefixed with the issuer minus its scheme, but
  # whether IAM keeps or strips a trailing slash on the registered provider URL
  # is not documented. Rather than guess, the trust policy below emits one
  # statement per candidate prefix. Both are fully scoped on :sub and :aud, so
  # the one that does not match simply never fires -- there is no weakening,
  # only a guarantee that the correct one is present. distinct() collapses the
  # pair when the caller passes a URL with no trailing slash.
  azure_condition_prefixes = distinct([
    local.azure_issuer_host_path,
    trimsuffix(local.azure_issuer_host_path, "/"),
  ])
}

# Azure's AKS issuer is not built into AWS, so this provider registration is
# genuinely required. thumbprint_list is omitted: the issuer is fronted by a
# publicly-trusted CA, which IAM verifies against its own root CA library and
# then populates the attribute itself.
resource "aws_iam_openid_connect_provider" "azure" {
  url            = var.azure_aks_oidc_issuer_url
  client_id_list = [var.audience]

  tags = {
    Name = "${var.name_prefix}-azure-oidc"
  }
}

data "aws_iam_policy_document" "from_azure" {
  dynamic "statement" {
    for_each = toset(local.azure_condition_prefixes)

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]

      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.azure.arn]
      }

      # The subject scope: one specific service account in one specific AKS
      # cluster. An unscoped trust would let any workload in that cluster --
      # and only the issuer URL is cluster-specific -- assume this role.
      condition {
        test     = "StringEquals"
        variable = "${statement.value}:sub"
        values   = [var.azure_subject]
      }

      condition {
        test     = "StringEquals"
        variable = "${statement.value}:aud"
        values   = [var.audience]
      }
    }
  }
}

resource "aws_iam_role" "from_azure" {
  name                 = "${var.name_prefix}-from-azure"
  description          = "Assumed by the Azure AKS workload-identity source runtime via AssumeRoleWithWebIdentity (cloud-auth harness run ${var.run_id})."
  assume_role_policy   = data.aws_iam_policy_document.from_azure.json
  max_session_duration = var.session_duration_seconds
}

resource "aws_iam_role_policy_attachment" "from_azure_probe" {
  role       = aws_iam_role.from_azure.name
  policy_arn = aws_iam_policy.probe.arn
}
