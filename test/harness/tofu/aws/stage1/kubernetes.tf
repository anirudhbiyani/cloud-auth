# The namespace / service account the verifier pod runs as.
#
# Names are fixed by test/harness/CONTRACT.md: namespace "cloud-auth-test",
# service account "verifier", giving the subject
# "system:serviceaccount:cloud-auth-test:verifier" that the other clouds'
# stage2 trust objects are scoped to.

resource "kubernetes_namespace_v1" "test" {
  metadata {
    name = var.irsa_namespace

    labels = {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    }
  }
}

resource "kubernetes_service_account_v1" "verifier" {
  metadata {
    name      = var.irsa_service_account
    namespace = kubernetes_namespace_v1.test.metadata[0].name

    labels = {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    }

    annotations = {
      # Load-bearing. The EKS pod identity webhook keys off this annotation to
      # inject AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE into the pod, and
      # source/aws.go detects the "eks-irsa" runtime from exactly that env var.
      # Without the annotation cloud-auth would fall through to the SigV4 path
      # and the IRSA pairs (rows 5 and 6 of the matrix) would never be exercised.
      "eks.amazonaws.com/role-arn" = aws_iam_role.irsa.arn
    }
  }
}

# Lets the verifier mint service-account tokens for ITSELF via the TokenRequest
# API.
#
# The projected token the webhook injects is fixed at aud=sts.amazonaws.com.
# When the target wants a different audience (a GCP workload identity pool
# resource name, or api://AzureADTokenExchange), source/aws.go re-mints one by
# POSTing to serviceaccounts/<name>/token. Default RBAC denies that, so the
# IRSA-to-GCP and IRSA-to-Azure pairs fail with a 403 unless this exists.
#
# resource_names pins it to the single "verifier" account: this Role cannot be
# used to mint a token for any other identity in the namespace.
resource "kubernetes_role_v1" "token_minter" {
  metadata {
    name      = "${var.name_prefix}-token-minter"
    namespace = kubernetes_namespace_v1.test.metadata[0].name

    labels = {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    }
  }

  rule {
    api_groups     = [""]
    resources      = ["serviceaccounts/token"]
    resource_names = [var.irsa_service_account]
    verbs          = ["create"]
  }
}

resource "kubernetes_role_binding_v1" "token_minter" {
  metadata {
    name      = "${var.name_prefix}-token-minter"
    namespace = kubernetes_namespace_v1.test.metadata[0].name

    labels = {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.token_minter.metadata[0].name
  }

  subject {
    api_group = ""
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.verifier.metadata[0].name
    namespace = kubernetes_namespace_v1.test.metadata[0].name
  }
}
