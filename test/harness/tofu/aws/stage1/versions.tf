# stage1 — AWS as a SOURCE runtime.
#
# Tooling is OpenTofu. Run every command as `tofu`, never `terraform`:
#   tofu -chdir=test/harness/tofu/aws/stage1 init
#   tofu -chdir=test/harness/tofu/aws/stage1 apply
#
# Local state only (terraform.tfstate in this directory, gitignored). There is
# deliberately no backend block: the harness must be runnable with nothing but
# cloud credentials, and its state is disposable by design.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0, < 7.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.30.0, < 3.0.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Every resource this module creates is tagged so that a failed `down.sh`
  # leaves findable, sweepable orphans. See README "Sweeping orphans".
  default_tags {
    tags = local.common_tags
  }
}

# The Kubernetes provider is pointed at the cluster this module creates.
# `aws_eks_cluster_auth` mints the API token in-process, so the harness does
# not require the AWS CLI or an updated kubeconfig on the runner.
provider "kubernetes" {
  host                   = aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}
