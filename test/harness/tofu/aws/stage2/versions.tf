# stage2 -- AWS as a TARGET.
#
# Tooling is OpenTofu:
#   tofu -chdir=test/harness/tofu/aws/stage2 init
#   tofu -chdir=test/harness/tofu/aws/stage2 apply -var-file=generated.tfvars
#
# This module consumes the OTHER clouds' stage-1 facts as plain input
# variables. It deliberately does NOT read gcp/ or azure/ tofu state: the three
# clouds' stage-1 modules are applied independently (possibly on different
# machines), and reading a sibling's state would couple their lifecycles and
# reintroduce the dependency cycle that the two-stage split exists to break.
# The driver renders a tfvars file from state/gcp-stage1.json and
# state/azure-stage1.json; see example.tfvars.
#
# Local state only, no backend block.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0, < 7.0.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}
