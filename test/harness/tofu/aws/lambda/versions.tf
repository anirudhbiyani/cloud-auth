# aws/lambda -- a serverless AWS SOURCE runtime (SigV4 proof), no VM or cluster.
#
# Lambda vends execution-role credentials in-process, so cloud-auth mints the
# same SigV4 GetCallerIdentity proof it would on EC2. This module exists so the
# AWS → GCP SigV4 pair and the AWS → Azure negative test can run without an EC2
# instance. Local state only, no backend block.

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
    tags = {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    }
  }
}
