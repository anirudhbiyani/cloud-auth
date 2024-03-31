variable "serviceaccountid" {
    description = "Unique ID of the GCP Service Account" 
    type = string
}

resource "aws_iam_role" "gcp-aws-role" {
    name = "gcp-aws-role"
    description = "IAM Role that would be used to access AWS Resource from GCP using Web Identity"
    max_session_duration = 43200
    assume_role_policy = data.aws_iam_policy_document.assume_role_with_gcp
    managed_policy_arns = []
}

data "aws_iam_policy_document" "assume_role_with_gcp" {
    statement {
        effect = "Allow"
        actions = ["sts:AssumeRoleWithWebIdentity"]
        principals {
          type = "Federated"
          identifiers = ["accounts.google.com"]
        }
        condition {
            test     = "StringEquals"
            variable = "accounts.google.com:aud"
            values   = var.serviceaccountid
        }
    }
}
