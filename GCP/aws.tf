data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "aws-gcp-role" {
    name                = "aws-gcp-role"
    assume_role_policy  = data.aws_iam_policy_document.instance_assume_role_policy.json 
    managed_policy_arns = []
}

resource "google_service_account" "sa-name" {
  account_id = "aws-access"
  display_name = "aws-access"
}

resource "google_project_iam_member" "firestore_owner_binding" {
  project = "<your_gcp_project_id_here>"
  role    = "roles/reader"
  member  = "serviceAccount:${google_service_account.sa-name.email}"
}

resource "google_iam_workload_identity_pool" "example" {
  workload_identity_pool_id = "example-pool"
  display_name              = "Name of pool"
  description               = "Identity pool for automated test"
}

resource "google_iam_workload_identity_pool_provider" "example" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "example-prvdr"
  display_name                       = "Name of provider"
  description                        = "AWS identity pool provider for automated test"
  disabled                           = true
  attribute_condition                = "attribute.aws_role==\"arn:aws:sts::999999999999:assumed-role/stack-eu-central-1-lambdaRole\""
  attribute_mapping                  = {
    "google.subject"        = "assertion.arn"
    "attribute.aws_account" = "assertion.account"
    "attribute.environment" = "assertion.arn.contains(\":instance-profile/Production\") ? \"prod\" : \"test\""
  }
  aws {
    account_id = "999999999999"
  }
}

resource "google_service_account_iam_binding" "admin-account-iam" {
  service_account_id = google_service_account.sa.name
  role               = "roles/iam.serviceAccountUser"
  members = [
    "user:jane@example.com",
  ]
}


resource "google_project_service" "project" {
  project = "your-project-id"
  service = "iam.googleapis.com"
}