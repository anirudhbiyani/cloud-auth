# Outputs -- these keys ARE the contract.
#
# test/harness/CONTRACT.md pins the exact shape of state/aws-stage1.json. This
# module deliberately declares no other outputs, so the driver can produce that
# file verbatim with:
#
#   tofu -chdir=test/harness/tofu/aws/stage1 output -json \
#     | jq 'map_values(.value)' > test/harness/state/aws-stage1.json
#
# Adding an output here changes that file. Don't, unless CONTRACT.md changes first.

output "account_id" {
  description = "AWS account id hosting the source runtimes."
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region the source runtimes live in."
  value       = var.region
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster providing the IRSA source runtime."
  value       = aws_eks_cluster.this.name
}

output "eks_oidc_issuer_url" {
  description = "EKS OIDC issuer URL, scheme included. GCP's WIF provider and Azure's federated credential are configured against this exact string."
  value       = local.eks_oidc_issuer_url
}

output "eks_oidc_issuer_host_path" {
  description = "EKS OIDC issuer with the https:// scheme stripped, as used in IAM condition-key prefixes and as the IAM OIDC provider's ARN suffix."
  value       = local.eks_oidc_issuer_host_path
}

output "irsa_namespace" {
  description = "Namespace the verifier pod runs in."
  value       = kubernetes_namespace_v1.test.metadata[0].name
}

output "irsa_service_account" {
  description = "Service account the verifier pod runs as."
  value       = kubernetes_service_account_v1.verifier.metadata[0].name
}

output "irsa_subject" {
  description = "The sub claim of the projected token, i.e. what other clouds' stage2 trust policies must be scoped to."
  value       = local.irsa_subject
}

output "ec2_instance_id" {
  description = "Instance id of the SigV4 source runtime. The driver targets this with SSM SendCommand."
  value       = aws_instance.ec2_source.id
}

output "ec2_role_arn" {
  description = "ARN of the role attached to the SigV4 source instance. GCP's aws-type WIF provider maps this principal."
  value       = aws_iam_role.ec2_source.arn
}

output "ec2_role_name" {
  description = "Name of the role attached to the SigV4 source instance."
  value       = aws_iam_role.ec2_source.name
}
