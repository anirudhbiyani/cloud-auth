# CONTRACT: state/aws-lambda.json
output "lambda_function_name" {
  value = aws_lambda_function.verifier.function_name
}

output "lambda_role_name" {
  description = "Bare role name; gcp/stage2 scopes its SigV4 provider to this."
  value       = aws_iam_role.source.name
}

output "lambda_role_arn" {
  value = aws_iam_role.source.arn
}

output "region" {
  value = var.region
}
