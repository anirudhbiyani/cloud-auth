data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# The role NAME is the identity under test: gcp/stage2's SigV4 provider scopes
# attribute.aws_role to it. No permissions beyond logs — the proof is
# sts:GetCallerIdentity, which every principal may call.
resource "aws_iam_role" "source" {
  name               = "${var.name_prefix}-lambda-source"
  description        = "cloud-auth harness Lambda source runtime (run ${var.run_id})."
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.source.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "verifier" {
  function_name = "${var.name_prefix}-verifier"
  description   = "cloud-auth harness verifier (run ${var.run_id}): event = targets.json, response = report."
  role          = aws_iam_role.source.arn
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["x86_64"]
  timeout       = 120
  memory_size   = 256

  filename         = var.zip_path
  source_code_hash = var.zip_path != "" ? filebase64sha256(var.zip_path) : null

  depends_on = [aws_iam_role_policy_attachment.logs]
}
