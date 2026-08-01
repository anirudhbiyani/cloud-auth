# EC2 -- the SigV4 source runtime.
#
# On a plain EC2 instance there is no OIDC token to present, so cloud-auth's
# AWS source falls back to a SigV4 pre-signed sts:GetCallerIdentity request.
# GCP's workload identity pool accepts that as an "aws" provider; Azure has no
# equivalent, which is the documented gap the harness asserts against
# (ErrNoFirstClassPath).
#
# IMDSv2 is REQUIRED here, not merely enabled. cloud-auth refuses to talk to
# IMDSv1 by design (an SSRF against a v1 endpoint leaks role credentials), so
# an instance that still allowed v1 would silently under-test the guard.

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name = "name"
    # Excludes the "-minimal-" variants, which omit the SSM agent.
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Named exactly "<name_prefix>-ec2-source" to match the ec2_role_name /
# ec2_role_arn examples in test/harness/CONTRACT.md.
#
# The only attached policy is SSM core, so the driver can push and run the
# verifier over Session Manager with no inbound ports and no SSH key. The
# SigV4 proof itself needs no AWS permissions: sts:GetCallerIdentity is
# allowed implicitly for every principal.
resource "aws_iam_role" "ec2_source" {
  name               = "${var.name_prefix}-ec2-source"
  description        = "SigV4 source-runtime role for the cloud-auth test harness (run ${var.run_id})."
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_source.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_source" {
  name = "${var.name_prefix}-ec2-source"
  role = aws_iam_role.ec2_source.name
}

# Egress-only: the instance reaches SSM, STS and the target clouds outbound.
# Nothing needs to reach in.
resource "aws_security_group" "ec2_source" {
  name        = "${var.name_prefix}-ec2-source"
  description = "cloud-auth harness SigV4 source instance: egress only, no ingress."
  vpc_id      = data.aws_vpc.default.id

  egress {
    description      = "Outbound to SSM, STS and cross-cloud token endpoints."
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.name_prefix}-ec2-source"
  }
}

resource "aws_instance" "ec2_source" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.ec2_instance_type
  subnet_id              = local.ec2_subnet_id
  vpc_security_group_ids = [aws_security_group.ec2_source.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_source.name

  # Default-VPC subnets already auto-assign, but be explicit: without a public
  # IP the instance cannot register with SSM and the driver loses its only way
  # in.
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"

    # The whole point of this instance. "required" == IMDSv2 only.
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_size           = var.ec2_root_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true

    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-ec2-source"
    })
  }

  tags = {
    Name = "${var.name_prefix}-ec2-source"
  }
}
