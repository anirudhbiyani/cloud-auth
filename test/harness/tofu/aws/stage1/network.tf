# Networking.
#
# The harness deliberately reuses the account's default VPC. Its subnets are
# public and already auto-assign public IPs, so nodes and the EC2 instance can
# reach the EKS API, ECR, SSM and the other clouds' token endpoints without a
# NAT gateway -- which would otherwise be the single most expensive line item
# in this harness (~$0.045/hr plus data processing, i.e. more than everything
# else here combined).

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

# Only the "default for AZ" subnets: exactly one per availability zone, so the
# az -> subnet map below can never collide.
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_subnet" "default" {
  for_each = toset(data.aws_subnets.default.ids)
  id       = each.value
}

locals {
  common_tags = merge(
    {
      "managed-by" = "cloud-auth-harness"
      "run-id"     = var.run_id
    },
    var.extra_tags,
  )

  # az -> subnet id, minus any AZ that EKS cannot use.
  eligible_subnets_by_az = {
    for subnet_id, subnet in data.aws_subnet.default :
    subnet.availability_zone => subnet_id
    if !contains(var.excluded_availability_zones, subnet.availability_zone)
  }

  # Sorted so repeated plans pick the same subnets rather than churning.
  sorted_eligible_azs = sort(keys(local.eligible_subnets_by_az))

  auto_subnet_ids = [
    for az in slice(
      local.sorted_eligible_azs,
      0,
      min(var.max_subnets, length(local.sorted_eligible_azs)),
    ) : local.eligible_subnets_by_az[az]
  ]

  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : local.auto_subnet_ids

  # The EC2 SigV4 source only needs one subnet.
  ec2_subnet_id = local.subnet_ids[0]
}

# Fail loudly at plan time rather than with an opaque EKS API error if the
# default VPC does not have usable subnets in two AZs.
check "enough_subnets" {
  assert {
    condition     = length(local.subnet_ids) >= 2
    error_message = "EKS needs subnets in at least two availability zones; found ${length(local.subnet_ids)}. Pass -var 'subnet_ids=[...]' explicitly, or check excluded_availability_zones."
  }
}
