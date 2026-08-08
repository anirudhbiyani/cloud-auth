variable "run_id" {
  description = <<-EOT
    Unique identifier for this harness run (for example "20260705-abc123").
    Applied to every resource as the `run-id` tag so orphaned resources from a
    failed destroy can be found and swept. Required on purpose: a blank or
    shared run id makes the sweep story useless.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", var.run_id))
    error_message = "run_id must be 1-63 chars of alphanumerics, dot, underscore or hyphen, starting with an alphanumeric."
  }
}

variable "name_prefix" {
  description = <<-EOT
    Name prefix for every resource. The EKS cluster is named exactly this, and
    the EC2 source role is named "<name_prefix>-ec2-source", matching the
    examples in test/harness/CONTRACT.md. Vary it if you need two harness runs
    live in the same account at the same time.
  EOT
  type        = string
  default     = "cloud-auth-test"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,37}$", var.name_prefix))
    error_message = "name_prefix must be 2-38 lowercase alphanumerics/hyphens starting with an alphanumeric (leaves room for resource suffixes)."
  }
}

variable "region" {
  description = "AWS region to build the source runtimes in. us-east-1 is the cheapest for the instance types this module uses."
  type        = string
  default     = "us-east-1"
}

variable "extra_tags" {
  description = "Additional tags merged onto every resource, on top of managed-by and run-id."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

variable "subnet_ids" {
  description = <<-EOT
    Explicit subnet ids for the EKS control plane, node group and EC2 instance.
    Leave empty (the default) to auto-select the default VPC's default subnets,
    which keeps the harness free of NAT gateways. Must span at least two AZs.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.subnet_ids) == 0 || length(var.subnet_ids) >= 2
    error_message = "subnet_ids must be empty (auto-select) or contain at least two subnets in different AZs."
  }
}

variable "excluded_availability_zones" {
  description = <<-EOT
    Availability zones to skip when auto-selecting default subnets. EKS control
    planes cannot be placed in us-east-1e, so it is excluded by default; an
    apply against the raw default-subnet list would fail there.
  EOT
  type        = list(string)
  default     = ["us-east-1e"]
}

variable "max_subnets" {
  description = "How many auto-selected default subnets to hand to EKS. Two is the EKS minimum; three spreads the node group a little wider at no extra cost."
  type        = number
  default     = 3

  validation {
    condition     = var.max_subnets >= 2 && var.max_subnets <= 6
    error_message = "max_subnets must be between 2 and 6 (EKS requires subnets in at least two AZs)."
  }
}

# ---------------------------------------------------------------------------
# EKS (the IRSA source runtime)
# ---------------------------------------------------------------------------

variable "eks_version" {
  description = "Kubernetes minor version for the EKS cluster, e.g. \"1.33\". Leave null to take whatever EKS currently defaults to."
  type        = string
  default     = null
}

variable "node_instance_types" {
  description = <<-EOT
    Instance types for the managed node group. t3.small is the smallest type
    that comfortably fits the EKS system pods (coredns, aws-node, kube-proxy)
    plus the verifier pod; t3.micro only supports 4 pod IPs and will wedge.
    Kept on x86_64 so one verifier binary runs on both the node group and the
    EC2 SigV4 instance.
  EOT
  type        = list(string)
  default     = ["t3.small"]
}

variable "node_capacity_type" {
  description = "ON_DEMAND or SPOT for the node group. SPOT is roughly 70% cheaper but can be reclaimed mid-verification, so ON_DEMAND is the default."
  type        = string
  default     = "ON_DEMAND"

  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.node_capacity_type)
    error_message = "node_capacity_type must be ON_DEMAND or SPOT."
  }
}

variable "node_disk_size" {
  description = "EBS root volume size in GiB for each node. 20 is the practical floor for the EKS AMI plus images."
  type        = number
  default     = 20
}

variable "node_desired_size" {
  description = "Desired node count. One node is enough to run a single verifier pod."
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum node count. Kept at 2 so a rolling replacement can proceed without a scaling failure."
  type        = number
  default     = 2
}

variable "eks_public_access_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the public EKS API endpoint. The default is open
    because the harness runner (CI or a laptop) has no fixed egress IP; the API
    is still authenticated via IAM. Narrow it if your runner has a stable IP.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "irsa_namespace" {
  description = "Kubernetes namespace holding the verifier service account. Fixed by test/harness/CONTRACT.md."
  type        = string
  default     = "cloud-auth-test"
}

variable "irsa_service_account" {
  description = "Kubernetes service account the verifier pod runs as. Fixed by test/harness/CONTRACT.md."
  type        = string
  default     = "verifier"
}

# ---------------------------------------------------------------------------
# EC2 (the SigV4 source runtime)
# ---------------------------------------------------------------------------

variable "ec2_instance_type" {
  description = "Instance type for the SigV4 source instance. t3.micro is ample: it only signs an sts:GetCallerIdentity request."
  type        = string
  default     = "t3.micro"
}

variable "ec2_root_volume_size" {
  description = "Root volume size in GiB for the SigV4 source instance."
  type        = number
  default     = 8
}
