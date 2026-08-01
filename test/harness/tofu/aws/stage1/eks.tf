# EKS -- the IRSA source runtime.
#
# What cloud-auth needs from this cluster:
#   1. A public OIDC issuer (identity[0].oidc[0].issuer). GCP's workload
#      identity pool and Azure's federated identity credential are configured
#      against that URL in the other clouds' stage2.
#   2. A pod whose service account token can be minted for an arbitrary
#      audience. cloud-auth detects the "eks-irsa" runtime from the
#      AWS_WEB_IDENTITY_TOKEN_FILE env var, which the EKS pod identity webhook
#      only injects when the service account carries the
#      eks.amazonaws.com/role-arn annotation -- hence the otherwise-unused IRSA
#      role below.
#   3. Permission to call the TokenRequest API. When the projected token's aud
#      does not match the target (source/aws.go mintIRSA), cloud-auth re-mints
#      one via POST serviceaccounts/<name>/token. Default RBAC does not allow a
#      service account to mint tokens for itself, so the Role/RoleBinding below
#      grants exactly that, scoped to this one service account.

# --- Cluster IAM role -------------------------------------------------------

data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${var.name_prefix}-eks-cluster"
  description        = "EKS control plane role for the cloud-auth test harness (run ${var.run_id})."
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# --- Cluster ----------------------------------------------------------------

resource "aws_eks_cluster" "this" {
  name     = var.name_prefix
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = local.subnet_ids
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = var.eks_public_access_cidrs
  }

  access_config {
    authentication_mode = "API_AND_CONFIG_MAP"

    # The principal running `tofu apply` becomes a cluster admin, which is what
    # lets the kubernetes provider below create the namespace and service
    # account in the same apply.
    bootstrap_cluster_creator_admin_permissions = true
  }

  # Without the cluster policy attached first, deleting the cluster can strand
  # ENIs; without it at create time the control plane cannot come up.
  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

data "aws_eks_cluster_auth" "this" {
  name = aws_eks_cluster.this.name
}

# --- IAM OIDC provider for the cluster issuer -------------------------------

# Registering the cluster's issuer as an IAM OIDC provider is what makes IRSA
# work at all. thumbprint_list is intentionally omitted: the EKS issuer serves
# its JWKS from an Amazon-trusted CA, and IAM verifies it against its own root
# CA library (see CreateOpenIDConnectProvider docs). IAM computes and stores a
# thumbprint itself, so the attribute is Computed rather than empty.
resource "aws_iam_openid_connect_provider" "eks" {
  url            = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]

  tags = {
    Name = "${var.name_prefix}-eks-oidc"
  }
}

locals {
  # "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123"
  eks_oidc_issuer_url = aws_eks_cluster.this.identity[0].oidc[0].issuer

  # "oidc.eks.us-east-1.amazonaws.com/id/ABC123" -- IAM condition keys are
  # prefixed with the issuer minus its scheme.
  eks_oidc_issuer_host_path = replace(local.eks_oidc_issuer_url, "https://", "")

  irsa_subject = "system:serviceaccount:${var.irsa_namespace}:${var.irsa_service_account}"
}

# --- IRSA role for the verifier service account -----------------------------

data "aws_iam_policy_document" "irsa_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    # Scoped to this one service account. An unscoped trust here would let any
    # pod in the cluster assume the role.
    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_issuer_host_path}:sub"
      values   = [local.irsa_subject]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_issuer_host_path}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# This role intentionally has no permissions policies attached. It exists only
# so the pod identity webhook injects AWS_WEB_IDENTITY_TOKEN_FILE / AWS_ROLE_ARN
# into the verifier pod, which is how cloud-auth recognises the eks-irsa source
# runtime. AWS is the *source* in every pair this runtime participates in, so
# the pod needs no AWS permissions at all.
resource "aws_iam_role" "irsa" {
  name               = "${var.name_prefix}-irsa-source"
  description        = "Marker IRSA role for the cloud-auth verifier pod (run ${var.run_id}). Grants nothing by design."
  assume_role_policy = data.aws_iam_policy_document.irsa_assume_role.json
}

# --- Node group IAM role ----------------------------------------------------

data "aws_iam_policy_document" "eks_node_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_node" {
  name               = "${var.name_prefix}-eks-node"
  description        = "EKS worker node role for the cloud-auth test harness (run ${var.run_id})."
  assume_role_policy = data.aws_iam_policy_document.eks_node_assume_role.json
}

resource "aws_iam_role_policy_attachment" "eks_node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    # Lets the driver reach nodes via SSM Session Manager for debugging without
    # opening any inbound port.
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ])

  role       = aws_iam_role.eks_node.name
  policy_arn = each.value
}

# --- Node group -------------------------------------------------------------

# A launch template is used for two reasons: it forces IMDSv2 on the nodes, and
# it propagates the harness tags onto the underlying instances and volumes
# (managed node groups do not do that on their own), which keeps the orphan
# sweep in the README honest.
#
# Note the template deliberately sets neither image_id nor instance_type: EKS
# supplies its own AMI and bootstrap user data, and instance_types stays on the
# node group resource. Setting image_id here would require hand-rolling the
# bootstrap script.
resource "aws_launch_template" "eks_node" {
  name_prefix = "${var.name_prefix}-node-"
  description = "cloud-auth harness EKS node template (run ${var.run_id})."

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"

    # Must be 2, not 1: with a hop limit of 1 the packet from a pod's network
    # namespace is dropped before reaching IMDS, breaking the CNI.
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  # Disk size MUST live here rather than on the node group: EKS rejects a node
  # group that sets diskSize while also referencing a launch template.
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.node_disk_size
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-eks-node"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-eks-node"
    })
  }

  tag_specifications {
    resource_type = "network-interface"
    tags          = local.common_tags
  }
}

resource "aws_eks_node_group" "this" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.name_prefix}-nodes"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = local.subnet_ids

  # instance_types stays here on purpose: the launch template deliberately does
  # not set instance_type, and EKS forbids specifying it in both places.
  instance_types = var.node_instance_types
  capacity_type  = var.node_capacity_type

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_desired_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.eks_node.id
    version = aws_launch_template.eks_node.latest_version
  }

  # Without this, destroy can race: the node role loses its policies before EKS
  # has finished deleting instances and ENIs, and the node group deletion hangs.
  depends_on = [aws_iam_role_policy_attachment.eks_node]

  lifecycle {
    # The harness never autoscales, but EKS may report a different desired_size
    # transiently during a rolling update.
    ignore_changes = [scaling_config[0].desired_size]
  }
}
