# AWS harness modules

Real AWS infrastructure for the cloud-auth cross-cloud integration harness.
Read [`../../CONTRACT.md`](../../CONTRACT.md) first — it is authoritative for
the output key names, the two-stage split, and the safety rules.

Tooling is **OpenTofu**. Every command below is `tofu`, never `terraform`.

| Module | Role | Costs money? |
|---|---|---|
| [`stage1/`](stage1) | AWS as a **source** runtime (EKS-IRSA + EC2 SigV4) | Yes, ~$0.15/hr |
| [`stage2/`](stage2) | AWS as a **target** (IAM trust for GCP and Azure sources) | No, IAM only |

```
tofu -chdir=test/harness/tofu/aws/stage1 init
tofu -chdir=test/harness/tofu/aws/stage1 apply -var run_id="$RUN_ID"

# ... after GCP and Azure stage1 have written their state/*.json ...

tofu -chdir=test/harness/tofu/aws/stage2 init
tofu -chdir=test/harness/tofu/aws/stage2 apply -var-file=generated.tfvars
```

State is local (`terraform.tfstate` beside each module, gitignored). There is no
backend block and no vendor login: the harness must be runnable with nothing but
cloud credentials, and its state is disposable by design.

---

## stage1 — AWS as a source runtime

Two source runtimes, because cloud-auth mints two different kinds of proof on AWS.

**EKS (the IRSA / OIDC source)**

- `aws_eks_cluster` named `var.name_prefix`, public API endpoint, in the default VPC.
- `aws_iam_openid_connect_provider` registered against the cluster's issuer.
- One managed node group, one `t3.small` node, driven by a launch template that
  forces IMDSv2 with a **hop limit of 2** (a hop limit of 1 drops packets from
  pod network namespaces and breaks the CNI).
- Namespace `cloud-auth-test`, service account `verifier`.
- A marker IRSA role with **no permissions attached**. It exists only so the EKS
  pod identity webhook injects `AWS_WEB_IDENTITY_TOKEN_FILE` — which is exactly
  how `source/aws.go` detects the `eks-irsa` runtime. Without the annotation,
  cloud-auth falls through to the SigV4 path and rows 5 and 6 of the pair matrix
  silently test the wrong thing.
- A `Role`/`RoleBinding` granting the `verifier` account `create` on
  `serviceaccounts/token` **for itself only**. The injected token is fixed at
  `aud=sts.amazonaws.com`; when the target wants a different audience,
  `source/aws.go` re-mints via the TokenRequest API. Default RBAC denies that,
  so without this the IRSA→GCP and IRSA→Azure pairs fail with a 403.

**EC2 (the SigV4 source)**

- One `t3.micro` on Amazon Linux 2023 with an instance profile.
- `http_tokens = "required"` — IMDSv2 only. cloud-auth refuses IMDSv1 by design
  (an SSRF against a v1 endpoint leaks role credentials), so an instance that
  still allowed v1 would under-test the guard.
- Egress-only security group, no inbound rules, no SSH key. The driver reaches
  it over SSM Session Manager, which is why the role carries
  `AmazonSSMManagedInstanceCore` and nothing else.

### Outputs

Exactly the eleven keys `CONTRACT.md` specifies for `state/aws-stage1.json`, and
nothing else — so the driver can render the file verbatim:

```sh
tofu -chdir=test/harness/tofu/aws/stage1 output -json \
  | jq 'map_values(.value)' > test/harness/state/aws-stage1.json
```

`account_id`, `region`, `eks_cluster_name`, `eks_oidc_issuer_url`,
`eks_oidc_issuer_host_path`, `irsa_namespace`, `irsa_service_account`,
`irsa_subject`, `ec2_instance_id`, `ec2_role_arn`, `ec2_role_name`.

---

## stage2 — AWS as a target

Consumes the **other** clouds' stage-1 facts as plain input variables. It does
not read the GCP or Azure tofu state: those modules are applied independently,
and reading a sibling's state would reintroduce the dependency cycle the
two-stage split exists to break. See [`stage2/example.tfvars`](stage2/example.tfvars)
for the field mapping and a jq snippet that generates the real file.

Creates one IAM OIDC provider for the AKS issuer, two roles with
`sts:AssumeRoleWithWebIdentity` trust policies, and a shared read-only probe
policy granting `s3:ListAllMyBuckets`. `sts:GetCallerIdentity` needs no
permission at all, so on its own it cannot distinguish "credentials minted
correctly" from "credentials minted but inert"; `ListAllMyBuckets` is the
smallest action that actually requires an authorized principal.

### Getting the trust conditions right

Both roles are scoped on `:sub` **and** `:aud`. An unscoped trust would be a
confused-deputy hole: for Azure the issuer URL is the only cluster-specific
element, so without `:sub` any pod in that cluster could assume the role.
`gcp_source_sa_unique_id` and `azure_subject` therefore have **no defaults** and
carry validation rules that reject wildcards.

Two details are not the obvious 1:1 mapping and are worth knowing before you
edit `stage2/main.tf`:

**Google's `aud` is not the audience.** A Google service-account ID token minted
for `sts.amazonaws.com` carries `sub=<sa unique id>`, `aud=sts.amazonaws.com`,
`azp=<sa unique id>`. Per the [IAM condition-key reference][iam-keys], AWS maps
those to `accounts.google.com:aud ← azp when azp is set, else aud`, and
`accounts.google.com:oaud ← aud`. So conditioning `:aud` on `sts.amazonaws.com`
alone — the intuitive reading, and what a literal reading of `CONTRACT.md`
implies — **fails** whenever Google emits `azp`, which it does for service
accounts. The module pins the audience via `:oaud` and lets `:aud` accept either
legitimate value. Nothing is loosened: `:sub` still pins the exact service
account and every value is an exact string.

**Google is a built-in AWS IdP.** `CreateOpenIDConnectProvider` documents that
Google, Facebook and Amazon Cognito are already built into AWS STS and do not
need a separate IAM provider, and the IAM docs give the principal as the bare
string `"accounts.google.com"` rather than a provider ARN. That is the default
here. Set `create_google_oidc_provider = true` to register one explicitly and
switch the principal to its ARN.

**Azure trailing slash.** AKS issuer URLs end in `/`, and whether IAM keeps or
strips that on the registered provider URL is undocumented. Rather than guess,
the Azure trust policy emits one statement per candidate prefix (with and
without the slash). Both are fully scoped on `:sub` and `:aud`, so the one that
does not match simply never fires — a guarantee that the correct key is present,
with no weakening. `distinct()` collapses them if you pass a URL with no slash.

[iam-keys]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html

### Outputs

Exactly the three keys `CONTRACT.md` specifies for `state/aws-stage2.json`:

```sh
tofu -chdir=test/harness/tofu/aws/stage2 output -json \
  | jq 'map_values(.value)' > test/harness/state/aws-stage2.json
```

`audience`, `role_arn_for_gcp_source`, `role_arn_for_azure_source`.

---

## Cost estimate

On-demand `us-east-1` list prices, defaults unchanged. **stage2 is free** — it
creates only IAM objects.

| Item | Qty | $/hour | $/day |
|---|---|---|---|
| **EKS control plane** | 1 | **0.1000** | **2.400** |
| EC2 node group (`t3.small`) | 1 | 0.0208 | 0.499 |
| Node EBS root (20 GiB gp3) | 1 | 0.0022 | 0.053 |
| EC2 SigV4 instance (`t3.micro`) | 1 | 0.0104 | 0.250 |
| SigV4 EBS root (8 GiB gp3) | 1 | 0.0009 | 0.021 |
| Public IPv4 addresses | 2 | 0.0100 | 0.240 |
| IAM roles, OIDC providers, SGs, launch template, instance profile | — | 0.0000 | 0.000 |
| **Total** | | **~$0.144/hr** | **~$3.46/day** |

**The EKS control plane is ~$0.10/hr — roughly 70% of the bill**, and it is
billed from the moment `CreateCluster` returns until the cluster is deleted,
whether or not any nodes are running. Deleting the node group alone saves almost
nothing.

A full `up → verify → down` cycle runs about 35–45 minutes wall-clock (EKS takes
~10 min to create and ~10 min to delete), so roughly **$0.10–0.12 per run**. The
danger is not the run, it is a leaked cluster: a forgotten stage1 costs about
**$104/month**. Sweep aggressively.

Cheaper knobs: `-var node_capacity_type=SPOT` cuts the node to roughly $0.006/hr
(but it can be reclaimed mid-verification, which is why it is not the default).
Cross-AZ and internet data transfer for a verification run is a few kilobytes
and rounds to zero. Fargate was considered instead of a node group and rejected:
it requires private subnets, which would mean a NAT gateway at ~$0.045/hr plus
data processing — more than everything in the table above combined.

---

## Required IAM permissions

The simplest correct answer is `AdministratorAccess` on a throwaway sandbox
account, which is what this harness is designed for. If you need least
privilege, the principal running `tofu` needs:

**stage1**

- `sts:GetCallerIdentity`
- `ec2:Describe*` (VPCs, subnets, images, instances, security groups, launch templates)
- `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:CreateTags`, `ec2:DeleteTags`
- `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`, `ec2:AuthorizeSecurityGroupEgress`, `ec2:RevokeSecurityGroupEgress`
- `ec2:CreateLaunchTemplate`, `ec2:CreateLaunchTemplateVersion`, `ec2:DeleteLaunchTemplate`
- `eks:CreateCluster`, `eks:DescribeCluster`, `eks:DeleteCluster`, `eks:TagResource`
- `eks:CreateNodegroup`, `eks:DescribeNodegroup`, `eks:DeleteNodegroup`, `eks:UpdateNodegroupConfig`
- `eks:CreateAccessEntry`, `eks:DescribeAccessEntry`, `eks:DeleteAccessEntry`, `eks:AssociateAccessPolicy`
- `iam:CreateRole`, `iam:DeleteRole`, `iam:GetRole`, `iam:TagRole`, `iam:PassRole`
- `iam:AttachRolePolicy`, `iam:DetachRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`
- `iam:CreateInstanceProfile`, `iam:DeleteInstanceProfile`, `iam:GetInstanceProfile`, `iam:AddRoleToInstanceProfile`, `iam:RemoveRoleFromInstanceProfile`
- `iam:CreateOpenIDConnectProvider`, `iam:DeleteOpenIDConnectProvider`, `iam:GetOpenIDConnectProvider`, `iam:TagOpenIDConnectProvider`
- Kubernetes-side admin on the new cluster, which
  `bootstrap_cluster_creator_admin_permissions = true` grants automatically to
  whoever runs the apply.

**stage2**

- `sts:GetCallerIdentity`
- `iam:CreateRole`, `iam:DeleteRole`, `iam:GetRole`, `iam:TagRole`, `iam:UpdateAssumeRolePolicy`
- `iam:CreatePolicy`, `iam:DeletePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`
- `iam:AttachRolePolicy`, `iam:DetachRolePolicy`, `iam:ListAttachedRolePolicies`
- `iam:CreateOpenIDConnectProvider`, `iam:DeleteOpenIDConnectProvider`, `iam:GetOpenIDConnectProvider`, `iam:TagOpenIDConnectProvider`

---

## Destroying

Tear down **stage2 first, then stage1**. Destroy never depends on verification
having passed, and either module can be destroyed even if its apply half-failed.

```sh
tofu -chdir=test/harness/tofu/aws/stage2 destroy -var-file=generated.tfvars
tofu -chdir=test/harness/tofu/aws/stage1 destroy -var run_id="$RUN_ID"
```

stage1 destroy takes ~10 minutes; most of it is EKS deleting the control plane.

If stage1 destroy fails partway, **rerun it** — the usual cause is a transient
ENI detach race, and a second pass almost always clears it.

### Sweeping orphans by tag

Every resource carries `managed-by=cloud-auth-harness` and `run-id=<run id>`,
including the node group's EC2 instances and EBS volumes (that is why the launch
template exists — managed node groups do not propagate tags on their own).

Find everything left behind:

```sh
aws resourcegroupstaggingapi get-resources \
  --region us-east-1 \
  --tag-filters Key=managed-by,Values=cloud-auth-harness \
  --query 'ResourceTagMappingList[].ResourceARN' --output table
```

Add `Key=run-id,Values=<run id>` to scope to a single run. IAM is global, so
query it from `us-east-1` to catch roles and OIDC providers.

Delete manually in this order — **the order matters**, each step blocks the next:

```sh
PREFIX=cloud-auth-test          # your name_prefix
REGION=us-east-1

# 1. Node group before the cluster. Blocks ~5 min.
aws eks delete-nodegroup --region "$REGION" \
  --cluster-name "$PREFIX" --nodegroup-name "$PREFIX-nodes"
aws eks wait nodegroup-deleted --region "$REGION" \
  --cluster-name "$PREFIX" --nodegroup-name "$PREFIX-nodes"

# 2. Cluster. Stops the $0.10/hr meter. Do this one first if you are in a hurry.
aws eks delete-cluster --region "$REGION" --name "$PREFIX"

# 3. SigV4 instance.
aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:managed-by,Values=cloud-auth-harness" \
            "Name=instance-state-name,Values=running,stopped,pending" \
  --query 'Reservations[].Instances[].InstanceId' --output text \
  | xargs -r aws ec2 terminate-instances --region "$REGION" --instance-ids

# 4. Security group and launch template, only after the instances are gone.
aws ec2 delete-security-group --region "$REGION" --group-name "$PREFIX-ec2-source"
aws ec2 describe-launch-templates --region "$REGION" \
  --filters "Name=tag:managed-by,Values=cloud-auth-harness" \
  --query 'LaunchTemplates[].LaunchTemplateId' --output text \
  | xargs -r -n1 aws ec2 delete-launch-template --region "$REGION" --launch-template-id

# 5. Instance profile: the role must be removed from it before either can go.
aws iam remove-role-from-instance-profile \
  --instance-profile-name "$PREFIX-ec2-source" --role-name "$PREFIX-ec2-source"
aws iam delete-instance-profile --instance-profile-name "$PREFIX-ec2-source"

# 6. Roles: detach every managed policy first, then delete.
for ROLE in "$PREFIX-eks-cluster" "$PREFIX-eks-node" "$PREFIX-ec2-source" \
            "$PREFIX-irsa-source" "$PREFIX-from-gcp" "$PREFIX-from-azure"; do
  aws iam list-attached-role-policies --role-name "$ROLE" \
    --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null \
    | tr '\t' '\n' | xargs -r -n1 aws iam detach-role-policy --role-name "$ROLE" --policy-arn
  aws iam delete-role --role-name "$ROLE" 2>/dev/null
done

# 7. OIDC providers (EKS issuer, AKS issuer, and Google if you enabled it).
aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text \
  | tr '\t' '\n' \
  | while read -r ARN; do
      aws iam list-open-id-connect-provider-tags --open-id-connect-provider-arn "$ARN" \
        --query "Tags[?Key=='managed-by'].Value" --output text | grep -q cloud-auth-harness \
        && aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$ARN"
    done

# 8. The stage2 probe policy.
aws iam delete-policy --policy-arn \
  "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$PREFIX-probe"
```

---

## Assumptions and knobs

- **Default VPC.** The module reuses the account's default VPC and its
  default-per-AZ subnets. They are public and auto-assign IPs, so nodes and the
  instance reach EKS, ECR, SSM and the other clouds without a NAT gateway. Pass
  `-var 'subnet_ids=["subnet-a","subnet-b"]'` to override. An account with no
  default VPC must supply `subnet_ids`.
- **`us-east-1e` is excluded** from auto-selection because EKS control planes
  cannot be placed there; an apply against the raw default-subnet list fails.
  See `excluded_availability_zones`.
- **The EKS API endpoint is public** and open to `0.0.0.0/0` by default, because
  a CI runner has no fixed egress IP. It is still IAM-authenticated. Narrow it
  with `eks_public_access_cidrs` if your runner has a stable address.
- **The cluster is named exactly `var.name_prefix`**, matching the
  `CONTRACT.md` example. Two concurrent runs in one account therefore need
  different `name_prefix` values, not just different `run_id`s.
- **`run_id` is required** in both stages — no default. A blank or shared run id
  makes the orphan sweep useless, which is the one thing standing between a
  failed destroy and a $104/month surprise.
- `node_instance_types` stays on x86_64 so a single verifier binary runs on both
  the node group and the SigV4 instance. `t3.micro` nodes will not work: only 4
  pod IPs, which the system pods exhaust.
