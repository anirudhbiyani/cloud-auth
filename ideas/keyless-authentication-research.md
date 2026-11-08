# Keyless authentication between AWS, GCP, Azure, Anthropic and OpenAI

*Research notes, 2026-11-09. Facts below were checked against vendor documentation on that date; links are at the end. This is a survey of what is possible and what cloud-auth does with it, not a design commitment. No code changed with this document.*

## 1. What "keyless" means here

A workload proves who it is with something its platform already gave it, and the target verifies that proof directly against the platform. Nothing long-lived is minted, stored, rotated or leaked. Four proof shapes exist in practice:

| Proof | What it is | Who mints it | Who can verify it |
|---|---|---|---|
| **OIDC JWT** | Signed JSON Web Token with `iss`, `sub`, `aud`, `exp`; verified against the issuer's published JWKS | Kubernetes API servers, GitHub Actions, GCP metadata server, Entra ID, AWS STS (outbound federation), SPIRE, Okta | Everyone: AWS, GCP, Azure, Anthropic, OpenAI |
| **SigV4 request** | A signed AWS `GetCallerIdentity` request that the target replays against AWS STS | Any AWS principal | GCP only |
| **X.509 client certificate** | mTLS at the token endpoint; identity from the certificate chain | SPIRE (X.509-SVID), private CAs, GCP managed workload identities | GCP (GA since May 2025), OpenAI (beta). Not AWS STS, not Entra FIC, not Anthropic |
| **Opaque platform credential** | Vendor-internal credentials with no externally verifiable form | AWS EKS Pod Identity, Azure managed identity *without* an audience you control | Nobody outside the vendor. Must be bridged (section 5) |

The OIDC JWT is the lingua franca. Every one of the five providers verifies it, so a design that gets every workload to an OIDC JWT has solved federation once for all targets. The rest of this document is about how each compute environment gets one, what each target does with it, and where the gaps are.

## 2. What each compute environment can mint

### AWS

| Runtime | Proof available | Notes |
|---|---|---|
| EC2, ECS, Lambda, any IAM role session | **OIDC JWT** via `sts:GetWebIdentityToken` (outbound identity federation) | Opt-in per account (`iam:EnableOutboundWebIdentityFederation`); caller needs `sts:GetWebIdentityToken`. Issuer is account-specific: `https://<id>.tokens.sts.global.api.aws`. Claims include `sub` = principal ARN, `jti`, and a `https://sts.amazonaws.com/` block with `aws_account`, `org_id`, `ou_path`, `principal_tags`, and session context such as `ec2_source_instance_arn` and `lambda_source_function_arn`. Up to 50 request tags become custom claims. Regional STS endpoints only. Tokens cannot be used to assume an AWS role via `AssumeRoleWithWebIdentity`. |
| EC2, ECS, Lambda | **SigV4** `GetCallerIdentity` | Zero prerequisites; works in any account. GCP is the only target that replays it. |
| EKS with IRSA | **OIDC JWT** (projected service-account token) | Issuer `https://oidc.eks.<region>.amazonaws.com/id/<cluster>`, public discovery. `sub` = `system:serviceaccount:<ns>:<sa>`. Audience chosen per projection. |
| EKS Pod Identity | **Opaque** (IAM role credentials from the Pod Identity agent) | Not federatable by itself. But the credentials *are* an IAM role session, so `sts:GetWebIdentityToken` works from them once outbound federation is on. See idea 5.1. |

### GCP

| Runtime | Proof available | Notes |
|---|---|---|
| GCE, GKE (Workload Identity with a GSA), Cloud Run, Cloud Functions | **OIDC JWT** from the metadata server identity endpoint | Issuer `https://accounts.google.com`, `sub` = service account unique id, `azp` present. Audience chosen per request. AWS maps `aud` to `azp` for this issuer, so AWS trust policies pin `:oaud` not `:aud`. |
| GKE (projected service-account token) | **OIDC JWT** | Issuer `https://container.googleapis.com/v1/projects/<p>/locations/<l>/clusters/<c>`, public discovery. Kubernetes-shaped `sub`. Works for clusters with no GSA mapping. |
| Any GCP workload with a CAS-issued certificate (managed workload identities) | **X.509-SVID** | For mTLS inside Google Cloud; could reach OpenAI's X.509 beta. Not a cross-cloud path today. |

### Azure

| Runtime | Proof available | Notes |
|---|---|---|
| AKS with Workload Identity | **OIDC JWT** (projected service-account token) | Issuer `https://<region>.oic.prod-aks.azure.com/<tenant>/<id>/`, public discovery, trailing slash matters. Default projected audience `api://AzureADTokenExchange`; other audiences via TokenRequest (needs RBAC on `serviceaccounts/token`). |
| VM, App Service, Container Apps with a managed identity | **Entra access token** from IMDS | *Looks* opaque but is a standard RS256 JWT with `iss` = `https://sts.windows.net/<tenant>/` (or the v2.0 authority) and `sub` = the managed identity's object id. The catch: its `aud` is whatever `resource=` was requested. Register an app in the tenant, give it an Application ID URI, request the token with that URI as the resource, and the result is an audience-pinned OIDC JWT that GCP, AWS, Anthropic and OpenAI all document accepting. cloud-auth currently refuses these runtimes; see idea 5.2. |

### Kubernetes outside the big three

| Runtime | Proof available | Notes |
|---|---|---|
| Self-managed cluster | **OIDC JWT** (projected token) | The API server serves `/.well-known/openid-configuration` and `/openid/v1/jwks`, but behind cluster auth. Options: bind `system:service-account-issuer-discovery` to unauthenticated and expose the endpoints publicly; publish the two documents to a static bucket and set `--service-account-issuer` to that URL; or use a target that accepts an uploaded JWKS (Anthropic `inline`, OpenAI "uploaded JWKS"). Key rotation is the operator's problem in the upload modes. |
| Any cluster with SPIRE | **JWT-SVID** via the SPIRE Agent Workload API, discovery via `spire-oidc-discovery-provider` | One issuer for every cluster and VM in the trust domain. `sub` = `spiffe://trust-domain/path`. Entra requires the JWKS keys to carry `"use":"sig"` (`set_key_use` in the discovery provider). Anthropic and OpenAI have first-class SPIFFE guides. AWS had JWT-SVID validation issues in 2024 that SPIRE worked around; verify on a current release. |
| Any cluster with SPIRE | **X.509-SVID** | Accepted by GCP WIF X.509 providers and OpenAI's mTLS beta. Not by AWS STS, Entra FIC, or Anthropic. |

### CI and brokers

| Source | Proof | Notes |
|---|---|---|
| GitHub Actions | OIDC JWT, `id-token: write` | Shared issuer for all of GitHub, so every target must scope the subject. Anthropic and OpenAI both ship guides. |
| HashiCorp Vault | Broker: JWT auth in, cloud secrets engines out | Not a proof source itself; a hop. cloud-auth already models it as a trust peer. |
| Okta | Client-credentials with a service app | Needs a client secret or private key JWT at Okta; keyless only in the sense of no *target* key. Anthropic lists it. |

## 3. What each target accepts

| Target | Trust object | Accepts | Does not accept | Limits worth knowing |
|---|---|---|---|---|
| **AWS** | IAM OIDC provider + role trust policy (`AssumeRoleWithWebIdentity`) | Any OIDC JWT (RS256/ES); Google and Cognito built in without a provider object | SigV4 from another account's compute, X.509, SAML for workloads | One provider per issuer URL per account; `:aud` vs `:oaud` for Google tokens; trailing-slash issuers are undocumented territory, pin both |
| **GCP** | Workload Identity Pool provider: `oidc`, `aws`, `saml`, `x509` | OIDC JWT, SigV4 (`aws` type), X.509 client certs (GA 2025), SAML | Nothing relevant missing | Attribute condition required for a safe provider; direct `principal://` access preferred over SA impersonation; pool ids soft-deleted 30 days |
| **Azure Entra** | Federated identity credential on an app registration or user-assigned managed identity | OIDC JWT signed RS256 only | ES-signed JWTs (untested per Microsoft), X.509, SigV4 | 20 FICs per app or identity; exact issuer/subject/audience match, no wildcards; flexible FICs in preview relax matching for GitHub, GitLab, Terraform Cloud; a managed identity can itself be a FIC (cross-tenant), preview |
| **Anthropic** | Issuer (`fdis_`) + rule (`fdrl_`) → service account (`svac_`) | OIDC JWT with asymmetric signature and `kid`; JWKS by discovery, explicit URL, or inline upload | X.509, SAML, HMAC JWTs | `jti` single-use by default; 30 s skew; token lifetime 60 s to 24 h and never more than twice the remaining life of the source JWT; rules matched by id, never searched; OAuth callers can only create `workspace:developer` and `workspace:inference` rules |
| **OpenAI** | Workload Identity Provider + service account mapping | OIDC JWT, SPIFFE JWT-SVID, X.509 client cert (beta, separate mTLS endpoint) | SigV4, SAML | 50 providers per org, 50 mappings per provider; tokens never outlive the subject token, max 1 h; no refresh token; providers and mappings are dashboard-only, no admin API; workload tokens cannot call the admin API |

## 4. The pair matrix

Rows are where the workload runs. Columns are what it wants credentials for. "Standard" is the path a new deployment should take; "legacy" works but should be flagged; "bridge" needs a hop described in section 5; "gap" has no keyless path today.

| From ↓ / To → | AWS | GCP | Azure | Anthropic | OpenAI |
|---|---|---|---|---|---|
| **AWS EC2/ECS/Lambda** (outbound federation on) | n/a | OIDC, standard | OIDC, standard | OIDC, standard | OIDC, standard |
| **AWS EC2/ECS/Lambda** (outbound federation off) | n/a | SigV4, legacy | **gap** | **gap** | **gap** |
| **AWS EKS IRSA** | role assumption, native | OIDC | OIDC | OIDC | OIDC |
| **AWS EKS Pod Identity** | native | bridge 5.1 | bridge 5.1 | bridge 5.1 | bridge 5.1 |
| **GCP GCE / GKE / Cloud Run** | OIDC (Google is a built-in IdP) | n/a | OIDC | OIDC | OIDC |
| **Azure AKS Workload Identity** | OIDC | OIDC | n/a | OIDC | OIDC |
| **Azure VM / App Service / Container Apps** (managed identity) | bridge 5.2 (documented by AWS) | bridge 5.2 (documented by Google) | native | bridge 5.2 (Anthropic guide covers IMDS) | bridge 5.2 (OpenAI guide covers managed identity) |
| **Self-managed Kubernetes** | OIDC with public discovery | OIDC with public discovery | OIDC with public discovery | OIDC; inline JWKS for private clusters | OIDC; uploaded JWKS |
| **SPIRE (any compute)** | JWT-SVID (verify current AWS behaviour) | JWT-SVID or X.509-SVID | JWT-SVID (`use: sig`) | JWT-SVID, first-class guide | JWT-SVID, first-class guide; X.509 beta |
| **GitHub Actions** | OIDC | OIDC | OIDC | OIDC | OIDC |
| **Anthropic / OpenAI** as a source | **n/a**: neither platform issues workload identities today | | | | |

Reading the matrix: the only true gaps are AWS compute in an account that has not enabled outbound federation, reaching anything that is not GCP. Every other cell is either standard OIDC or a documented bridge. The two bridges are the highest-value things cloud-auth does not do yet.

## 5. Ideas, ranked by value over effort

### 5.1 EKS Pod Identity as a federatable source via outbound federation

**Today:** cloud-auth refuses `eks-pod-identity` with `ErrNonFederatableSource`, because the Pod Identity agent vends plain IAM credentials and there is no projected token.

**Observation:** those credentials are an IAM role session. `sts:GetWebIdentityToken` is callable by any role session in an account with outbound federation enabled. The AWS source already has the OIDC mint path for EC2, ECS and Lambda; the only thing that distinguishes Pod Identity is that detection classifies it as non-federatable before trying.

**Change:** treat `eks-pod-identity` like `ecs`: federatable via OIDC when outbound federation is on, refused with the current message when STS answers `OutboundWebIdentityFederationDisabledException`. SigV4 would also work for GCP from those credentials, same as EC2.

**Why it matters:** Pod Identity is AWS's recommended replacement for IRSA. As clusters migrate, cloud-auth's "refused" cell becomes the common case rather than the exception.

**Effort:** small. One branch in detection, one matrix row, tests with a fake STS. **Risk:** the token's `sub` is the role ARN, not a Kubernetes identity, so the target trust is per role, not per service account. Document that difference; it is the same trade-off ECS already has.

### 5.2 Azure managed identity as a source, with an operator-chosen audience

**Today:** cloud-auth refuses `vm`, `app-service` and `container-apps` because an Entra access token is "a live bearer credential for whatever Azure resource was named, not an audience-pinned assertion." That is true of the default. It is not true when the operator controls the resource.

**Observation:** Google, AWS, Anthropic and OpenAI all document the same recipe: register an app in the tenant, give it an Application ID URI, request the IMDS token with `resource=<that URI>`, and the resulting JWT has `iss` = the tenant authority, `sub` = the managed identity's object id, `aud` = a value no Azure service accepts. It is a legitimate audience-pinned OIDC assertion, and the "disclosure" objection disappears because the token is useless against Azure itself.

**Change:** an `AzureManagedIdentity` source path that requires an explicit `--azure-token-resource` (the app's Application ID URI) and refuses to mint without it. Detection stays as is; only `Mint` gains a configured path. The control plane gains a helper that creates the app registration and prints the URI, or documents the two `az` commands.

**Why it matters:** this turns five refused cells into standard OIDC cells, and it is the only way Azure VMs and App Service reach the AI platforms.

**Effort:** medium. Source mint path, a flag and config key, and the audience must be enforced as required-no-default exactly like Azure targets' `scope`. **Risk:** a wrong `resource` silently produces a token for a real Azure API. Mitigate by refusing resources that look like Microsoft first-party URIs (`https://management.azure.com`, `https://graph.microsoft.com`, `https://storage.azure.com`, any `*.azure.com` / `*.microsoft.com` host).

### 5.3 SPIRE JWT-SVID as a source

**Today:** not a source. The verifier knows the runtime key but nothing mints it.

**Observation:** SPIRE gives one issuer across every cluster and VM in an organisation, with `sub` = `spiffe://trust-domain/workload`. Anthropic and OpenAI ship first-class SPIFFE guides; Entra documents it; GCP accepts it as a plain OIDC provider. Minting is one Unix-socket call to the Workload API, selecting the audience. The Go SDK is `github.com/spiffe/go-spiffe/v2`.

**Change:** a `source/spiffe.go` that detects `SPIFFE_ENDPOINT_SOCKET` and mints a JWT-SVID for the target audience. The control plane needs nothing new: the SPIRE OIDC discovery provider is the issuer, and every existing target mechanism takes an issuer URL and subject.

**Effort:** medium, one dependency. **Risk:** low; the target side is unchanged. Note Entra's `use: sig` requirement in docs.

### 5.4 Self-managed Kubernetes: publish-the-discovery helper

**Today:** cloud-auth's Kubernetes mechanism assumes the cluster's issuer is publicly resolvable. For EKS, GKE and AKS it is. For a self-managed or on-premise cluster it is not, and the operator has to either expose the API server's discovery endpoints or copy the JWKS somewhere public by hand, then keep it fresh when keys rotate.

**Idea:** a `cloud-auth publish-issuer` helper that reads the cluster's discovery document and JWKS via the API, writes them to an S3, GCS or Azure Blob static site, and prints the issuer URL to set `--service-account-issuer` to. Run it on a schedule or as a Kubernetes CronJob to track rotation. For Anthropic specifically, the `inline` JWKS mode means the helper can push keys straight into the issuer object instead.

**Effort:** medium. **Risk:** stale keys after rotation break every exchange; the helper's whole job is to make the refresh boring.

### 5.5 X.509 to GCP and OpenAI

**Today:** every path is a bearer token. X.509 gives sender-constrained identity and is the only keyless option when a workload has a certificate but no OIDC issuer (classic VMs with a corporate CA, SPIRE X.509-SVIDs).

**Idea:** an `X509` proof kind, minted from a certificate and key on disk or the SPIRE Workload API, accepted by GCP WIF `x509` providers and OpenAI's `mtls.auth.openai.com`. Everything else refuses it with `ErrNoFirstClassPath`.

**Effort:** medium to large; TLS client config per target, trust-store management on the GCP side, and OpenAI's beta may change. **Why later:** two targets, both reachable by OIDC anyway. Do it when a user has certificates and nothing else.

### 5.6 AWS outbound federation as a target-side trust in the control plane

**Today:** `setup --type gcp-wif --source aws` creates an `aws`-type (SigV4) provider when told `--provider-type aws`, and an `oidc` provider only if the operator supplies the issuer URL by hand. Nothing looks up the account's outbound issuer.

**Idea:** `--provider-type oidc --source aws` resolves the issuer with `iam:GetOutboundWebIdentityFederationInfo` and fills it in, for GCP, Azure, Anthropic and OpenAI targets alike. `audit` could flag SigV4 trusts in accounts where outbound federation is already on as "migrate now, nothing blocks you."

**Effort:** small. **Why:** it makes the standard path the default, which section 6 argues for.

### 5.7 Things deliberately not pursued

- **Anthropic or OpenAI as sources.** Neither issues workload identities. If either ships one, the model is just another OIDC issuer.
- **Token chaining** (AWS → GCP → Azure). Each hop widens the blast radius and the final target sees the wrong `sub`. Every cell above has a direct path or a one-hop bridge inside the same platform; keep it that way.
- **Vault or Aembit-style brokers as the primary design.** Useful where they already exist; cloud-auth should remain the direct, broker-less path and interoperate (it already models Vault as a trust peer).

## 6. Recommendations for cloud-auth

1. **Make OIDC the one proof everything standardizes on.** Already the default; PR #24 made SigV4 visibly legacy. Idea 5.6 closes the control-plane half.
2. **Land 5.1 and 5.2 next.** Together they remove every "refused" cell that has a vendor-documented keyless path, and they are the two platforms' recommended runtimes going forward.
3. **Then 5.3.** SPIRE is the only answer for mixed estates and both AI platforms treat it as first-class.
4. **Keep the refusals that remain honest.** AWS compute without outbound federation reaching Azure, Anthropic or OpenAI has no keyless path; the right behaviour is the current `ErrNoFirstClassPath` with the enable-outbound-federation instruction, not a workaround.
5. **Treat every bridge as a trust boundary.** 5.2 needs a refuse-list of first-party Azure audiences; 5.1 needs the "subject is the role, not the pod" caveat in the setup output.

## Sources

- AWS, Federating AWS identities to external services (outbound identity federation): https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html
- AWS, Understanding token claims: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_token_claims.html
- AWS, Getting started with outbound identity federation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html
- AWS Security Blog, access AWS resources from Microsoft Entra ID tenants using STS: https://aws.amazon.com/blogs/security/how-to-access-aws-resources-from-microsoft-entra-id-tenants-using-aws-security-token-service/
- AWS, Create a role for OIDC federation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
- Google Cloud, Configure Workload Identity Federation with AWS or Azure VMs: https://docs.cloud.google.com/iam/docs/access-resources-aws
- Google Cloud, Workload Identity Federation overview (supported providers incl. X.509): https://docs.cloud.google.com/iam/docs/workload-identity-federation
- Google Cloud, IAM release notes (X.509 GA, May 2025): https://docs.cloud.google.com/iam/docs/release-notes
- Microsoft, Workload identity federation considerations (RS256 only, 20-credential limit): https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations
- Microsoft, Federate a Google Cloud workload identity: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-google-cloud
- Microsoft, Federate a SPIFFE/SPIRE workload identity: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-spiffe-spire
- Microsoft, Configure an application to trust a managed identity: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-config-app-trust-managed-identity
- Microsoft, Flexible federated identity credentials (preview): https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials
- Anthropic, Workload Identity Federation (provider guides: AWS, Google Cloud, Entra ID, GitHub Actions, Kubernetes, SPIFFE, Okta): https://platform.claude.com/docs/en/manage-claude/workload-identity-federation
- Anthropic, WIF reference (JWT verification rules, scopes, errors): https://platform.claude.com/docs/en/manage-claude/wif-reference
- Anthropic, Manage WIF with the Admin API: https://platform.claude.com/docs/en/manage-claude/wif-admin-api
- OpenAI, Workload identity federation overview: https://developers.openai.com/api/docs/guides/workload-identity-federation
- OpenAI, Token exchange reference (JWT and X.509 endpoints, limits): https://developers.openai.com/api/reference/workload-identity-federation
- OpenAI, platform guides: AWS, Azure, Google Cloud, Kubernetes, GitHub Actions, Oracle Cloud, Idira under https://developers.openai.com/api/docs/guides/workload-identity-federation/
- SPIRE OIDC with Kubernetes and Istio, Indeed Engineering (AWS JWT-SVID validation history): https://engineering.indeedblog.com/blog/2024/07/workload-identity-with-spire-oidc-for-k8s-istio/
- Azure AD workload identity federation with SPIFFE and SPIRE (`use: sig` requirement): https://blog.identitydigest.com/azuread-federate-spiffe/
- Kubernetes service accounts for Google WIF (self-managed clusters), salrashid123: https://github.com/salrashid123/k8s_federation_with_gcp
