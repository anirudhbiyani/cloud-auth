# Using cloud-auth as an SDK

Everything the CLI does is a thin wrapper over exported Go packages. A workload can
embed the runtime exchange directly and hand the result to its cloud SDK; a platform
tool can drive the control plane without shelling out. This section is the map; the
pages that follow are complete, compilable programs.

```bash
go get github.com/anirudhbiyani/cloud-auth@latest
```

Module path `github.com/anirudhbiyani/cloud-auth`, Go 1.27.4 or newer. API reference on
[pkg.go.dev](https://pkg.go.dev/github.com/anirudhbiyani/cloud-auth).

## Two halves, one module

| You want to | Start with | Page |
|---|---|---|
| Get credentials for another cloud from inside a workload | `broker.New().Exchange` | [Runtime exchange](runtime.md) |
| Drop cloud-auth into an existing AWS, GCP or Azure SDK client | `adapters.NewAWS` / `NewGCP` / `NewAzure` | [Runtime exchange](runtime.md#plug-into-the-cloud-sdks) |
| Create, validate, or delete the trust itself | `core.NewManager` + a spec | [Control plane](control-plane.md) |
| Enumerate and score every federated trust in an account | `core.BuildInventory` | [Audit](audit.md) |
| Handle failures by category, log credentials safely | `core.CategoryOf`, `Credentials.Reveal` | [Errors and redaction](errors.md) |
| Add a source runtime, a target, or a provider | `core.SourceProvider`, `core.Exchanger`, `core.LifecycleProvider` | [Extending](extending.md) |
| Look up any exported function, type, or helper | generated from `go/doc` on every build | [API reference](reference/index.md) |

## Package map

| Package | Role |
|---|---|
| `core` | Types shared by everything: `Target`, `Credentials`, `MechanismSpec`, `Manager`, errors, validation, inventory. No cloud SDK imports. |
| `broker` | One call that detects the runtime, mints a proof, and exchanges it. |
| `source` | Source runtimes: AWS (EC2, ECS, Lambda, EKS IRSA; EKS Pod Identity is detected but refused as non-federatable), GCP (GCE, GKE, Cloud Run, Cloud Functions), Azure (AKS workload identity; VM, App Service and Container Apps are detected but refused), GitHub Actions. `source.Default()` is the detection registry. |
| `target` | Exchangers for AWS STS, GCP STS, Entra, Anthropic, OpenAI. `target.For(cloud)` picks one. |
| `adapters` | The exchange wrapped as `aws.CredentialsProvider`, `oauth2.TokenSource`, `azcore.TokenCredential`. |
| `provider/{aws,gcp,azure,vault,anthropic}` | Control-plane providers. Blank-import the ones you use; each registers itself. |
| `config` | The YAML federation config the CLI reads, as a library: named targets, source selector, refresh buffer. |
| `state` | A retrying mechanism-state store over any object store; S3 ships. `core` has file and in-memory stores. |

## One rule to keep in mind

Credentials and source tokens never print in plaintext. `core.Credentials` and
`core.SourceToken` implement `String`, `Format`, `LogValue` and `MarshalJSON` with
redaction. The only way to the secret bytes is an explicit `Reveal()`, which exists so
that the place you leak a credential is always greppable.
