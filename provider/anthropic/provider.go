package anthropic

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Provider manages Claude Platform federation rules.
type Provider struct {
	client *Client
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithClient injects the Admin API client.
func WithClient(c *Client) ProviderOption { return func(p *Provider) { p.client = c } }

// New builds the provider; the client defaults to one reading ANTHROPIC_AUTH_TOKEN.
func New(opts ...ProviderOption) *Provider {
	p := &Provider{}
	for _, o := range opts {
		o(p)
	}
	if p.client == nil {
		p.client = NewClient()
	}
	return p
}

// Name implements core.Provider.
func (p *Provider) Name() core.Cloud { return core.Anthropic }

// Capabilities implements core.Provider.
func (p *Provider) Capabilities() []core.Capability {
	return []core.Capability{core.CapabilitySetup, core.CapabilityValidate, core.CapabilityDelete, core.CapabilityDryRun, core.CapabilityFederationOIDC}
}

// HasCapability implements core.Provider.
func (p *Provider) HasCapability(c core.Capability) bool {
	for _, have := range p.Capabilities() {
		if have == c {
			return true
		}
	}
	return false
}

func (p *Provider) requireClient() error {
	if !p.client.HasToken() {
		return core.ErrValidation("Anthropic Admin API token not configured: export ANTHROPIC_AUTH_TOKEN " +
			"from `ant auth login --profile admin --scope org:admin`; Admin API keys are not accepted on " +
			"the federation endpoints, and --dry-run needs no token").WithProvider(core.Anthropic)
	}
	return nil
}

// ResourceIDs keys. The match facts are stored too, so validate can diff the live rule without the spec.
const (
	keyRule          = "federation_rule_id"
	keyIssuer        = "issuer_id"
	keySA            = "service_account_id"
	keyOrg           = "organization_id"
	keyWorkspace     = "workspace_id"
	keyIssuerURL     = "issuer_url"
	keySubjectPrefix = "subject_prefix"
	keyAudience      = "audience"
	keyCreatedIssuer = "created_issuer"
	keyCreatedSA     = "created_service_account"
)

// Setup implements core.LifecycleProvider.
func (p *Provider) Setup(ctx context.Context, in core.MechanismSpec, opts core.SetupOptions) (*core.Outputs, error) {
	spec, ok := in.(*core.AnthropicFederationSpec)
	if !ok {
		return nil, core.ErrValidation(fmt.Sprintf("anthropic: expected *AnthropicFederationSpec, got %T", in))
	}
	if opts.DryRun {
		// The CLI prints Values["plan"] for a dry run, as the cloud providers do.
		return &core.Outputs{
			Ref: core.MechanismRef{Type: spec.Type(), Provider: core.Anthropic, ResourceIDs: map[string]string{}},
			Values: map[string]string{"plan": fmt.Sprintf(
				"Would reuse or create service account %q, register issuer %s, and create rule %q (scope %s) in organization %s",
				spec.ServiceAccountName, spec.IssuerURL, spec.RuleName, scopeOf(spec), spec.OrganizationID)},
		}, nil
	}
	if err := p.requireClient(); err != nil {
		return nil, err
	}

	var cleanup []func() error
	rollback := func(cause error) error {
		rb := &core.RollbackError{OriginalError: cause}
		for i := len(cleanup) - 1; i >= 0; i-- {
			if err := cleanup[i](); err != nil {
				rb.RollbackErrors = append(rb.RollbackErrors, err)
			}
		}
		return rb
	}

	// 1. Service account: by id, by name, or new.
	sa, createdSA, err := p.ensureServiceAccount(ctx, spec)
	if err != nil {
		return nil, err
	}
	if createdSA {
		cleanup = append(cleanup, func() error { return p.client.ArchiveServiceAccount(ctx, sa.ID) })
	}

	// 2. Issuer: by URL, or new.
	issuer, createdIssuer, err := p.ensureIssuer(ctx, spec)
	if err != nil {
		return nil, rollback(err)
	}
	if createdIssuer {
		cleanup = append(cleanup, func() error { return p.client.ArchiveIssuer(ctx, issuer.ID) })
	}

	// 3. Rule: by name under this issuer, or new. Names are unique per organization, so a same-named rule on another issuer is a conflict, not a reuse.
	rules, err := p.client.ListRules(ctx, "")
	if err != nil {
		return nil, rollback(err)
	}
	var rule *Rule
	for i := range rules {
		if rules[i].Name == spec.RuleName && rules[i].ArchivedAt == nil {
			rule = &rules[i]
		}
	}
	createdRule := false
	switch {
	case rule == nil:
		created, err := p.client.CreateRule(ctx, Rule{
			Name:        spec.RuleName,
			IssuerID:    issuer.ID,
			Match:       RuleMatch{SubjectPrefix: spec.SubjectPrefix, Audience: spec.Audience, Claims: spec.Claims, Condition: spec.Condition},
			Target:      RuleTarget{Type: "service_account", ServiceAccountID: sa.ID},
			WorkspaceID: spec.WorkspaceID, AppliesToAllWorkspaces: spec.AppliesToAllWorkspaces,
			OAuthScope: scopeOf(spec), TokenLifetimeSeconds: spec.TokenLifetimeSeconds,
		})
		if err != nil {
			return nil, rollback(err)
		}
		rule, createdRule = created, true
	case rule.IssuerID != issuer.ID || rule.Target.ServiceAccountID != sa.ID:
		return nil, rollback(core.ErrValidation(fmt.Sprintf("federation rule %q already exists as %s but binds issuer %s to %s, "+
			"not %s to %s; pick another rule_name or archive it", spec.RuleName, rule.ID, rule.IssuerID,
			rule.Target.ServiceAccountID, issuer.ID, sa.ID)).WithProvider(core.Anthropic))
	}

	ref := core.MechanismRef{
		ID: "anthropic-" + spec.RuleName, Type: spec.Type(), Provider: core.Anthropic, Owned: createdRule,
		ResourceIDs: map[string]string{
			keyRule: rule.ID, keyIssuer: issuer.ID, keySA: sa.ID, keyOrg: spec.OrganizationID,
			keyWorkspace: spec.WorkspaceID, keyIssuerURL: spec.IssuerURL,
			keySubjectPrefix: spec.SubjectPrefix, keyAudience: spec.Audience,
			keyCreatedIssuer: fmt.Sprint(createdIssuer), keyCreatedSA: fmt.Sprint(createdSA),
		},
	}
	return &core.Outputs{
		Ref: ref,
		Values: map[string]string{
			"ANTHROPIC_FEDERATION_RULE_ID": rule.ID, "ANTHROPIC_ORGANIZATION_ID": spec.OrganizationID,
			"ANTHROPIC_SERVICE_ACCOUNT_ID": sa.ID, "ANTHROPIC_WORKSPACE_ID": spec.WorkspaceID,
		},
		Instructions: []string{fmt.Sprintf(
			"cloud-auth exec --to anthropic --federation-rule %s --organization %s --service-account-id %s%s --audience %s -- your-program",
			rule.ID, spec.OrganizationID, sa.ID, optFlag(" --workspace ", spec.WorkspaceID), spec.Audience)},
	}, nil
}

func (p *Provider) ensureServiceAccount(ctx context.Context, spec *core.AnthropicFederationSpec) (*ServiceAccount, bool, error) {
	if spec.ServiceAccountID != "" {
		sa, err := p.client.GetServiceAccount(ctx, spec.ServiceAccountID)
		if err != nil {
			return nil, false, err
		}
		if sa.ArchivedAt != nil {
			return nil, false, core.ErrValidation(fmt.Sprintf("service account %s is archived", sa.ID))
		}
		return sa, false, nil
	}
	existing, err := p.client.ListServiceAccounts(ctx)
	if err != nil {
		return nil, false, err
	}
	for i := range existing {
		if existing[i].Name == spec.ServiceAccountName && existing[i].ArchivedAt == nil {
			return &existing[i], false, nil
		}
	}
	sa, err := p.client.CreateServiceAccount(ctx, spec.ServiceAccountName)
	return sa, err == nil, err
}

func (p *Provider) ensureIssuer(ctx context.Context, spec *core.AnthropicFederationSpec) (*Issuer, bool, error) {
	existing, err := p.client.ListIssuers(ctx)
	if err != nil {
		return nil, false, err
	}
	for i := range existing {
		if existing[i].IssuerURL == spec.IssuerURL && existing[i].ArchivedAt == nil {
			return &existing[i], false, nil
		}
	}
	jwks := map[string]any{"type": "discovery"}
	if spec.JWKSURL != "" {
		jwks = map[string]any{"type": "explicit_url", "url": spec.JWKSURL}
	}
	name := spec.IssuerName
	if name == "" {
		name = issuerSlug(spec.IssuerURL)
	}
	issuer, err := p.client.CreateIssuer(ctx, name, spec.IssuerURL, jwks)
	return issuer, err == nil, err
}

// issuerSlug derives a ^[a-z0-9-]+$ name from an issuer URL: token.actions.githubusercontent.com -> token-actions-githubusercontent-com.
func issuerSlug(issuerURL string) string {
	u, err := url.Parse(issuerURL)
	host := issuerURL
	if err == nil && u.Host != "" {
		host = u.Host + u.Path
	}
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 255 {
		s = s[:255]
	}
	return s
}

func scopeOf(s *core.AnthropicFederationSpec) string {
	if s.OAuthScope == "" {
		return "workspace:developer"
	}
	return s.OAuthScope
}

func optFlag(flag, v string) string {
	if v == "" {
		return ""
	}
	return flag + v
}

// Validate implements core.LifecycleProvider.
func (p *Provider) Validate(ctx context.Context, ref core.MechanismRef, _ core.ValidateOptions) (*core.ValidationReport, error) {
	if err := p.requireClient(); err != nil {
		return nil, err
	}
	ids := ref.ResourceIDs
	checks := []core.Validator{
		&check{id: "anthropic.rule.live", name: "Federation rule exists and is live", desc: "The rule is readable and not archived, and binds the recorded issuer to the recorded service account.",
			run: func(ctx context.Context) (string, error) {
				r, err := p.client.GetRule(ctx, ids[keyRule])
				if err != nil {
					return "", err
				}
				if r.ArchivedAt != nil {
					return "", fmt.Errorf("rule %s is archived", r.ID)
				}
				if r.IssuerID != ids[keyIssuer] || r.Target.ServiceAccountID != ids[keySA] {
					return "", fmt.Errorf("rule binds issuer %s to %s; cloud-auth recorded %s to %s", r.IssuerID, r.Target.ServiceAccountID, ids[keyIssuer], ids[keySA])
				}
				if ids[keySubjectPrefix] != "" && r.Match.SubjectPrefix != ids[keySubjectPrefix] {
					return "", fmt.Errorf("subject_prefix is %q, cloud-auth set %q: the rule was edited", r.Match.SubjectPrefix, ids[keySubjectPrefix])
				}
				if ids[keyAudience] != "" && r.Match.Audience != ids[keyAudience] {
					return "", fmt.Errorf("audience is %q, cloud-auth set %q", r.Match.Audience, ids[keyAudience])
				}
				return "rule " + r.ID + " live, scope " + r.OAuthScope, nil
			}},
		&check{id: "anthropic.issuer.live", name: "Issuer registration is live", desc: "The issuer is not archived and still names the recorded issuer URL.",
			run: func(ctx context.Context) (string, error) {
				is, err := p.client.GetIssuer(ctx, ids[keyIssuer])
				if err != nil {
					return "", err
				}
				if is.ArchivedAt != nil {
					return "", fmt.Errorf("issuer %s is archived", is.ID)
				}
				if is.IssuerURL != ids[keyIssuerURL] {
					return "", fmt.Errorf("issuer URL is %s, cloud-auth recorded %s", is.IssuerURL, ids[keyIssuerURL])
				}
				return "issuer " + is.IssuerURL, nil
			}},
		&check{id: "anthropic.service_account.live", name: "Service account is live", desc: "The target service account is not archived.",
			run: func(ctx context.Context) (string, error) {
				sa, err := p.client.GetServiceAccount(ctx, ids[keySA])
				if err != nil {
					return "", err
				}
				if sa.ArchivedAt != nil {
					return "", fmt.Errorf("service account %s is archived", sa.ID)
				}
				return sa.Name + " (" + sa.OrganizationRole + ")", nil
			}},
	}
	return core.RunValidation(ctx, ref, checks), nil
}

// check is the one validator shape this provider needs.
type check struct {
	id, name, desc string
	run            func(ctx context.Context) (string, error)
}

func (c *check) ID() string          { return c.id }
func (c *check) Name() string        { return c.name }
func (c *check) Description() string { return c.desc }
func (c *check) Validate(ctx context.Context, _ core.MechanismRef) core.ValidationCheck {
	out := core.NewCheck(c, core.SeverityCritical)
	msg, err := c.run(ctx)
	if err != nil {
		out.Status, out.Message = core.CheckStatusFailed, err.Error()
		out.Remediation = "Re-run `cloud-auth setup -f` to recreate the trust, or archive and re-create it in the Claude Console."
		return out
	}
	out.Status, out.Message = core.CheckStatusPassed, msg
	return out
}

// Delete implements core.LifecycleProvider: archive the rule, then the issuer and service account if this tool created them.
func (p *Provider) Delete(ctx context.Context, ref core.MechanismRef, opts core.DeleteOptions) error {
	if opts.DryRun {
		return nil
	}
	if err := p.requireClient(); err != nil {
		return err
	}
	ids := ref.ResourceIDs
	if opts.OwnedOnly && !ref.Owned && !opts.Force {
		return core.ErrPermission(fmt.Sprintf("rule %s was not created by cloud-auth; pass --force to archive it anyway", ids[keyRule]))
	}
	if err := p.client.ArchiveRule(ctx, ids[keyRule]); err != nil {
		return fmt.Errorf("archiving rule: %w", err)
	}
	// Archiving an issuer or service account another live rule still uses answers 400; that is "shared, kept", not a failure.
	if ids[keyCreatedIssuer] == "true" {
		if err := p.client.ArchiveIssuer(ctx, ids[keyIssuer]); err != nil && !stillReferenced(err) {
			return fmt.Errorf("archiving issuer: %w", err)
		}
	}
	if ids[keyCreatedSA] == "true" {
		if err := p.client.ArchiveServiceAccount(ctx, ids[keySA]); err != nil && !stillReferenced(err) {
			return fmt.Errorf("archiving service account: %w", err)
		}
	}
	return nil
}

func stillReferenced(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusBadRequest
}

func init() {
	if err := core.Register(New()); err != nil {
		panic(err)
	}
}
