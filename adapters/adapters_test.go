package adapters

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// fakeSource / fakeExchanger let us test adapters without a live cloud.
type fakeSource struct{ minted int }

func (f *fakeSource) Detect(ctx context.Context) (*core.Runtime, error) {
	return &core.Runtime{Cloud: core.GCP, Federatable: true}, nil
}
func (f *fakeSource) Mint(ctx context.Context, audience string) (*core.SourceToken, error) {
	f.minted++
	return &core.SourceToken{Kind: core.OIDC, Value: "jwt", Audience: audience}, nil
}

type fakeExchanger struct {
	creds *core.Credentials
	calls int
}

func (f *fakeExchanger) Exchange(ctx context.Context, tok *core.SourceToken, target core.Target) (*core.Credentials, error) {
	f.calls++
	return f.creds, nil
}

func TestAWSAdapterRetrieveMapsAndCaches(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := core.NewFakeClock(base)
	src := &fakeSource{}
	ex := &fakeExchanger{creds: &core.Credentials{
		Cloud: core.AWS, AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st",
		Expiry: base.Add(time.Hour),
	}}
	target := core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"}

	p := NewAWS(src, ex, target, WithClock(clk))

	got, err := p.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.AccessKeyID != "AKIA" || got.SecretAccessKey != "sk" || got.SessionToken != "st" {
		t.Errorf("mapped creds = %+v", got)
	}
	if !got.CanExpire || !got.Expires.Equal(base.Add(time.Hour)) {
		t.Errorf("expiry not propagated: canExpire=%v expires=%v", got.CanExpire, got.Expires)
	}
	// Second call within TTL is cached: no extra mint/exchange.
	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ex.calls != 1 || src.minted != 1 {
		t.Errorf("expected 1 mint + 1 exchange (cached), got mint=%d exchange=%d", src.minted, ex.calls)
	}
}

// Compile-time proof the adapter satisfies the AWS SDK interface.
var _ awssdk.CredentialsProvider = (*AWSProvider)(nil)

// Each adapter must expose invalidation, or a caller holding a revoked session has no way to recover except waiting out the refresh buffer.
func TestAdaptersExposeInvalidate(t *testing.T) {
	src, ex := &fakeSource{}, &fakeExchanger{}
	target := core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"}
	type invalidator interface{ Invalidate() }
	for name, p := range map[string]invalidator{
		"aws":   NewAWS(src, ex, target),
		"gcp":   NewGCP(src, ex, target),
		"azure": NewAzure(src, ex, target),
	} {
		if p == nil {
			t.Errorf("%s adapter does not expose Invalidate", name)
			continue
		}
		p.Invalidate() // must not panic on a cold cache
	}
}
