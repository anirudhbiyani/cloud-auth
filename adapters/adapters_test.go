package adapters

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// fakeSource / fakeExchanger let us test adapters without a live cloud.
type fakeSource struct{ minted int }

func (f *fakeSource) Detect(ctx context.Context) (*cloudauth.Runtime, error) {
	return &cloudauth.Runtime{Cloud: cloudauth.GCP, Federatable: true}, nil
}
func (f *fakeSource) Mint(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	f.minted++
	return &cloudauth.SourceToken{Kind: cloudauth.OIDC, Value: "jwt", Audience: audience}, nil
}

type fakeExchanger struct {
	creds *cloudauth.Credentials
	calls int
}

func (f *fakeExchanger) Exchange(ctx context.Context, tok *cloudauth.SourceToken, target cloudauth.Target) (*cloudauth.Credentials, error) {
	f.calls++
	return f.creds, nil
}

func TestAWSAdapterRetrieveMapsAndCaches(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	clk := cloudauth.NewFakeClock(base)
	src := &fakeSource{}
	ex := &fakeExchanger{creds: &cloudauth.Credentials{
		Cloud: cloudauth.AWS, AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st",
		Expiry: base.Add(time.Hour),
	}}
	target := cloudauth.Target{Cloud: cloudauth.AWS, Role: "arn:...:role/r", Audience: "sts.amazonaws.com"}

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
