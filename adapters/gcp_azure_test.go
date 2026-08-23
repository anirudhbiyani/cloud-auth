package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/oauth2"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestGCPAdapterTokenSource(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	ex := &fakeExchanger{creds: &core.Credentials{Cloud: core.GCP, AccessToken: "gcp-tok", Expiry: base.Add(time.Hour)}}
	target := core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x"}

	p := NewGCP(&fakeSource{}, ex, target, WithClock(core.NewFakeClock(base)))
	tok, err := p.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "gcp-tok" {
		t.Errorf("access token = %q", tok.AccessToken)
	}
	if !tok.Expiry.Equal(base.Add(time.Hour)) {
		t.Errorf("expiry = %v", tok.Expiry)
	}
}

func TestAzureAdapterGetToken(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	ex := &fakeExchanger{creds: &core.Credentials{Cloud: core.Azure, AccessToken: "entra-tok", Expiry: base.Add(time.Hour)}}
	target := core.AzureTarget{
		Tenant:   "11111111-1111-1111-1111-111111111111",
		ClientID: "22222222-2222-2222-2222-222222222222",
		Scope:    "https://storage.azure.com/.default",
	}

	p := NewAzure(&fakeSource{}, ex, target, WithClock(core.NewFakeClock(base)))
	at, err := p.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}})
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if at.Token != "entra-tok" {
		t.Errorf("token = %q", at.Token)
	}
	if !at.ExpiresOn.Equal(base.Add(time.Hour)) {
		t.Errorf("expiresOn = %v", at.ExpiresOn)
	}
}

var (
	_ oauth2.TokenSource     = (*GCPProvider)(nil)
	_ azcore.TokenCredential = (*AzureProvider)(nil)
)
