package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/oauth2"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestGCPAdapterTokenSource(t *testing.T) {
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	ex := &fakeExchanger{creds: &cloudauth.Credentials{Cloud: cloudauth.GCP, AccessToken: "gcp-tok", Expiry: base.Add(time.Hour)}}
	target := cloudauth.Target{Cloud: cloudauth.GCP, Audience: "//iam..."}

	p := NewGCP(&fakeSource{}, ex, target, WithClock(cloudauth.NewFakeClock(base)))
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
	ex := &fakeExchanger{creds: &cloudauth.Credentials{Cloud: cloudauth.Azure, AccessToken: "entra-tok", Expiry: base.Add(time.Hour)}}
	target := cloudauth.Target{Cloud: cloudauth.Azure, Tenant: "t", ClientID: "c", Audience: "api://AzureADTokenExchange"}

	p := NewAzure(&fakeSource{}, ex, target, WithClock(cloudauth.NewFakeClock(base)))
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
