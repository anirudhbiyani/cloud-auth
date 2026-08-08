package broker

import (
	"context"
	"errors"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/source"
)

type fakeProvider struct {
	rt      *cloudauth.Runtime
	detErr  error
	mintErr error
}

func (f *fakeProvider) Detect(ctx context.Context) (*cloudauth.Runtime, error) {
	return f.rt, f.detErr
}
func (f *fakeProvider) Mint(ctx context.Context, aud string) (*cloudauth.SourceToken, error) {
	if f.mintErr != nil {
		return nil, f.mintErr
	}
	return &cloudauth.SourceToken{Kind: cloudauth.OIDC, Value: "jwt", Audience: aud}, nil
}

type fakeExchanger struct{ creds *cloudauth.Credentials }

func (f *fakeExchanger) Exchange(ctx context.Context, tok *cloudauth.SourceToken, tgt cloudauth.Target) (*cloudauth.Credentials, error) {
	return f.creds, nil
}

func TestExchangeDetectsMintsExchanges(t *testing.T) {
	prov := &fakeProvider{rt: &cloudauth.Runtime{Cloud: cloudauth.GCP, SubRuntime: "gke", Federatable: true}}
	want := &cloudauth.Credentials{Cloud: cloudauth.AWS, AccessKeyID: "AKIA"}

	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(cloudauth.Cloud) (cloudauth.Exchanger, error) {
			return &fakeExchanger{creds: want}, nil
		}),
	)
	target := cloudauth.Target{Cloud: cloudauth.AWS, Role: "arn:...:role/r", Audience: "sts.amazonaws.com"}
	creds, rt, err := b.Exchange(context.Background(), target)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if creds.AccessKeyID != "AKIA" {
		t.Errorf("creds = %+v", creds)
	}
	if rt.SubRuntime != "gke" {
		t.Errorf("runtime = %+v", rt)
	}
}

func TestExchangeRejectsNonFederatableSource(t *testing.T) {
	// A detected but non-federatable source must fail before any exchange.
	prov := &fakeProvider{
		rt:      &cloudauth.Runtime{Cloud: cloudauth.AWS, SubRuntime: "eks-pod-identity", Federatable: false},
		mintErr: cloudauth.ErrNonFederatableSource,
	}
	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(cloudauth.Cloud) (cloudauth.Exchanger, error) {
			return &fakeExchanger{creds: &cloudauth.Credentials{}}, nil
		}),
	)
	_, _, err := b.Exchange(context.Background(), cloudauth.Target{Cloud: cloudauth.GCP, Audience: "x"})
	if !errors.Is(err, cloudauth.ErrNonFederatableSource) {
		t.Errorf("err = %v, want ErrNonFederatableSource", err)
	}
}

func TestExchangeRequiresAudience(t *testing.T) {
	prov := &fakeProvider{rt: &cloudauth.Runtime{Cloud: cloudauth.GCP, Federatable: true}}
	b := New(WithRegistry(source.NewRegistry(prov)))
	_, _, err := b.Exchange(context.Background(), cloudauth.Target{Cloud: cloudauth.AWS, Role: "r"})
	if err == nil {
		t.Fatal("expected error when audience is empty (fail closed)")
	}
}
