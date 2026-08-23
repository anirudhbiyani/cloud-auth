package broker

import (
	"context"
	"errors"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
)

type fakeProvider struct {
	rt      *core.Runtime
	detErr  error
	mintErr error
}

func (f *fakeProvider) Detect(ctx context.Context) (*core.Runtime, error) {
	return f.rt, f.detErr
}
func (f *fakeProvider) Mint(ctx context.Context, aud string) (*core.SourceToken, error) {
	if f.mintErr != nil {
		return nil, f.mintErr
	}
	return &core.SourceToken{Kind: core.OIDC, Value: "jwt", Audience: aud}, nil
}

type fakeExchanger struct{ creds *core.Credentials }

func (f *fakeExchanger) Exchange(ctx context.Context, tok *core.SourceToken, tgt core.Target) (*core.Credentials, error) {
	return f.creds, nil
}

func TestExchangeDetectsMintsExchanges(t *testing.T) {
	prov := &fakeProvider{rt: &core.Runtime{Cloud: core.GCP, SubRuntime: "gke", Federatable: true}}
	want := &core.Credentials{Cloud: core.AWS, AccessKeyID: "AKIA"}

	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(core.Cloud) (core.Exchanger, error) {
			return &fakeExchanger{creds: want}, nil
		}),
	)
	target := core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"}
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
		rt:      &core.Runtime{Cloud: core.AWS, SubRuntime: "eks-pod-identity", Federatable: false},
		mintErr: core.ErrNonFederatableSource,
	}
	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(core.Cloud) (core.Exchanger, error) {
			return &fakeExchanger{creds: &core.Credentials{}}, nil
		}),
	)
	_, _, err := b.Exchange(context.Background(), core.GCPTarget{WorkloadIdentityPool: "//iam.googleapis.com/projects/1/x"})
	if !errors.Is(err, core.ErrNonFederatableSource) {
		t.Errorf("err = %v, want ErrNonFederatableSource", err)
	}
}

func TestExchangeRequiresAudience(t *testing.T) {
	prov := &fakeProvider{rt: &core.Runtime{Cloud: core.GCP, Federatable: true}}
	b := New(WithRegistry(source.NewRegistry(prov)))
	_, _, err := b.Exchange(context.Background(), core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"})
	if err == nil {
		t.Fatal("expected error when audience is empty (fail closed)")
	}
}
