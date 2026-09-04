package broker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
)

type fakeProvider struct {
	rt      *core.Runtime
	detErr  error
	mintErr error
	mints   int
}

func (f *fakeProvider) Detect(ctx context.Context) (*core.Runtime, error) {
	return f.rt, f.detErr
}
func (f *fakeProvider) Mint(ctx context.Context, aud string) (*core.SourceToken, error) {
	if f.mintErr != nil {
		return nil, f.mintErr
	}
	// mints counts calls so a test can assert a FRESH proof per exchange, and
	// the value carries the count so the exchanger can see they differ.
	f.mints++
	return &core.SourceToken{
		Kind: core.OIDC, Value: fmt.Sprintf("jwt-with-jti-%d", f.mints), Audience: aud,
		Expiry: time.Now().Add(time.Hour),
	}, nil
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

// The Claude Platform treats a jti-bearing identity token as single-use: each
// exchange must present a JWT that has not been exchanged before, and
// re-presenting one is refused as jti_reused.
//
// That makes "a fresh proof per exchange" a CORRECTNESS property, not an
// efficiency choice. It holds today because Exchange calls Mint every time, and
// an optimisation that cached the source token would silently break Anthropic
// while leaving AWS, GCP and Azure working — which is exactly the kind of
// regression nobody would attribute to the cache.
func TestEveryExchangeMintsAFreshProof(t *testing.T) {
	prov := &fakeProvider{rt: &core.Runtime{
		Cloud: core.AWS, SubRuntime: "eks-irsa", Federatable: true,
	}}

	var seen []string
	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(core.Cloud) (core.Exchanger, error) {
			return exchangerFunc(func(_ context.Context, tok *core.SourceToken, _ core.Target) (*core.Credentials, error) {
				seen = append(seen, tok.Reveal())
				return &core.Credentials{
					Cloud: core.AWS, AccessToken: "t", Expiry: time.Now().Add(time.Hour),
				}, nil
			}), nil
		}),
	)

	target := core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/r"}
	for range 3 {
		if _, _, err := b.Exchange(context.Background(), target); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
	}

	if prov.mints != 3 {
		t.Errorf("Mint was called %d times for 3 exchanges; a source proof must not be reused",
			prov.mints)
	}
	distinct := map[string]bool{}
	for _, v := range seen {
		distinct[v] = true
	}
	if len(distinct) != 3 {
		t.Errorf("%d distinct proofs across 3 exchanges: %v — re-presenting one is refused as "+
			"jti_reused by the Claude Platform", len(distinct), seen)
	}
}

// exchangerFunc adapts a function to core.Exchanger.
type exchangerFunc func(context.Context, *core.SourceToken, core.Target) (*core.Credentials, error)

func (f exchangerFunc) Exchange(ctx context.Context, tok *core.SourceToken, t core.Target) (*core.Credentials, error) {
	return f(ctx, tok, t)
}
