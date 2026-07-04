package source

import (
	"context"
	"errors"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// fakeProvider records detection order and returns a canned result.
type fakeProvider struct {
	name    string
	runtime *cloudauth.Runtime
	err     error
	order   *[]string
}

func (f *fakeProvider) Detect(ctx context.Context) (*cloudauth.Runtime, error) {
	*f.order = append(*f.order, f.name)
	if f.err != nil {
		return nil, f.err
	}
	return f.runtime, nil
}

func (f *fakeProvider) Mint(ctx context.Context, audience string) (*cloudauth.SourceToken, error) {
	return &cloudauth.SourceToken{Audience: audience}, nil
}

func TestRegistryDetectReturnsFirstMatchInOrder(t *testing.T) {
	var order []string
	notHere := func(name string) *fakeProvider {
		return &fakeProvider{name: name, err: cloudauth.ErrNotThisRuntime, order: &order}
	}
	match := &fakeProvider{
		name:    "gcp",
		runtime: &cloudauth.Runtime{Cloud: cloudauth.GCP, SubRuntime: "gke", Federatable: true},
		order:   &order,
	}

	reg := NewRegistry(notHere("aws"), match, notHere("azure"))
	prov, rt, err := reg.Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Cloud != cloudauth.GCP {
		t.Errorf("detected cloud = %v, want gcp", rt.Cloud)
	}
	if prov != match {
		t.Error("Detect returned a different provider than the one that matched")
	}
	// aws probed before the gcp match; azure never probed (short-circuit).
	want := []string{"aws", "gcp"}
	if len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Errorf("probe order = %v, want %v (must stop at first match)", order, want)
	}
}

func TestRegistryDetectNoMatch(t *testing.T) {
	var order []string
	reg := NewRegistry(
		&fakeProvider{name: "aws", err: cloudauth.ErrNotThisRuntime, order: &order},
		&fakeProvider{name: "gcp", err: cloudauth.ErrNotThisRuntime, order: &order},
	)
	_, _, err := reg.Detect(context.Background())
	if err == nil {
		t.Fatal("expected error when no provider matches")
	}
}

func TestRegistryDetectPropagatesRealError(t *testing.T) {
	// A non-ErrNotThisRuntime error (e.g. metadata server misbehaving) must
	// not be swallowed as "not this runtime".
	var order []string
	boom := errors.New("metadata server on fire")
	reg := NewRegistry(&fakeProvider{name: "aws", err: boom, order: &order})
	_, _, err := reg.Detect(context.Background())
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want it to wrap %v", err, boom)
	}
}
