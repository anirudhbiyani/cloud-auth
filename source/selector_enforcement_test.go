package source

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

type fixedRuntime struct{ rt *core.Runtime }

func (f fixedRuntime) Detect(context.Context) (*core.Runtime, error) {
	if f.rt == nil {
		return nil, core.ErrNotThisRuntime
	}
	return f.rt, nil
}
func (f fixedRuntime) Mint(context.Context, string) (*core.SourceToken, error) {
	return &core.SourceToken{Kind: core.OIDC}, nil
}

// The point of the whole feature: a host that satisfies a probe the operator did
// not authorise must fail, not silently authenticate as that identity.
func TestRestrictedRegistryRefusesTheWrongRuntime(t *testing.T) {
	onAWS := NewRegistry(fixedRuntime{&core.Runtime{Cloud: core.AWS, SubRuntime: "ec2"}})

	// Unrestricted: detection succeeds.
	if _, rt, err := onAWS.Detect(context.Background()); err != nil || rt.Cloud != core.AWS {
		t.Fatalf("unrestricted detect should succeed: rt=%v err=%v", rt, err)
	}

	// Pinned to GCP: the AWS identity must be refused.
	pinned := NewRegistry(fixedRuntime{&core.Runtime{Cloud: core.AWS, SubRuntime: "ec2"}}).
		Restrict(core.Selector{Cloud: core.GCP})
	_, rt, err := pinned.Detect(context.Background())
	if !errors.Is(err, core.ErrRuntimeMismatch) {
		t.Fatalf("want ErrRuntimeMismatch, got %v", err)
	}
	// The detected runtime is still reported, so doctor can explain the mismatch.
	if rt == nil || rt.Cloud != core.AWS {
		t.Errorf("the detected runtime should be returned alongside the error, got %v", rt)
	}
}

// Pinning a sub-runtime distinguishes two identities on the same cloud — an EKS
// pod's projected token versus the node's instance profile, for instance.
func TestRestrictedRegistryChecksTheSubRuntime(t *testing.T) {
	reg := NewRegistry(fixedRuntime{&core.Runtime{Cloud: core.AWS, SubRuntime: "ec2"}}).
		Restrict(core.Selector{Cloud: core.AWS, SubRuntime: "eks-irsa"})

	if _, _, err := reg.Detect(context.Background()); !errors.Is(err, core.ErrRuntimeMismatch) {
		t.Fatalf("want ErrRuntimeMismatch for the wrong sub-runtime, got %v", err)
	}
}

// A restriction with nothing detected must say what was required, not just
// "no supported runtime".
func TestRestrictedRegistryExplainsWhenNothingDetected(t *testing.T) {
	reg := NewRegistry(fixedRuntime{nil}).Restrict(core.Selector{Cloud: core.GCP, SubRuntime: "gke"})
	_, _, err := reg.Detect(context.Background())
	if !errors.Is(err, core.ErrRuntimeMismatch) {
		t.Fatalf("want ErrRuntimeMismatch, got %v", err)
	}
	if want := "gcp-gke"; !strings.Contains(err.Error(), want) {
		t.Errorf("error should name the requirement %q: %v", want, err)
	}
}
