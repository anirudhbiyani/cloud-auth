// Package source contains the Source Identity Providers: per-cloud detectors and
// proof minters. A Registry probes providers in a fixed order so detection is
// deterministic and testable.
package source

import (
	"context"
	"errors"
	"fmt"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Registry probes an ordered set of SourceProviders to resolve the runtime.
type Registry struct {
	providers []core.SourceProvider
	selector  core.Selector
}

// NewRegistry returns a Registry that probes providers in the given order.
func NewRegistry(providers ...core.SourceProvider) *Registry {
	return &Registry{providers: providers}
}

// Restrict pins which runtime this registry is willing to resolve, and returns
// the registry so it can be chained onto a constructor.
//
// This is what makes the config's `source.detect` mean something. Without it the
// field was parsed, validated and ignored — an operator pinning their identity
// source had configured nothing, while believing they had constrained which
// identity the workload could use.
func (r *Registry) Restrict(sel core.Selector) *Registry {
	r.selector = sel
	return r
}

// Detect probes each provider in order and returns the first that matches,
// along with its resolved Runtime. A provider signals "not me" with
// core.ErrNotThisRuntime; any other error is propagated immediately (a
// misbehaving metadata server must not be mistaken for "not this runtime").
func (r *Registry) Detect(ctx context.Context) (core.SourceProvider, *core.Runtime, error) {
	// The first "recognised, but switched off" reason seen, kept so it can be
	// reported instead of the generic answer when nothing detects.
	var notConfigured error

	for _, p := range r.providers {
		rt, err := p.Detect(ctx)
		if err == nil {
			// Check the restriction AFTER a successful probe rather than skipping
			// providers up front: a mismatch is worth reporting precisely, and
			// "you are on AWS but configured GCP" is a far more useful message
			// than "no supported runtime detected".
			if mErr := r.selector.Match(rt); mErr != nil {
				return nil, rt, mErr
			}
			return p, rt, nil
		}
		if errors.Is(err, core.ErrNotThisRuntime) {
			// "You are on this platform and it is switched off" is a far more
			// useful answer than "no supported runtime detected", and it was
			// being discarded — every provider's reason looked alike to this
			// loop. Probing continues, because the same host may legitimately
			// have another identity, but the reason survives.
			if errors.Is(err, core.ErrRuntimeNotConfigured) && notConfigured == nil {
				notConfigured = err
			}
			continue
		}
		return nil, nil, err
	}
	if !r.selector.IsAuto() {
		return nil, nil, fmt.Errorf("%w: source.detect requires %s, but no runtime was detected "+
			"at all", core.ErrRuntimeMismatch, r.selector)
	}
	if notConfigured != nil {
		return nil, nil, notConfigured
	}
	return nil, nil, fmt.Errorf("cloud-auth/source: no supported runtime detected")
}

// Default returns the standard registry, probed in the documented order:
// GitHub Actions, then AWS, then GCP, then Azure.
//
// GitHub goes FIRST, and the order is not arbitrary. Its detection is two
// environment variable reads — cheap, unambiguous, and impossible to satisfy
// accidentally — whereas the cloud probes reach for a metadata endpoint. On a
// hosted runner, which is a virtual machine in somebody's cloud, probing IMDS
// first spends a timeout on every single exchange before reaching the answer
// that was in the environment all along.
func Default() *Registry {
	return NewRegistry(NewGitHub(), NewAWS(), NewGCP(), NewAzure())
}

// DefaultRestricted is Default pinned to sel.
func DefaultRestricted(sel core.Selector) *Registry { return Default().Restrict(sel) }
