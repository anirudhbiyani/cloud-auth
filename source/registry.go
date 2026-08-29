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
			continue
		}
		return nil, nil, err
	}
	if !r.selector.IsAuto() {
		return nil, nil, fmt.Errorf("%w: source.detect requires %s, but no runtime was detected "+
			"at all", core.ErrRuntimeMismatch, r.selector)
	}
	return nil, nil, fmt.Errorf("cloud-auth/source: no supported runtime detected")
}

// Default returns the standard registry, probed in the documented order:
// AWS, then GCP, then Azure.
func Default() *Registry {
	return NewRegistry(NewAWS(), NewGCP(), NewAzure())
}

// DefaultRestricted is Default pinned to sel.
func DefaultRestricted(sel core.Selector) *Registry { return Default().Restrict(sel) }
