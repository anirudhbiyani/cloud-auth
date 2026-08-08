// Package source contains the Source Identity Providers: per-cloud detectors and
// proof minters. A Registry probes providers in a fixed order so detection is
// deterministic and testable.
package source

import (
	"context"
	"errors"
	"fmt"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// Registry probes an ordered set of SourceProviders to resolve the runtime.
type Registry struct {
	providers []cloudauth.SourceProvider
}

// NewRegistry returns a Registry that probes providers in the given order.
func NewRegistry(providers ...cloudauth.SourceProvider) *Registry {
	return &Registry{providers: providers}
}

// Detect probes each provider in order and returns the first that matches,
// along with its resolved Runtime. A provider signals "not me" with
// cloudauth.ErrNotThisRuntime; any other error is propagated immediately (a
// misbehaving metadata server must not be mistaken for "not this runtime").
func (r *Registry) Detect(ctx context.Context) (cloudauth.SourceProvider, *cloudauth.Runtime, error) {
	for _, p := range r.providers {
		rt, err := p.Detect(ctx)
		if err == nil {
			return p, rt, nil
		}
		if errors.Is(err, cloudauth.ErrNotThisRuntime) {
			continue
		}
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("cloud-auth/source: no supported runtime detected")
}

// Default returns the standard registry, probed in the documented order:
// AWS, then GCP, then Azure.
func Default() *Registry {
	return NewRegistry(NewAWS(), NewGCP(), NewAzure())
}
