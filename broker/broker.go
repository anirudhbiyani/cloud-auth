// Package broker orchestrates a single cross-cloud exchange: detect the local
// runtime, mint an audience-pinned source proof, and exchange it at the target
// STS. It is the shared core behind `cloud-auth exchange`, `cloud-auth doctor`, and the
// SDK adapters.
package broker

import (
	"context"
	"fmt"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/source"
	"github.com/anirudhbiyani/cloud-auth/target"
)

// Broker performs detect→mint→exchange.
type Broker struct {
	registry     *source.Registry
	exchangerFor func(cloudauth.Cloud) (cloudauth.Exchanger, error)
}

// Option configures a Broker.
type Option func(*Broker)

// WithRegistry overrides the source-detection registry.
func WithRegistry(r *source.Registry) Option { return func(b *Broker) { b.registry = r } }

// WithExchangerFor overrides how target exchangers are resolved.
func WithExchangerFor(f func(cloudauth.Cloud) (cloudauth.Exchanger, error)) Option {
	return func(b *Broker) { b.exchangerFor = f }
}

// New builds a Broker with the default registry (AWS→GCP→Azure) and the default
// exchanger dispatcher.
func New(opts ...Option) *Broker {
	b := &Broker{registry: source.Default(), exchangerFor: target.For}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Exchange detects the runtime, mints a proof pinned to target.Audience, and
// exchanges it. It fails closed when the audience is missing. It returns the
// detected Runtime alongside the credentials for diagnostics.
func (b *Broker) Exchange(ctx context.Context, target cloudauth.Target) (*cloudauth.Credentials, *cloudauth.Runtime, error) {
	if target.Audience == "" {
		return nil, nil, fmt.Errorf("cloud-auth: target audience is required and must be pinned per target")
	}
	prov, rt, err := b.registry.Detect(ctx)
	if err != nil {
		return nil, nil, err
	}
	ex, err := b.exchangerFor(target.Cloud)
	if err != nil {
		return nil, rt, err
	}
	tok, err := prov.Mint(ctx, target.Audience)
	if err != nil {
		return nil, rt, err
	}
	creds, err := ex.Exchange(ctx, tok, target)
	if err != nil {
		return nil, rt, err
	}
	return creds, rt, nil
}
