package adapters

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// AWSProvider satisfies aws.CredentialsProvider so it can be passed directly to config.WithCredentialsProvider with no glue code.
type AWSProvider struct {
	cache *cache.Cache
}

// NewAWS builds an AWSProvider from a detected source, a target exchanger, and a target binding.
func NewAWS(src core.SourceProvider, ex core.Exchanger, target core.Target, opts ...Option) *AWSProvider {
	return &AWSProvider{cache: newCache(src, ex, target, resolve(opts))}
}

// Retrieve implements aws.CredentialsProvider.
func (p *AWSProvider) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	c, err := p.cache.Get(ctx)
	if err != nil {
		return awssdk.Credentials{}, err
	}
	// Handing plaintext to the AWS SDK is the adapter's purpose.
	plain := c.Reveal()
	return awssdk.Credentials{
		AccessKeyID:     plain.AccessKeyID,
		SecretAccessKey: plain.SecretAccessKey,
		SessionToken:    plain.SessionToken,
		Source:          "cloud-auth",
		// Always expiring.
		CanExpire: true,
		Expires:   c.Expiry,
	}, nil
}

// Invalidate discards the cached credentials so the next call re-exchanges.
func (p *AWSProvider) Invalidate() { p.cache.Invalidate() }
