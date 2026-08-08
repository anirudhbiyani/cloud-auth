package adapters

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
	"github.com/anirudhbiyani/cloud-auth/internal/cache"
)

// AWSProvider satisfies aws.CredentialsProvider so it can be passed directly to
// config.WithCredentialsProvider with no glue code.
type AWSProvider struct {
	cache *cache.Cache
}

// NewAWS builds an AWSProvider from a detected source, a target exchanger, and
// a target binding.
func NewAWS(src cloudauth.SourceProvider, ex cloudauth.Exchanger, target cloudauth.Target, opts ...Option) *AWSProvider {
	return &AWSProvider{cache: newCache(src, ex, target, resolve(opts))}
}

// Retrieve implements aws.CredentialsProvider.
func (p *AWSProvider) Retrieve(ctx context.Context) (awssdk.Credentials, error) {
	c, err := p.cache.Get(ctx)
	if err != nil {
		return awssdk.Credentials{}, err
	}
	return awssdk.Credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Source:          "cloud-auth",
		CanExpire:       !c.Expiry.IsZero(),
		Expires:         c.Expiry,
	}, nil
}
