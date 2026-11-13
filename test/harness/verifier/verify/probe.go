package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// Probe names used in targets.json.
const (
	// ProbeSTSGetCallerIdentity proves AWS credentials work by calling sts:GetCallerIdentity with them and reporting the resolved ARN.
	ProbeSTSGetCallerIdentity = "sts-get-caller-identity"
	// ProbeGCSGetObject proves a GCP token works by reading the harness probe object from target.bucket.
	ProbeGCSGetObject = "gcs-get-object"
	// ProbeAnthropicListModels and ProbeOpenAIListModels prove a minted token works by listing models.
	ProbeAnthropicListModels = "anthropic-list-models"
	ProbeOpenAIListModels    = "openai-list-models"
)

// gcsProbeObject is the object tofu/gcp/stage2 writes into the test bucket.
const gcsProbeObject = "cloud-auth-probe.txt"

// probeSTSEndpoint is the global STS endpoint the AWS probe signs against.
const probeSTSEndpoint = "https://sts.amazonaws.com/"

// probeHTTPTimeout bounds a probe's own network call, independently of the case timeout, so a slow probe degrades to a soft failure instead of eating the case's budget.
const probeHTTPTimeout = 15 * time.Second

// DefaultProbes is the registry the verifier binary ships with.
func DefaultProbes() map[string]Probe {
	return map[string]Probe{
		ProbeSTSGetCallerIdentity: STSGetCallerIdentityProbe(nil),
		ProbeGCSGetObject: BearerGetProbe(nil, core.GCP, func(c Case) (string, error) {
			if c.Target.Bucket == "" {
				return "", fmt.Errorf("%s probe needs target.bucket", ProbeGCSGetObject)
			}
			return "https://storage.googleapis.com/storage/v1/b/" + url.PathEscape(c.Target.Bucket) + "/o/" + gcsProbeObject, nil
		}, nil),
		ProbeAnthropicListModels: BearerGetProbe(nil, core.Anthropic, func(Case) (string, error) {
			return "https://api.anthropic.com/v1/models?limit=1", nil
		}, http.Header{"Anthropic-Version": {"2023-06-01"}}),
		ProbeOpenAIListModels: BearerGetProbe(nil, core.OpenAI, func(Case) (string, error) {
			return "https://api.openai.com/v1/models", nil
		}, nil),
	}
}

// BearerGetProbe returns a probe that GETs a URL with the exchanged bearer token and passes on 200.
func BearerGetProbe(client *http.Client, cloud core.Cloud, urlFor func(Case) (string, error), extra http.Header) Probe {
	if client == nil {
		client = &http.Client{Timeout: probeHTTPTimeout}
	}
	return func(ctx context.Context, creds *core.Credentials, c Case) (string, error) {
		if creds == nil || creds.Cloud != cloud {
			return "", fmt.Errorf("probe needs %s credentials, got cloud %q", cloud, credCloud(creds))
		}
		u, err := urlFor(c)
		if err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		for k, v := range extra {
			req.Header[k] = v
		}
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
		resp, err := client.Do(req) // #nosec G704 -- probe URLs are fixed API hosts; only the bucket name comes from the harness's own plan.
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("GET %s returned %d: %s", req.URL.Host+req.URL.Path, resp.StatusCode, string(raw))
		}
		return fmt.Sprintf("GET %s -> 200", req.URL.Host+req.URL.Path), nil
	}
}

// STSGetCallerIdentityProbe returns a probe that signs a GetCallerIdentity call with the exchanged credentials.
func STSGetCallerIdentityProbe(client *http.Client) Probe {
	if client == nil {
		client = &http.Client{Timeout: probeHTTPTimeout}
	}
	return func(ctx context.Context, creds *core.Credentials, c Case) (string, error) {
		if creds == nil || creds.Cloud != core.AWS {
			return "", fmt.Errorf("%s probe needs AWS credentials, got cloud %q", ProbeSTSGetCallerIdentity, credCloud(creds))
		}
		body := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeSTSEndpoint, strings.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		signer := v4.NewSigner()
		err = signer.SignHTTP(ctx, aws.Credentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
		}, req, sha256Hex(body), "sts", "us-east-1", time.Now().UTC())
		if err != nil {
			return "", fmt.Errorf("signing GetCallerIdentity: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode != http.StatusOK {
			// The body is an STS error document; it can echo request detail, so it is summarized and (like everything else) scrubbed downstream.
			return "", fmt.Errorf("sts:GetCallerIdentity returned %d: %s", resp.StatusCode, string(raw))
		}
		var out struct {
			Arn     string `xml:"GetCallerIdentityResult>Arn"`
			Account string `xml:"GetCallerIdentityResult>Account"`
			UserID  string `xml:"GetCallerIdentityResult>UserId"`
		}
		if err := xml.Unmarshal(raw, &out); err != nil {
			return "", fmt.Errorf("parsing GetCallerIdentity response: %w", err)
		}
		return fmt.Sprintf("arn=%s account=%s user_id=%s", out.Arn, out.Account, out.UserID), nil
	}
}

// sha256Hex is the payload hash SigV4 signs over.
func sha256Hex(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func credCloud(c *core.Credentials) core.Cloud {
	if c == nil {
		return ""
	}
	return c.Cloud
}
