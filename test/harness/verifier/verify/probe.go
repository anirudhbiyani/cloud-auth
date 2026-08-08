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

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

// Probe names used in targets.json.
const (
	// ProbeSTSGetCallerIdentity proves AWS credentials work by calling
	// sts:GetCallerIdentity with them and reporting the resolved ARN.
	ProbeSTSGetCallerIdentity = "sts-get-caller-identity"
)

// probeSTSEndpoint is the global STS endpoint the AWS probe signs against.
const probeSTSEndpoint = "https://sts.amazonaws.com/"

// probeHTTPTimeout bounds a probe's own network call, independently of the case
// timeout, so a slow probe degrades to a soft failure instead of eating the
// case's budget.
const probeHTTPTimeout = 15 * time.Second

// DefaultProbes is the registry the verifier binary ships with. A case naming a
// probe that is absent here gets a clearly-labelled "unimplemented" soft result
// — the case itself still passes or fails on the credentials alone. Add probes
// by extending this map; nothing else needs to change.
func DefaultProbes() map[string]Probe {
	return map[string]Probe{
		ProbeSTSGetCallerIdentity: STSGetCallerIdentityProbe(nil),
	}
}

// STSGetCallerIdentityProbe returns a probe that signs a GetCallerIdentity call
// with the exchanged credentials. It reports only the identity STS resolves
// (ARN, account, user id) — never the credentials used to sign.
func STSGetCallerIdentityProbe(client *http.Client) Probe {
	if client == nil {
		client = &http.Client{Timeout: probeHTTPTimeout}
	}
	return func(ctx context.Context, creds *cloudauth.Credentials, c Case) (string, error) {
		if creds == nil || creds.Cloud != cloudauth.AWS {
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
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode != http.StatusOK {
			// The body is an STS error document; it can echo request detail, so
			// it is summarized and (like everything else) scrubbed downstream.
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

func credCloud(c *cloudauth.Credentials) cloudauth.Cloud {
	if c == nil {
		return ""
	}
	return c.Cloud
}
