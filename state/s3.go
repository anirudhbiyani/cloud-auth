package state

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3 as a shared state backend.
//
// S3 gained conditional writes in 2024: If-None-Match on a PutObject creates
// only when nothing is there, and If-Match writes only when the current ETag
// still matches. Together those are a compare-and-swap, which is what makes a
// shared store safe without a lock table — no DynamoDB alongside, and nothing
// to leave stale when a process dies mid-write.

// s3API is the subset used here, so the store can be tested against a fake.
type s3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3Objects implements ObjectStore against one S3 object.
type S3Objects struct {
	api    s3API
	bucket string
	key    string
}

// NewS3Objects builds an S3-backed ObjectStore from ambient AWS configuration.
func NewS3Objects(ctx context.Context, bucket, key string) (*S3Objects, error) {
	if bucket == "" || key == "" {
		return nil, fmt.Errorf("state: an s3 state location needs both a bucket and a key")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("state: loading AWS configuration: %w", err)
	}
	return &S3Objects{api: s3.NewFromConfig(cfg), bucket: bucket, key: key}, nil
}

// NewS3ObjectsWithAPI builds a store over a supplied client. For tests.
func NewS3ObjectsWithAPI(api s3API, bucket, key string) *S3Objects {
	return &S3Objects{api: api, bucket: bucket, key: key}
}

// ParseS3URL splits an s3://bucket/key location.
func ParseS3URL(raw string) (bucket, key string, ok bool) {
	if !strings.HasPrefix(raw, "s3://") {
		return "", "", false
	}
	rest := strings.TrimPrefix(raw, "s3://")
	bucket, key, found := strings.Cut(rest, "/")
	if !found || bucket == "" || key == "" {
		return "", "", false
	}
	return bucket, key, true
}

// Describe names the object.
func (o *S3Objects) Describe() string { return "s3://" + o.bucket + "/" + o.key }

// Get reads the document and its ETag.
func (o *S3Objects) Get(ctx context.Context) ([]byte, string, error) {
	out, err := o.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(o.bucket),
		Key:    aws.String(o.key),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	defer func() { _ = out.Body.Close() }()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading the object body: %w", err)
	}
	return data, aws.ToString(out.ETag), nil
}

// Put writes the document under a precondition.
//
// An empty expectedVersion means "create only": If-None-Match: * fails if
// anything is already there, which is what makes two operators initialising the
// same bucket at the same moment safe.
func (o *S3Objects) Put(ctx context.Context, data []byte, expectedVersion string) error {
	in := &s3.PutObjectInput{
		Bucket:      aws.String(o.bucket),
		Key:         aws.String(o.key),
		Body:        strings.NewReader(string(data)),
		ContentType: aws.String("application/json"),
	}
	if expectedVersion == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(expectedVersion)
	}

	if _, err := o.api.PutObject(ctx, in); err != nil {
		if isS3PreconditionFailed(err) {
			return ErrPreconditionFailed
		}
		return err
	}
	return nil
}

// isS3NotFound reports whether err means the object is absent.
func isS3NotFound(err error) bool {
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	return s3StatusCode(err) == http.StatusNotFound
}

// isS3PreconditionFailed reports whether a conditional write lost.
//
// S3 answers a failed If-Match with 412, and a failed If-None-Match with 409 —
// two statuses for one meaning, and treating either as a hard error would turn
// a normal race into a failed command.
func isS3PreconditionFailed(err error) bool {
	switch s3StatusCode(err) {
	case http.StatusPreconditionFailed, http.StatusConflict:
		return true
	}
	return false
}

// s3StatusCode digs the HTTP status out of a smithy error.
func s3StatusCode(err error) int {
	var respErr interface{ HTTPStatusCode() int }
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode()
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "PreconditionFailed":
			return http.StatusPreconditionFailed
		case "NoSuchKey", "NotFound":
			return http.StatusNotFound
		}
	}
	return 0
}
