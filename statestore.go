package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/state"
)

// openStateStore resolves --state to a store.
func openStateStore(ctx context.Context, location string) (core.StateStore, error) {
	if strings.HasPrefix(location, "s3://") {
		bucket, key, ok := state.ParseS3URL(location)
		if !ok {
			// Refused, not fallen through.
			return nil, fmt.Errorf("--state %q is not a valid S3 location: "+
				"want s3://<bucket>/<key>", location)
		}
		objects, err := state.NewS3Objects(ctx, bucket, key)
		if err != nil {
			return nil, err
		}
		return state.New(objects), nil
	}
	return core.NewFileStateStore(location)
}
