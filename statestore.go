package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/state"
)

// openStateStore resolves --state to a store.
//
// One function rather than five NewFileStateStore calls, so a location scheme
// added here is available to every command at once. The previous shape meant
// `list --state s3://…` would have created a FILE literally named "s3:" in the
// working directory and reported it as empty.
func openStateStore(ctx context.Context, location string) (core.StateStore, error) {
	if strings.HasPrefix(location, "s3://") {
		bucket, key, ok := state.ParseS3URL(location)
		if !ok {
			// Refused, not fallen through. A malformed s3:// location that
			// reaches NewFileStateStore creates a FILE named "s3:" in the
			// working directory and reports it as an empty store — a typo in a
			// shared state location silently becoming a private empty one is
			// how two operators each conclude the other created nothing.
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
