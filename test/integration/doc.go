// Package integration holds the cloud-integration tests for the pair matrix in
// test/harness/CONTRACT.md.
//
// Every test file here is behind the `integration` build tag, so `go test ./...`
// never runs them. They are executed by the harness after `up.sh` has applied
// stage 1 and stage 2:
//
//	go test -tags integration -v ./test/integration/...
//
// With no harness state present they skip with an explanatory message — they
// never fail and never hang on a laptop with no cloud access. See README.md.
package integration
