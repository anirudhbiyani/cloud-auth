// Command cloud-auth establishes cross-cloud trust relationships and obtains
// short-lived credentials at workload run time, with no static secrets.
//
//	go install github.com/anirudhbiyani/cloud-auth@latest
//
// The command has two halves. The control plane establishes trust — setup,
// validate, delete, list, describe — against a cloud's IAM APIs. The data plane
// then uses that trust: doctor, exchange, exec, init and credential-process
// detect the workload's own identity, mint a native proof of it, and exchange
// that proof at the target cloud's STS for short-lived credentials.
//
// Every operation the command performs is also available as a library, in the
// subpackages:
//
//	core    shared vocabulary, lifecycle manager, validation framework
//	source       source-identity detection and audience-pinned minting
//	target       target STS exchangers, one per cloud
//	broker       detect → mint → exchange, the data-plane core
//	adapters     SDK-native credential providers (aws, oauth2, azcore)
//	config       declarative federation config
//	provider/…   per-cloud control-plane lifecycle providers
package main

import (
	"fmt"
	"os"
)

// Exit codes. A validation failure is deliberately distinct from an operational
// error, so a pipeline can tell "the trust is misconfigured" from "the run
// itself broke" without parsing stderr.
const (
	exitError           = 1
	exitValidationError = 2
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitError)
	}
}
