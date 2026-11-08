package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anirudhbiyani/cloud-auth/core"
	"github.com/anirudhbiyani/cloud-auth/source"
)

// A machine with no detectable runtime cannot exercise the trust; that is skipped, not a verdict on the trust.
func TestTokenTestIsSkippedWhenNothingIsDetected(t *testing.T) {
	nothing := &fakeProvider{detErr: core.ErrNotThisRuntime}
	b := New(WithRegistry(source.NewRegistry(nothing)))
	check := NewTokenTestValidator(core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"}, b).Validate(context.Background(), core.MechanismRef{})
	if check.Status != core.CheckStatusSkipped || !strings.Contains(check.Message, "no source runtime detected") {
		t.Fatalf("check = %+v", check)
	}
}

func TestTokenTestPassesOnASuccessfulExchange(t *testing.T) {
	prov := &fakeProvider{rt: &core.Runtime{Cloud: core.GCP, SubRuntime: "gke", Federatable: true, Subject: "sa@p.iam"}}
	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(core.Cloud) (core.Exchanger, error) {
			return &fakeExchanger{creds: &core.Credentials{Cloud: core.AWS, AccessKeyID: "AKIA", Expiry: time.Now().Add(time.Hour)}}, nil
		}),
	)
	check := NewTokenTestValidator(core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"}, b).Validate(context.Background(), core.MechanismRef{})
	if check.Status != core.CheckStatusPassed {
		t.Fatalf("check = %+v", check)
	}
	if check.Evidence["source_runtime"] != "gcp/gke" || check.Evidence["source_subject"] != "sa@p.iam" {
		t.Errorf("evidence = %v", check.Evidence)
	}
}

// A refusal from the target is a real finding: either the trust is wrong or this runtime is not the one it names.
func TestTokenTestFailsWhenTheTargetRefuses(t *testing.T) {
	prov := &fakeProvider{rt: &core.Runtime{Cloud: core.GCP, SubRuntime: "gce", Federatable: true}}
	b := New(
		WithRegistry(source.NewRegistry(prov)),
		WithExchangerFor(func(core.Cloud) (core.Exchanger, error) {
			return &refusingExchanger{}, nil
		}),
	)
	check := NewTokenTestValidator(core.AWSTarget{RoleARN: "arn:aws:iam::123456789012:role/x"}, b).Validate(context.Background(), core.MechanismRef{})
	if check.Status != core.CheckStatusFailed || !strings.Contains(check.Remediation, "doctor --explain") {
		t.Fatalf("check = %+v", check)
	}
}

func TestTokenTestRejectsAnIncompleteTarget(t *testing.T) {
	check := NewTokenTestValidator(core.AWSTarget{}, New()).Validate(context.Background(), core.MechanismRef{})
	if check.Status != core.CheckStatusFailed || !strings.Contains(check.Message, "complete runtime target") {
		t.Fatalf("check = %+v", check)
	}
}

type refusingExchanger struct{}

func (refusingExchanger) Exchange(context.Context, *core.SourceToken, core.Target) (*core.Credentials, error) {
	return nil, errors.New("AccessDenied: not authorized to perform sts:AssumeRoleWithWebIdentity")
}
