# cloud-auth integration harness.
#
#   make up      provision (stage1 compute -> stage2 cross-cloud trust)
#   make verify  run the verifier inside every source runtime
#   make down    destroy everything (safe to run any time, even after a failure)
#   make sweep   list orphaned resources by tag if a destroy failed
#   make cycle   up -> verify -> down, with down guaranteed even if verify fails
#
# `make up` creates REAL, BILLABLE infrastructure. See README.md.
# Scope a run with CLOUDS=aws,gcp   /  RUNTIMES=gcp-gce,aws-ec2
# Non-interactive (CI):              YES=1

SHELL   := /usr/bin/env bash
SCRIPTS := ./scripts
CLOUDS  ?= aws,gcp,azure
RUNTIMES?= gcp-gce,aws-ec2,aws-eks-irsa,azure-aks-workload-identity
YES     ?=
YESFLAG := $(if $(YES),--yes,)

.PHONY: up verify down sweep cycle targets fmt check help

help:
	@sed -n '1,14p' Makefile

up:
	$(SCRIPTS)/up.sh $(YESFLAG) --clouds $(CLOUDS)

verify:
	$(SCRIPTS)/verify.sh --runtimes $(RUNTIMES)

down:
	$(SCRIPTS)/down.sh $(YESFLAG) --clouds $(CLOUDS)

sweep:
	$(SCRIPTS)/sweep.sh

targets:
	$(SCRIPTS)/build-targets.sh

# Delegates to run-harness.sh, which owns the teardown guarantee (a trap that
# fires on failure AND on Ctrl-C — something make alone can't give us).
cycle:
	./run-harness.sh --yes --clouds $(CLOUDS) --runtimes $(RUNTIMES)

# Static checks that need no cloud access at all.
check: fmt
	@command -v tofu >/dev/null 2>&1 && { \
	  for d in tofu/*/stage1 tofu/*/stage2; do \
	    [ -d "$$d" ] || continue; \
	    echo "==> validate $$d"; \
	    tofu -chdir=$$d init -backend=false -input=false >/dev/null && \
	    tofu -chdir=$$d validate || exit 1; \
	  done; } || echo "tofu not installed — skipping HCL validate"
	@echo "==> shellcheck"; command -v shellcheck >/dev/null 2>&1 && shellcheck scripts/*.sh || echo "shellcheck not installed — skipping"
	@echo "==> go vet (verifier + integration)"
	cd ../.. && go vet ./test/... && go vet -tags integration ./test/integration/...

fmt:
	@command -v tofu >/dev/null 2>&1 && tofu fmt -recursive tofu || echo "tofu not installed — skipping fmt"
	cd ../.. && gofmt -l test/
