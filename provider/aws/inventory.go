package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// AWS side of the cross-cloud trust inventory.
//
// Enumerating the ACCOUNT, not cloud-auth's state file. The population this
// serves is roles that predate this tool: AWS's shared-IdP guardrail explicitly
// does not apply to roles created before June 2025, and published research
// found assumable roles across 275+ accounts by exactly this route. A state
// file lists what cloud-auth created, which is the one set already known to be
// fine.

// InventoryCloud implements core.InventorySource.
func (p *Provider) InventoryCloud() core.Cloud { return core.AWS }

// ListTrustRecords enumerates every IAM role whose trust policy admits an
// external federated principal.
//
// One record per (role, subject condition): a role trusting three subjects is
// three rows, because each is separately scoreable and separately claimable,
// and collapsing them would hide the worst one behind the best.
func (p *Provider) ListTrustRecords(ctx context.Context) ([]core.TrustRecord, error) {
	client, err := p.iam(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: resolving IAM client: %w", err)
	}

	roles, err := client.ListRoles(ctx)
	if err != nil {
		return nil, err
	}

	var records []core.TrustRecord
	for _, role := range roles {
		if role == nil {
			continue
		}
		records = append(records, trustRecordsForRole(role)...)
	}
	return records, nil
}

// trustRecordsForRole turns one role's assume-role policy into inventory rows.
//
// Roles with no federated principal are skipped entirely rather than reported
// as clean: a role assumable only by an IAM principal in the same account is
// not a cross-cloud trust relationship and has nothing to do with this
// inventory. Listing them would bury the ones that matter.
func trustRecordsForRole(role *Role) []core.TrustRecord {
	var parsed iamPolicyDoc
	if err := json.Unmarshal([]byte(role.AssumeRolePolicyDocument), &parsed); err != nil {
		// A policy this code cannot read is worth surfacing rather than
		// dropping — "we could not tell" is not "nothing here".
		return []core.TrustRecord{{
			Cloud: core.AWS, Resource: role.ARN, Name: role.RoleName,
			SubjectCondition: "",
		}}
	}

	var records []core.TrustRecord
	for _, st := range parsed.Statement {
		if st.Effect != "" && !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		fed := stringOrSlice(st.Principal.Federated)
		if len(fed) == 0 {
			continue // not a federated trust
		}
		issuer := issuerFromFederatedPrincipal(fed[0])

		var audiences []string
		type subjectCondition struct{ operator, value string }
		var subjects []subjectCondition

		for operator, kv := range st.Condition {
			for key, raw := range kv {
				claim := key
				if i := strings.LastIndex(key, ":"); i >= 0 {
					claim = key[i+1:]
				}
				switch claim {
				case "aud", "oaud":
					audiences = append(audiences, stringOrSlice(raw)...)
				case "sub":
					for _, v := range stringOrSlice(raw) {
						subjects = append(subjects, subjectCondition{operator, v})
					}
				}
			}
		}

		base := core.TrustRecord{
			Cloud: core.AWS, Resource: role.ARN, Name: role.RoleName,
			Issuer: issuer, Audiences: audiences,
		}
		if len(subjects) == 0 {
			// No subject condition at all. This is the widest possible trust,
			// and it is a row rather than an omission — it is the finding.
			records = append(records, base)
			continue
		}
		for _, sub := range subjects {
			r := base
			r.SubjectCondition = sub.value
			r.Operator = sub.operator
			records = append(records, r)
		}
	}
	return records
}
