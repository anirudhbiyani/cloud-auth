package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anirudhbiyani/cloud-auth/core"
)

// AWS side of the cross-cloud trust inventory.

// InventoryCloud implements core.InventorySource.
func (p *Provider) InventoryCloud() core.Cloud { return core.AWS }

// ListTrustRecords enumerates every IAM role whose trust policy admits an external federated principal.
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
func trustRecordsForRole(role *Role) []core.TrustRecord {
	var parsed iamPolicyDoc
	if err := json.Unmarshal([]byte(role.AssumeRolePolicyDocument), &parsed); err != nil {
		// A policy this code cannot read is worth surfacing rather than dropping — "we could not tell" is not "nothing here".
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
			// No subject condition at all.
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
