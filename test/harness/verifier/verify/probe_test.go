package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestBearerGetProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" || r.Header.Get("Anthropic-Version") == "" {
			http.Error(w, "denied", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	p := BearerGetProbe(srv.Client(), core.Anthropic, func(Case) (string, error) { return srv.URL + "/v1/models", nil },
		http.Header{"Anthropic-Version": {"2023-06-01"}})

	if _, err := p(context.Background(), &core.Credentials{Cloud: core.Anthropic, AccessToken: "good"}, Case{}); err != nil {
		t.Errorf("valid token: %v", err)
	}
	if _, err := p(context.Background(), &core.Credentials{Cloud: core.Anthropic, AccessToken: "bad"}, Case{}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("bad token: err = %v, want a 403", err)
	}
	if _, err := p(context.Background(), &core.Credentials{Cloud: core.GCP, AccessToken: "good"}, Case{}); err == nil {
		t.Error("wrong-cloud credentials must be refused before any request")
	}
}

func TestAITargetSpecs(t *testing.T) {
	plan := `{"run_id":"r","cases":[
	 {"name":"a","expect":"success","source_runtime":"gcp-gke","probe":"anthropic-list-models","target":{"cloud":"anthropic","audience":"https://api.anthropic.com","federation_rule_id":"fdrl_1","organization_id":"00000000-0000-0000-0000-000000000000","service_account_id":"svac_1","workspace_id":"wrkspc_1"}},
	 {"name":"o","expect":"success","source_runtime":"gcp-gke","probe":"openai-list-models","target":{"cloud":"openai","audience":"https://api.openai.com/v1","identity_provider_id":"idp_1","service_account_id":"sa_1"}}]}`
	p, err := LoadPlan([]byte(plan))
	if err != nil {
		t.Fatalf("LoadPlan: %v", err)
	}
	for i, want := range []core.Cloud{core.Anthropic, core.OpenAI} {
		tgt, err := p.Cases[i].Target.Target()
		if err != nil || tgt.Cloud() != want {
			t.Errorf("case %d: target = %v, %v; want cloud %s", i, tgt, err, want)
		}
		if _, ok := DefaultProbes()[p.Cases[i].Probe]; !ok {
			t.Errorf("probe %q is not registered", p.Cases[i].Probe)
		}
	}
	if _, err := LoadPlan([]byte(strings.Replace(plan, `"identity_provider_id":"idp_1",`, "", 1))); err == nil {
		t.Error("openai target without identity_provider_id must be rejected")
	}
}
