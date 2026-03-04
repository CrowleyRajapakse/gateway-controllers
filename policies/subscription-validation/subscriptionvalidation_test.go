package subscriptionvalidation

import (
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	policyenginev1 "github.com/wso2/api-platform/sdk/gateway/policyengine/v1"
)

// --- helpers -----------------------------------------------------------------

func newStore(entries []policyenginev1.SubscriptionData) *policyenginev1.SubscriptionStore {
	s := policyenginev1.NewSubscriptionStore()
	s.ReplaceAll(entries)
	return s
}

func newPolicy(cfg PolicyConfig, store *policyenginev1.SubscriptionStore) *SubscriptionValidationPolicy {
	return &SubscriptionValidationPolicy{
		cfg:        cfg,
		store:      store,
		rateLimits: make(map[string]*rateLimitEntry),
	}
}

func defaultCfg() PolicyConfig {
	return PolicyConfig{
		Enabled:               true,
		SubscriptionKeyHeader: defaultSubscriptionKeyHeader,
	}
}

func ctxWithToken(apiID, token, headerName string) *policy.RequestContext {
	if headerName == "" {
		headerName = defaultSubscriptionKeyHeader
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId:    apiID,
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(map[string][]string{
			headerName: {token},
		}),
	}
}

func ctxWithAppID(apiID, appID string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId: apiID,
			Metadata: map[string]interface{}{
				applicationIDMetadataKey: appID,
			},
		},
		Headers: policy.NewHeaders(nil),
	}
}

func assertNil(t *testing.T, action policy.RequestAction) {
	t.Helper()
	if action != nil {
		t.Fatalf("expected nil action, got %#v", action)
	}
}

func assertImmediate(t *testing.T, action policy.RequestAction, wantStatus int, wantErrorKey string) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("expected status %d, got %d", wantStatus, resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if body["error"] != wantErrorKey {
		t.Fatalf("expected error=%q, got %q", wantErrorKey, body["error"])
	}
}

// --- mergeConfig tests -------------------------------------------------------

func TestMergeConfig_Defaults(t *testing.T) {
	cfg := mergeConfig(defaultCfg(), nil)
	if !cfg.Enabled {
		t.Fatal("expected Enabled=true by default")
	}
	if cfg.SubscriptionKeyHeader != defaultSubscriptionKeyHeader {
		t.Fatalf("expected default header=%q, got %q", defaultSubscriptionKeyHeader, cfg.SubscriptionKeyHeader)
	}
}

func TestMergeConfig_Overrides(t *testing.T) {
	cfg := mergeConfig(defaultCfg(), map[string]interface{}{
		"enabled":               false,
		"subscriptionKeyHeader": "X-My-Key",
	})
	if cfg.Enabled {
		t.Fatal("expected Enabled=false after override")
	}
	if cfg.SubscriptionKeyHeader != "X-My-Key" {
		t.Fatalf("expected header=X-My-Key, got %q", cfg.SubscriptionKeyHeader)
	}
}

// --- disabled ----------------------------------------------------------------

func TestOnRequest_SkipsWhenDisabled(t *testing.T) {
	cfg := defaultCfg()
	cfg.Enabled = false
	p := newPolicy(cfg, nil)
	ctx := ctxWithToken("api-1", "tok-1", "")
	assertNil(t, p.OnRequest(ctx, nil))
}

// --- token path (primary) ----------------------------------------------------

func TestOnRequest_AllowsValidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: "tok-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := ctxWithToken("api-1", "tok-1", "")
	assertNil(t, p.OnRequest(ctx, nil))
}

func TestOnRequest_DeniesInvalidToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: "tok-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := ctxWithToken("api-1", "wrong-token", "")
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}

func TestOnRequest_DeniesInactiveToken(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: "tok-1", Status: "INACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := ctxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}

func TestOnRequest_CustomHeaderName(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: "tok-1", Status: "ACTIVE"},
	})
	cfg := defaultCfg()
	cfg.SubscriptionKeyHeader = "X-Custom-Sub"
	p := newPolicy(cfg, store)

	ctx := ctxWithToken("api-1", "tok-1", "X-Custom-Sub")
	assertNil(t, p.OnRequest(ctx, nil))
}

// --- appId fallback (legacy) -------------------------------------------------

func TestOnRequest_FallbackAppIdAllows(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := ctxWithAppID("api-1", "app-1")
	assertNil(t, p.OnRequest(ctx, nil))
}

func TestOnRequest_FallbackAppIdDenies(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)
	ctx := ctxWithAppID("api-1", "app-wrong")
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}

// --- no identity at all ------------------------------------------------------

func TestOnRequest_DeniesWhenNoIdentity(t *testing.T) {
	store := newStore(nil)
	p := newPolicy(defaultCfg(), store)
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId:    "api-1",
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(nil),
	}
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}

// --- missing apiId fails closed ----------------------------------------------

func TestOnRequest_FailsClosedWhenAPIIdMissing(t *testing.T) {
	store := newStore(nil)
	p := newPolicy(defaultCfg(), store)
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId:    "",
			Metadata: map[string]interface{}{},
		},
		Headers: policy.NewHeaders(nil),
	}
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}

// --- rate limiting -----------------------------------------------------------

func TestOnRequest_RateLimitEnforced(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:              "api-1",
			SubscriptionToken:  "tok-1",
			Status:             "ACTIVE",
			ThrottleLimitCount: 3,
			ThrottleLimitUnit:  "Min",
			StopOnQuotaReach:   true,
		},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 3; i++ {
		ctx := ctxWithToken("api-1", "tok-1", "")
		action := p.OnRequest(ctx, nil)
		if action != nil {
			t.Fatalf("request %d should be allowed, got %#v", i+1, action)
		}
	}

	ctx := ctxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequest(ctx, nil), 429, "rate_limit_exceeded")
}

func TestOnRequest_RateLimitNotEnforcedWhenStopOnQuotaFalse(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{
			APIId:              "api-1",
			SubscriptionToken:  "tok-1",
			Status:             "ACTIVE",
			ThrottleLimitCount: 1,
			ThrottleLimitUnit:  "Min",
			StopOnQuotaReach:   false,
		},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 5; i++ {
		ctx := ctxWithToken("api-1", "tok-1", "")
		action := p.OnRequest(ctx, nil)
		if action != nil {
			t.Fatalf("request %d should be allowed (stopOnQuotaReach=false), got %#v", i+1, action)
		}
	}
}

func TestOnRequest_NoRateLimitWithoutPlan(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: "tok-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)

	for i := 0; i < 100; i++ {
		ctx := ctxWithToken("api-1", "tok-1", "")
		action := p.OnRequest(ctx, nil)
		if action != nil {
			t.Fatalf("request %d should be allowed (no throttle plan), got %#v", i+1, action)
		}
	}
}

// --- token takes precedence over appId ---------------------------------------

func TestOnRequest_TokenTakesPrecedenceOverAppId(t *testing.T) {
	store := newStore([]policyenginev1.SubscriptionData{
		{APIId: "api-1", SubscriptionToken: "tok-1", Status: "ACTIVE"},
		{APIId: "api-1", ApplicationId: "app-1", Status: "ACTIVE"},
	})
	p := newPolicy(defaultCfg(), store)

	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId: "api-1",
			Metadata: map[string]interface{}{
				applicationIDMetadataKey: "app-1",
			},
		},
		Headers: policy.NewHeaders(map[string][]string{
			defaultSubscriptionKeyHeader: {"wrong-token"},
		}),
	}
	// Token path should be tried first and should fail (wrong token),
	// even though appId path would succeed.
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}

// --- nil context / nil store guards ------------------------------------------

func TestOnRequest_NilContext(t *testing.T) {
	p := newPolicy(defaultCfg(), policyenginev1.NewSubscriptionStore())
	assertImmediate(t, p.OnRequest(nil, nil), 403, "forbidden")
}

func TestOnRequest_NilStore(t *testing.T) {
	p := newPolicy(defaultCfg(), nil)
	ctx := ctxWithToken("api-1", "tok-1", "")
	assertImmediate(t, p.OnRequest(ctx, nil), 403, "forbidden")
}
