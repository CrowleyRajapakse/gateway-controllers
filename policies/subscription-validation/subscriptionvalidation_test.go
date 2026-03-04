package subscriptionvalidation

import (
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	policyenginev1 "github.com/wso2/api-platform/sdk/gateway/policyengine/v1"
)

type fakeSubscriptionStore struct {
	active bool
}

func (f *fakeSubscriptionStore) ReplaceAll(_ []policyenginev1.SubscriptionData) {
	// no-op for tests
}

func (f *fakeSubscriptionStore) IsActive(apiID, appID string) bool {
	return f.active && apiID != "" && appID != ""
}

// Test helper to build a basic request context.
func newRequestContext(apiID, appID string, metadataKey string) *policy.RequestContext {
	if metadataKey == "" {
		metadataKey = defaultApplicationIDMetadataKey
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId: apiID,
			Metadata: map[string]interface{}{
				metadataKey: appID,
			},
		},
	}
}

func TestMergeConfig_DefaultsAndOverrides(t *testing.T) {
	base := PolicyConfig{
		Enabled:                  true,
		ApplicationIDMetadataKey: defaultApplicationIDMetadataKey,
		ForbiddenStatusCode:      defaultForbiddenStatusCode,
		ForbiddenMessage:         defaultForbiddenMessage,
	}

	params := map[string]interface{}{
		"enabled":                  false,
		"applicationIdMetadataKey": "custom-key",
		"forbiddenStatusCode":      429,
		"forbiddenMessage":         "too many requests",
	}

	cfg := mergeConfig(base, params)

	if cfg.Enabled {
		t.Fatalf("expected Enabled to be false")
	}
	if cfg.ApplicationIDMetadataKey != "custom-key" {
		t.Fatalf("expected ApplicationIDMetadataKey=custom-key, got %q", cfg.ApplicationIDMetadataKey)
	}
	if cfg.ForbiddenStatusCode != 429 {
		t.Fatalf("expected ForbiddenStatusCode=429, got %d", cfg.ForbiddenStatusCode)
	}
	if cfg.ForbiddenMessage != "too many requests" {
		t.Fatalf("expected ForbiddenMessage override, got %q", cfg.ForbiddenMessage)
	}
}

func TestOnRequest_SkipsWhenDisabled(t *testing.T) {
	p := &SubscriptionValidationPolicy{
		cfg: PolicyConfig{
			Enabled:                  false,
			ApplicationIDMetadataKey: defaultApplicationIDMetadataKey,
			ForbiddenStatusCode:      defaultForbiddenStatusCode,
			ForbiddenMessage:         defaultForbiddenMessage,
		},
		store: &fakeSubscriptionStore{active: false},
	}

	ctx := newRequestContext("api-1", "app-1", "")
	if action := p.OnRequest(ctx, nil); action != nil {
		t.Fatalf("expected no action when policy is disabled, got %#v", action)
	}
}

func TestOnRequest_AllowsWhenSubscribed(t *testing.T) {
	p := &SubscriptionValidationPolicy{
		cfg: PolicyConfig{
			Enabled:                  true,
			ApplicationIDMetadataKey: defaultApplicationIDMetadataKey,
			ForbiddenStatusCode:      defaultForbiddenStatusCode,
			ForbiddenMessage:         defaultForbiddenMessage,
		},
		store: &fakeSubscriptionStore{active: true},
	}

	ctx := newRequestContext("api-1", "app-1", "")
	if action := p.OnRequest(ctx, nil); action != nil {
		t.Fatalf("expected nil action when subscription is active, got %#v", action)
	}
}

func TestOnRequest_DeniesWhenNotSubscribed(t *testing.T) {
	p := &SubscriptionValidationPolicy{
		cfg: PolicyConfig{
			Enabled:                  true,
			ApplicationIDMetadataKey: defaultApplicationIDMetadataKey,
			ForbiddenStatusCode:      403,
			ForbiddenMessage:         "Subscription required",
		},
		store: &fakeSubscriptionStore{active: false},
	}

	ctx := newRequestContext("api-1", "app-1", "")
	action := p.OnRequest(ctx, nil)

	immediate, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}

	if immediate.StatusCode != 403 {
		t.Fatalf("expected status 403, got %d", immediate.StatusCode)
	}
	if ct := immediate.Headers["Content-Type"]; ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(immediate.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Fatalf("expected error=forbidden, got %q", body["error"])
	}
	if body["message"] == "" {
		t.Fatalf("expected non-empty message")
	}
}

func TestOnRequest_DeniesWhenApplicationIdMissing(t *testing.T) {
	p := &SubscriptionValidationPolicy{
		cfg: PolicyConfig{
			Enabled:                  true,
			ApplicationIDMetadataKey: defaultApplicationIDMetadataKey,
			ForbiddenStatusCode:      403,
			ForbiddenMessage:         "Subscription required",
		},
		store: &fakeSubscriptionStore{active: true},
	}

	// Build a context without application id metadata.
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			APIId:    "api-1",
			Metadata: map[string]interface{}{},
		},
	}

	action := p.OnRequest(ctx, nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse when application id is missing, got %T", action)
	}

	if resp.StatusCode != p.cfg.ForbiddenStatusCode {
		t.Fatalf("expected status code %d, got %d", p.cfg.ForbiddenStatusCode, resp.StatusCode)
	}

	var body map[string]string
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Fatalf("expected error=forbidden, got %q", body["error"])
	}
	if body["message"] == "" {
		t.Fatalf("expected non-empty message")
	}
}
