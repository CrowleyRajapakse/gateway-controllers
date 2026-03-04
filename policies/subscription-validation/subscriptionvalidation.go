package subscriptionvalidation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	policyenginev1 "github.com/wso2/api-platform/sdk/gateway/policyengine/v1"
)

const (
	defaultApplicationIDMetadataKey = "x-wso2-application-id"
	defaultForbiddenStatusCode      = 403
	defaultForbiddenMessage         = "Subscription required for this API"
)

// PolicyConfig holds the resolved configuration for the subscriptionValidation policy.
type PolicyConfig struct {
	Enabled                  bool
	ApplicationIDMetadataKey string
	ForbiddenStatusCode      int
	ForbiddenMessage         string
}

// SubscriptionValidationPolicy validates that the calling application has an active
// subscription for the requested API.
type SubscriptionValidationPolicy struct {
	cfg   PolicyConfig
	store *policyenginev1.SubscriptionStore
}

var ins = &SubscriptionValidationPolicy{
	cfg: PolicyConfig{
		Enabled:                  true,
		ApplicationIDMetadataKey: defaultApplicationIDMetadataKey,
		ForbiddenStatusCode:      defaultForbiddenStatusCode,
		ForbiddenMessage:         defaultForbiddenMessage,
	},
	store: policyenginev1.GetSubscriptionStoreInstance(),
}

// GetPolicy returns a singleton instance of SubscriptionValidationPolicy.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	// Create a shallow copy of the singleton with route-specific configuration
	p := *ins
	p.cfg = mergeConfig(ins.cfg, params)
	return &p, nil
}

// mergeConfig merges raw parameters from the policy configuration into a base config.
func mergeConfig(base PolicyConfig, params map[string]interface{}) PolicyConfig {
	cfg := base
	if params == nil {
		return cfg
	}

	// enabled (bool, default true)
	if raw, ok := params["enabled"]; ok {
		if b, ok := raw.(bool); ok {
			cfg.Enabled = b
		} else if s, ok := raw.(string); ok {
			lower := strings.ToLower(strings.TrimSpace(s))
			cfg.Enabled = lower == "true" || lower == "1" || lower == "yes"
		}
	}

	// applicationIdMetadataKey (string, default x-wso2-application-id)
	if raw, ok := params["applicationIdMetadataKey"]; ok {
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			cfg.ApplicationIDMetadataKey = s
		}
	}

	// forbiddenStatusCode (int, default 403). Restrict to 4xx range.
	if raw, ok := params["forbiddenStatusCode"]; ok {
		switch v := raw.(type) {
		case int:
			if v >= 400 && v <= 499 {
				cfg.ForbiddenStatusCode = v
			}
		case float64:
			n := int(v)
			if n >= 400 && n <= 499 {
				cfg.ForbiddenStatusCode = n
			}
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 400 && n <= 499 {
				cfg.ForbiddenStatusCode = n
			}
		}
	}

	// forbiddenMessage (string, default message)
	if raw, ok := params["forbiddenMessage"]; ok {
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			cfg.ForbiddenMessage = s
		}
	}

	return cfg
}

// Mode returns the processing mode for this policy.
func (p *SubscriptionValidationPolicy) Mode() policy.ProcessingMode {
	// Only needs request headers and shared metadata; no body processing required.
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequest validates the subscription and may short-circuit with a 403 response.
func (p *SubscriptionValidationPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if !p.cfg.Enabled {
		return nil
	}
	if ctx == nil || ctx.SharedContext == nil {
		return p.forbiddenResponse("request context is missing")
	}

	apiID := ctx.SharedContext.APIId
	if strings.TrimSpace(apiID) == "" {
		// Without an API ID we cannot validate subscriptions; fail closed to avoid bypass.
		slog.Error("subscriptionValidation: APIId is empty in SharedContext; failing validation")
		return p.forbiddenResponse("API id is missing")
	}

	metadata := ctx.SharedContext.Metadata
	if metadata == nil {
		// Missing application metadata is treated as an authentication problem.
		return p.unauthorizedResponse("application metadata is missing")
	}

	rawAppID, ok := metadata[p.cfg.ApplicationIDMetadataKey]
	if !ok {
		return p.unauthorizedResponse("application id is missing")
	}

	appID := strings.TrimSpace(fmt.Sprint(rawAppID))
	if appID == "" {
		return p.unauthorizedResponse("application id is empty")
	}

	if p.store == nil {
		slog.Error("subscriptionValidation: subscription store is not initialized")
		return p.forbiddenResponse("subscription store is not available")
	}

	if !p.store.IsActive(apiID, appID) {
		slog.Info("subscriptionValidation: no active subscription found",
			"apiId", apiID,
			"applicationId", appID)
		return p.forbiddenResponse("")
	}

	// Subscription is active; continue to next policy.
	return nil
}

// OnResponse is a no-op for this policy.
func (p *SubscriptionValidationPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil
}

// forbiddenResponse constructs an ImmediateResponse with the configured status and message.
func (p *SubscriptionValidationPolicy) forbiddenResponse(detail string) policy.RequestAction {
	message := p.cfg.ForbiddenMessage
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	payload := map[string]string{
		"error":   "forbidden",
		"message": message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"forbidden","message":"subscription validation failed"}`)
	}

	statusCode := p.cfg.ForbiddenStatusCode
	if statusCode < 400 || statusCode > 499 {
		statusCode = defaultForbiddenStatusCode
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}

// unauthorizedResponse constructs an ImmediateResponse for missing/invalid
// authentication or application identity with a 401 status code.
func (p *SubscriptionValidationPolicy) unauthorizedResponse(detail string) policy.RequestAction {
	message := p.cfg.ForbiddenMessage
	if detail != "" {
		message = fmt.Sprintf("%s: %s", message, detail)
	}

	payload := map[string]string{
		"error":   "unauthorized",
		"message": message,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"unauthorized","message":"subscription validation failed"}`)
	}

	return policy.ImmediateResponse{
		StatusCode: http.StatusUnauthorized,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}
}
