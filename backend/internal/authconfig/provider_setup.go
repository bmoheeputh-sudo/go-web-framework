package authconfig

import (
	"net/url"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
)

const providerSetupPath = "/api/admin/auth/provider-setup"

// ProviderSetup contains server-owned OIDC registration values. It deliberately
// contains no revision data, credentials, discovery results, or request-derived
// host information.
type ProviderSetup struct {
	ApplicationName   string   `json:"application_name"`
	ApplicationType   string   `json:"application_type"`
	NormalCallbackURL string   `json:"normal_callback_url"`
	TestCallbackURL   string   `json:"test_callback_url"`
	GrantTypes        []string `json:"grant_types"`
	PKCEMethods       []string `json:"pkce_methods"`
	Scopes            []string `json:"scopes"`
	ClientAuthMethods []string `json:"client_authentication_methods"`
	Environment       string   `json:"environment"`
	DevelopmentHTTP   bool     `json:"development_http"`
}

func newProviderSetup(origin, environment string) (ProviderSetup, error) {
	if err := access.ValidateOrigin(origin, environment); err != nil {
		return ProviderSetup{}, ErrUnavailable
	}
	u, err := url.Parse(origin)
	if err != nil {
		return ProviderSetup{}, ErrUnavailable
	}
	return ProviderSetup{
		ApplicationName:   "Vopak Enterprise Security",
		ApplicationType:   "confidential_web_application",
		NormalCallbackURL: origin + "/api/auth/callback",
		TestCallbackURL:   origin + "/api/auth/test/callback",
		GrantTypes:        []string{"authorization_code"},
		PKCEMethods:       []string{"S256"},
		Scopes:            []string{"openid", "profile", "email"},
		// The isolated connection test intentionally uses one token request and
		// client_secret_basic. Advertising the runtime's legacy auto-detection
		// would suggest configurations that cannot complete the required test.
		ClientAuthMethods: []string{"client_secret_basic"},
		Environment:       environment,
		DevelopmentHTTP:   u.Scheme == "http",
	}, nil
}
