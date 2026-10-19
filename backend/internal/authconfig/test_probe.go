package authconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// Keys are validated at discovery and fetched again before exchanging a code,
// supporting rotation without accepting unchecked JWKS keys or token algorithms.
type connectionProbe struct {
	config       oauth2.Config
	issuer, jwks string
	algorithms   []string
	client       *http.Client
}

func newConnectionProbe(ctx context.Context, m Metadata, secret Secret, callback string, client *http.Client) (*connectionProbe, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), m.IssuerURL)
	if err != nil {
		return nil, ErrUnavailable
	}
	var metadata struct {
		Issuer        string   `json:"issuer"`
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		Responses     []string `json:"response_types_supported"`
		Challenges    []string `json:"code_challenge_methods_supported"`
		Algorithms    []string `json:"id_token_signing_alg_values_supported"`
	}
	if provider.Claims(&metadata) != nil || metadata.Issuer != m.IssuerURL || !slices.Contains(metadata.Responses, "code") || !slices.Contains(metadata.Challenges, "S256") {
		return nil, ErrInvalid
	}
	issuer, err := testHTTPS(m.IssuerURL)
	if err != nil {
		return nil, ErrInvalid
	}
	for _, endpoint := range []string{metadata.Authorization, metadata.Token, metadata.JWKS} {
		u, err := testHTTPS(endpoint)
		// Deliberately narrow: credentials never leave the approved issuer origin.
		if err != nil || u.Host != issuer.Host {
			return nil, ErrInvalid
		}
	}
	algorithms := []string{}
	for _, alg := range []string{oidc.RS256, oidc.ES256} {
		if slices.Contains(metadata.Algorithms, alg) {
			algorithms = append(algorithms, alg)
		}
	}
	if len(algorithms) == 0 {
		return nil, ErrInvalid
	}
	p := &connectionProbe{config: oauth2.Config{ClientID: m.ClientID, ClientSecret: string(secret.value), RedirectURL: callback, Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, issuer: m.IssuerURL, jwks: metadata.JWKS, algorithms: algorithms, client: client}
	// Avoid OAuth2's credential-style auto-detection retry: one exchange only.
	p.config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if _, err = p.keys(ctx); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *connectionProbe) keys(ctx context.Context) (*oidc.StaticKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.jwks, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	response, err := p.client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, ErrInvalid
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(data, &keys) != nil || len(keys.Keys) == 0 || len(keys.Keys) > 32 {
		return nil, ErrInvalid
	}
	result := &oidc.StaticKeySet{}
	seen := map[string]bool{}
	for _, key := range keys.Keys {
		if key.KeyID == "" || seen[key.KeyID] || !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") {
			return nil, ErrInvalid
		}
		seen[key.KeyID] = true
		alg := key.Algorithm
		switch value := key.Key.(type) {
		case *rsa.PublicKey:
			if value.N.BitLen() < 2048 || value.E < 65537 || (alg != "" && alg != oidc.RS256) {
				return nil, ErrInvalid
			}
		case *ecdsa.PublicKey:
			if value.Curve.Params().BitSize != 256 || (alg != "" && alg != oidc.ES256) {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		result.PublicKeys = append(result.PublicKeys, key.Key)
	}
	return result, nil
}
func (p *connectionProbe) authorization(state, nonce, verifier string) string {
	return p.config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("response_mode", "query"), oauth2.SetAuthURLParam("prompt", "login"))
}
func (p *connectionProbe) exchange(ctx context.Context, code, nonce, verifier string) (auth.Identity, error) {
	keys, err := p.keys(ctx)
	if err != nil {
		return auth.Identity{}, err
	}
	token, err := p.config.Exchange(oidc.ClientContext(ctx, p.client), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return auth.Identity{}, ErrInvalid
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return auth.Identity{}, ErrInvalid
	}
	check := oidc.NewVerifier(p.issuer, keys, &oidc.Config{ClientID: p.config.ClientID, SupportedSigningAlgs: p.algorithms})
	identity, expiry, err := auth.VerifyOIDCIdentity(ctx, check, raw, p.issuer, p.config.ClientID, nonce)
	if err != nil || !time.Now().Before(expiry) || len(identity.Subject) > 1024 || len(identity.Email) > 1024 || len(identity.DisplayName) > 1024 {
		return auth.Identity{}, ErrInvalid
	}
	return identity, nil
}
func testCallback(origin string, m Metadata) (string, error) {
	if authConfig := (auth.OIDCConfig{AppEnv: m.Environment, Issuer: m.IssuerURL, ClientID: m.ClientID, ClientSecret: "present", RedirectURI: origin + "/api/auth/callback", AllowHTTPDevelopment: m.AllowHTTPDevelopment, Sessions: auth.SessionConfig{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 8 * time.Hour}}); authConfig.Validate() != nil {
		return "", ErrInvalid
	}
	u, _ := url.Parse(origin)
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalid
	}
	return origin + "/api/auth/test/callback", nil
}
