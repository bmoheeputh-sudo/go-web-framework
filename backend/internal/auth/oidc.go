package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "__Host-gwf_session"
	flowCookie    = "__Host-gwf_oidc_flow"
)

type OIDCConfig struct {
	AppEnv, Issuer, ClientID, ClientSecret, RedirectURI string
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("requires an absolute HTTPS URL without userinfo or fragment")
	}
	return u, nil
}

func (c OIDCConfig) validate() error {
	if c.AppEnv != "development" {
		return errors.New("OIDC memory sessions require APP_ENV=development; other environments require shared persistent sessions")
	}
	issuer, err := httpsURL(c.Issuer)
	if err != nil || issuer.RawQuery != "" {
		return errors.New("OIDC_ISSUER_URL must be an HTTPS issuer URL without query or fragment")
	}
	if strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required")
	}
	redirect, err := httpsURL(c.RedirectURI)
	if err != nil || redirect.Path != "/api/auth/callback" || redirect.RawPath != "" || redirect.RawQuery != "" {
		return errors.New("OIDC_REDIRECT_URI must be an HTTPS URL ending in /api/auth/callback without query or fragment")
	}
	return nil
}

// httpsTransport also guards metadata-supplied JWKS/token URLs and outbound
// requests; TLS verification remains enabled. Redirects are refused separately.
type httpsTransport struct{ base http.RoundTripper }

func (t httpsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, err := httpsURL(r.URL.String()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

type OIDCAuthenticator struct {
	config   oauth2.Config
	issuer   string
	origin   string
	client   *http.Client
	verifier *oidc.IDTokenVerifier
	store    *memoryStore
}

// NewOIDC discovers trusted provider metadata before the application starts.
// OAuth errors can include tokens or response bodies, so callers receive only
// fixed errors. A context HTTP client supports isolated TLS test providers.
func NewOIDC(ctx context.Context, config OIDCConfig) (*OIDCAuthenticator, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	client := &http.Client{}
	if supplied, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		copy := *supplied
		client = &copy
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = httpsTransport{base: transport}
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("OIDC HTTP redirects are not permitted") }
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, errors.New("OIDC discovery failed; verify issuer, connectivity and TLS trust")
	}
	var metadata struct {
		Issuer        string   `json:"issuer"`
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		ResponseTypes []string `json:"response_types_supported"`
		Challenges    []string `json:"code_challenge_methods_supported"`
	}
	if provider.Claims(&metadata) != nil || metadata.Issuer != config.Issuer || !slices.Contains(metadata.ResponseTypes, "code") {
		return nil, errors.New("OIDC discovery metadata is invalid or does not support authorization code flow")
	}
	for _, endpoint := range []string{metadata.Authorization, metadata.Token, metadata.JWKS} {
		if _, err := httpsURL(endpoint); err != nil {
			return nil, errors.New("OIDC discovery endpoints must use HTTPS")
		}
	}
	if len(metadata.Challenges) > 0 && !slices.Contains(metadata.Challenges, "S256") {
		return nil, errors.New("OIDC provider does not support PKCE S256")
	}
	redirect, _ := url.Parse(config.RedirectURI)
	return &OIDCAuthenticator{
		config: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret,
			RedirectURL: config.RedirectURI, Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}},
		issuer: config.Issuer, origin: redirect.Scheme + "://" + redirect.Host,
		client: client, verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}), store: newMemoryStore(),
	}, nil
}

func (p *OIDCAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	identity, ok := p.store.identity(cookie.Value)
	if !ok {
		return Identity{}, ErrUnauthenticated
	}
	return identity, nil
}

func authHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if value == "" {
		maxAge = -1
	} else if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: expires})
}

func clearCookie(w http.ResponseWriter, name string) {
	setCookie(w, name, "", time.Unix(1, 0))
}

func (p *OIDCAuthenticator) Login(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	if previous, err := r.Cookie(flowCookie); err == nil {
		p.store.takeFlow(previous.Value, "")
	}
	flow := loginFlow{State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(),
		Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(loginLifetime)}
	id, err := p.store.addFlow(flow)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
		return
	}
	setCookie(w, flowCookie, id, flow.Expires)
	location := p.config.AuthCodeURL(flow.State, oidc.Nonce(flow.Nonce),
		oauth2.S256ChallengeOption(flow.Verifier), oauth2.SetAuthURLParam("response_mode", "query"))
	http.Redirect(w, r, location, http.StatusFound)
}

func (p *OIDCAuthenticator) Callback(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	clearCookie(w, flowCookie)
	// Reject malformed/ambiguous queries before exchanging a code. Callback errors
	// redirect to a fixed URL, clearing code/state from the browser address bar.
	fail := func() { http.Redirect(w, r, p.origin+"/?auth_error=login_failed", http.StatusSeeOther) }
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail()
		return
	}
	for _, key := range []string{"state", "code", "error", "iss"} {
		if len(query[key]) > 1 {
			fail()
			return
		}
	}
	cookie, err := r.Cookie(flowCookie)
	if err != nil {
		fail()
		return
	}
	flow, ok := p.store.takeFlow(cookie.Value, query.Get("state"))
	if !ok || query.Get("error") != "" || query.Get("code") == "" ||
		(query.Get("iss") != "" && query.Get("iss") != p.issuer) {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), p.client), 20*time.Second)
	defer cancel()
	token, err := p.config.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		fail()
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		fail()
		return
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil || idToken.Issuer != p.issuer ||
		subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		fail()
		return
	}
	var claims struct {
		Email           string `json:"email"`
		EmailVerified   bool   `json:"email_verified"`
		Name            string `json:"name"`
		AuthorizedParty string `json:"azp"`
	}
	if idToken.Claims(&claims) != nil ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != p.config.ClientID) ||
		(len(idToken.Audience) > 1 && claims.AuthorizedParty != p.config.ClientID) {
		fail()
		return
	}
	identity := Identity{Issuer: idToken.Issuer, Subject: idToken.Subject, Email: claims.Email,
		EmailVerified: claims.EmailVerified, DisplayName: claims.Name, Provider: OIDC}
	if identity.Validate() != nil {
		fail()
		return
	}
	expires := time.Now().Add(sessionLifetime)
	if idToken.Expiry.Before(expires) {
		expires = idToken.Expiry
	}
	if !time.Now().Before(expires) {
		fail()
		return
	}
	id, err := p.store.addSession(identity, expires)
	if err != nil {
		fail()
		return
	}
	// Rotate an existing browser session only after the replacement succeeds.
	if previous, err := r.Cookie(sessionCookie); err == nil {
		p.store.deleteSession(previous.Value)
	}
	setCookie(w, sessionCookie, id, expires)
	// ID/access/refresh tokens are discarded, never stored or sent to React.
	http.Redirect(w, r, p.origin+"/", http.StatusSeeOther)
}

func (p *OIDCAuthenticator) Logout(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	// Require the configured browser origin rather than trusting Host/forwarded
	// headers. POST + Origin validation protects logout from cross-site requests.
	if r.Header.Get("Origin") != p.origin {
		writeError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		p.store.deleteSession(cookie.Value)
	}
	if cookie, err := r.Cookie(flowCookie); err == nil {
		p.store.takeFlow(cookie.Value, "")
	}
	clearCookie(w, sessionCookie)
	clearCookie(w, flowCookie)
	w.WriteHeader(http.StatusNoContent)
}
