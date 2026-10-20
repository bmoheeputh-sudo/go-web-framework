package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
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
	AllowHTTPDevelopment                                bool
	Sessions                                            SessionConfig
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("requires an absolute HTTPS URL without userinfo or fragment")
	}
	return u, nil
}

func (c OIDCConfig) Validate() error {
	switch c.AppEnv {
	case "development", "test", "TEST", "production", "prd", "PRD":
	default:
		return errors.New("APP_ENV must be development, test/TEST, or production/prd/PRD")
	}
	if c.AllowHTTPDevelopment && c.AppEnv != "development" {
		return errors.New("OIDC_ALLOW_HTTP_DEVELOPMENT is restricted to development")
	}
	if err := c.Sessions.validate(); err != nil {
		return err
	}
	issuer, err := httpsURL(c.Issuer)
	if err != nil || issuer.RawQuery != "" {
		return errors.New("OIDC_ISSUER_URL must be an HTTPS issuer URL without query or fragment")
	}
	if strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required")
	}
	redirect, err := url.Parse(c.RedirectURI)
	if err != nil || redirect.Hostname() == "" || redirect.User != nil || redirect.Fragment != "" ||
		redirect.Path != "/api/auth/callback" || redirect.RawPath != "" || redirect.RawQuery != "" {
		return errors.New("OIDC_REDIRECT_URI must be an absolute callback URL without userinfo, query or fragment")
	}
	if redirect.Scheme != "https" && !(redirect.Scheme == "http" && c.AllowHTTPDevelopment &&
		(redirect.Hostname() == "localhost" || net.ParseIP(redirect.Hostname()).IsLoopback())) {
		return errors.New("OIDC_REDIRECT_URI requires HTTPS; explicit HTTP development is limited to loopback")
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
	config                    oauth2.Config
	issuer                    string
	origin                    string
	client                    *http.Client
	verifier                  *oidc.IDTokenVerifier
	store                     sessionStore
	sessionCookie, flowCookie string
	secureCookies             bool
	absoluteTimeout           time.Duration
	onVerified                func(context.Context, Identity) error
}

// NewOIDC discovers trusted provider metadata before the application starts.
// OAuth errors can include tokens or response bodies, so callers receive only
// fixed errors. A context HTTP client supports isolated TLS test providers.
func NewOIDC(ctx context.Context, config OIDCConfig, store sessionStore) (*OIDCAuthenticator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("OIDC requires a configured session store")
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
	sessionName, flowName := sessionCookie, flowCookie
	secure := redirect.Scheme == "https"
	if !secure {
		sessionName, flowName = "gwf_dev_session", "gwf_dev_oidc_flow"
	}
	return &OIDCAuthenticator{
		config: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret,
			RedirectURL: config.RedirectURI, Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}},
		issuer: config.Issuer, origin: redirect.Scheme + "://" + redirect.Host,
		client: client, verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}), store: store,
		sessionCookie: sessionName, flowCookie: flowName, secureCookies: secure, absoluteTimeout: config.Sessions.AbsoluteTimeout,
	}, nil
}

func (p *OIDCAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	cookie, err := r.Cookie(p.sessionCookie)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	identity, err := p.store.identity(r.Context(), cookie.Value)
	if err != nil {
		return Identity{}, err
	}
	if identity.Issuer != p.issuer || identity.Provider != OIDC {
		return Identity{}, ErrUnauthenticated
	}
	return identity, nil
}

func authHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (p *OIDCAuthenticator) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if value == "" {
		maxAge = -1
	} else if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: p.secureCookies,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: expires})
}

func (p *OIDCAuthenticator) clearCookie(w http.ResponseWriter, name string) {
	p.setCookie(w, name, "", time.Unix(1, 0))
}

func (p *OIDCAuthenticator) Login(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	if previous, err := r.Cookie(p.flowCookie); err == nil {
		if _, err := p.store.takeFlow(r.Context(), previous.Value, ""); err != nil && !errors.Is(err, ErrUnauthenticated) {
			writeError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
			return
		}
	}
	flow := loginFlow{State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(),
		Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(loginLifetime)}
	id, err := p.store.addFlow(r.Context(), flow)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
		return
	}
	p.setCookie(w, p.flowCookie, id, flow.Expires)
	location := p.config.AuthCodeURL(flow.State, oidc.Nonce(flow.Nonce),
		oauth2.S256ChallengeOption(flow.Verifier), oauth2.SetAuthURLParam("response_mode", "query"))
	http.Redirect(w, r, location, http.StatusFound)
}

func (p *OIDCAuthenticator) Callback(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	p.clearCookie(w, p.flowCookie)
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
	cookie, err := r.Cookie(p.flowCookie)
	if err != nil {
		fail()
		return
	}
	flow, err := p.store.takeFlow(r.Context(), cookie.Value, query.Get("state"))
	if err != nil || query.Get("error") != "" || query.Get("code") == "" ||
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
	identity, tokenExpiry, err := VerifyOIDCIdentity(ctx, p.verifier, rawIDToken, p.issuer, p.config.ClientID, flow.Nonce)
	if err != nil {
		fail()
		return
	}
	// A database-bound callback must still be inside its original flow and
	// transition lifetime after token exchange. Environment semantics are unchanged.
	if _, bound := p.store.(*databaseBoundStore); bound && !time.Now().Before(flow.Expires) {
		fail()
		return
	}
	if p.onVerified != nil {
		if !time.Now().Before(flow.Expires) || p.onVerified(ctx, identity) != nil {
			fail()
			return
		}
		http.Redirect(w, r, p.origin+"/?auth_test=completed", http.StatusSeeOther)
		return
	}
	expires := time.Now().Add(p.absoluteTimeout)
	if tokenExpiry.Before(expires) {
		expires = tokenExpiry
	}
	if !time.Now().Before(expires) {
		fail()
		return
	}
	previous := ""
	if cookie, err := r.Cookie(p.sessionCookie); err == nil {
		previous = cookie.Value
	}
	id, err := p.store.addSession(r.Context(), identity, expires, previous)
	if err != nil {
		fail()
		return
	}
	// The store atomically rotates the existing session before issuing a cookie.
	p.setCookie(w, p.sessionCookie, id, expires)
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
	if cookie, err := r.Cookie(p.sessionCookie); err == nil {
		if err := p.store.deleteSession(r.Context(), cookie.Value); err != nil {
			writeError(w, http.StatusServiceUnavailable, "logout unavailable; please retry")
			return
		}
	}
	if cookie, err := r.Cookie(p.flowCookie); err == nil {
		if _, err := p.store.takeFlow(r.Context(), cookie.Value, ""); err != nil && !errors.Is(err, ErrUnauthenticated) {
			writeError(w, http.StatusServiceUnavailable, "logout unavailable; please retry")
			return
		}
	}
	p.clearCookie(w, p.sessionCookie)
	p.clearCookie(w, p.flowCookie)
	w.WriteHeader(http.StatusNoContent)
}

// VerifyOIDCIdentity is shared by normal login and isolated configuration tests.
// It verifies tokens and maps claims only; it never creates sessions or users.
func VerifyOIDCIdentity(ctx context.Context, verifier *oidc.IDTokenVerifier, rawIDToken, issuer, clientID, nonce string) (Identity, time.Time, error) {
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil || idToken.Issuer != issuer ||
		subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return Identity{}, time.Time{}, ErrUnauthenticated
	}
	var claims struct {
		Email           string `json:"email"`
		EmailVerified   bool   `json:"email_verified"`
		Name            string `json:"name"`
		AuthorizedParty string `json:"azp"`
	}
	if idToken.Claims(&claims) != nil ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID) ||
		(len(idToken.Audience) > 1 && claims.AuthorizedParty != clientID) {
		return Identity{}, time.Time{}, ErrUnauthenticated
	}
	identity := Identity{Issuer: idToken.Issuer, Subject: idToken.Subject, Email: claims.Email,
		EmailVerified: claims.EmailVerified, DisplayName: claims.Name, Provider: OIDC}
	if identity.Validate() != nil {
		return Identity{}, time.Time{}, ErrUnauthenticated
	}
	return identity, idToken.Expiry, nil
}
