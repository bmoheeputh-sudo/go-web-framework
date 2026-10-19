package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	iapIssuer        = "https://cloud.google.com/iap"
	iapAssertion     = "X-Goog-IAP-JWT-Assertion"
	iapClockSkew     = int64(30) // Seconds, per Google's signed-header guidance.
	iapMaxLifetime   = int64(600) + 2*iapClockSkew
	iapMaxTokenBytes = 16 * 1024
)

// These are signed-header resource audiences, not OAuth client IDs or origin URLs.
var iapAudiencePattern = regexp.MustCompile(`^/projects/[0-9]+/(apps/[a-z][a-z0-9-]*|global/backendServices/[0-9]+|locations/[a-z][a-z0-9-]*/services/[a-z][a-z0-9-]*)$`)

type IAPAuthenticator struct {
	audience string
	keys     *iapKeyCache
	now      func() time.Time
}

// NewGoogleIAP needs no metadata server, credentials, database, or login callback.
// Keys are fetched lazily; protected requests fail closed during a key outage.
func NewGoogleIAP(audience string) (*IAPAuthenticator, error) {
	if err := ValidateIAPAudience(audience); err != nil {
		return nil, err
	}
	return &IAPAuthenticator{audience: audience, keys: newIAPKeyCache(), now: time.Now}, nil
}

// ValidateIAPAudience checks configuration syntax without constructing a provider
// or fetching keys. Administration uses the same rules as runtime startup.
func ValidateIAPAudience(audience string) error {
	if len(audience) > 512 || !iapAudiencePattern.MatchString(audience) {
		return errors.New("IAP_AUDIENCE must be an explicit App Engine, backend service, or Cloud Run signed-header resource audience")
	}
	return nil
}

func (p *IAPAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	values := r.Header.Values(iapAssertion)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > iapMaxTokenBytes || strings.TrimSpace(values[0]) != values[0] {
		return Identity{}, ErrUnauthenticated
	}
	// Compact JWS only, with exactly one protected ES256 signature. No token-supplied
	// URL, embedded key, unsigned identity header, cookie, or Bearer token is trusted.
	signed, err := jose.ParseSignedCompact(values[0], []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 {
		return Identity{}, ErrUnauthenticated
	}
	header := signed.Signatures[0].Protected
	if header.Algorithm != string(jose.ES256) || header.KeyID == "" || len(header.KeyID) > 128 || header.JSONWebKey != nil {
		return Identity{}, ErrUnauthenticated
	}
	key, err := p.keys.key(r.Context(), header.KeyID)
	if err != nil {
		return Identity{}, err
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	var claims struct {
		Issuer        string `json:"iss"`
		Subject       string `json:"sub"`
		Audience      string `json:"aud"` // IAP requires one exact string, not an array.
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		IssuedAt      int64  `json:"iat"`
		Expires       int64  `json:"exp"`
		NotBefore     *int64 `json:"nbf"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return Identity{}, ErrUnauthenticated
	}
	now := p.now().Unix()
	if claims.Issuer != iapIssuer || claims.Audience != p.audience ||
		claims.IssuedAt <= 0 || claims.Expires <= claims.IssuedAt ||
		claims.Expires-claims.IssuedAt > iapMaxLifetime ||
		claims.IssuedAt > now+iapClockSkew || claims.Expires <= now-iapClockSkew ||
		(claims.NotBefore != nil && *claims.NotBefore > now+iapClockSkew) {
		return Identity{}, ErrUnauthenticated
	}
	identity := Identity{Issuer: claims.Issuer, Subject: claims.Subject, Email: claims.Email,
		EmailVerified: claims.EmailVerified, DisplayName: claims.Name, Provider: GoogleIAP}
	if identity.Validate() != nil {
		return Identity{}, ErrUnauthenticated
	}
	return identity, nil
}
