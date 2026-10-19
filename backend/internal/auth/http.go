package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator resolves the identity for a protected request. It does not impose
// a shared credential format: IAP can verify its assertion, while OIDC can resolve
// a session established by separate login/callback handlers. Those flows and
// session storage are intentionally outside this request-authentication interface.
type Authenticator interface {
	Authenticate(*http.Request) (Identity, error)
}

type identityKey struct{}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}

// Require rejects requests without a verified, valid identity. A nil provider
// leaves protected routes unavailable while public routes can still be served.
func Require(provider Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if provider == nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		identity, err := provider.Authenticate(r)
		if errors.Is(err, ErrUnauthenticated) {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if err != nil || identity.Validate() != nil {
			writeError(w, http.StatusInternalServerError, "authentication unavailable")
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
