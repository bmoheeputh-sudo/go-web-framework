package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	iapKeysURL       = "https://www.gstatic.com/iap/verify/public_key-jwk"
	iapKeyTTL        = 5 * time.Minute
	iapRefreshPeriod = 30 * time.Second
	iapMaxJWKSBytes  = 1024 * 1024
)

var ErrIAPKeysUnavailable = errors.New("IAP verification keys unavailable")

// The mutex coalesces refreshes; the cooldown bounds unknown-kid attacks and
// retries during outages. Expired keys are never used as an outage fallback.
type iapKeyCache struct {
	mu          sync.Mutex
	keys        map[string]*ecdsa.PublicKey
	expires     time.Time
	nextRefresh time.Time
	client      *http.Client
	now         func() time.Time
}

func newIAPKeyCache() *iapKeyCache {
	return &iapKeyCache{
		now: time.Now,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("IAP key redirects are not allowed")
			},
		},
	}
}

func (c *iapKeyCache) key(ctx context.Context, id string) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if key := c.keys[id]; key != nil && now.Before(c.expires) {
		return key, nil
	}
	if now.Before(c.nextRefresh) {
		if !now.Before(c.expires) {
			return nil, ErrIAPKeysUnavailable
		}
		return nil, ErrUnauthenticated
	}
	c.nextRefresh = now.Add(iapRefreshPeriod)
	keys, err := c.fetch(ctx)
	if err != nil {
		return nil, ErrIAPKeysUnavailable
	}
	c.keys, c.expires = keys, now.Add(iapKeyTTL)
	if key := c.keys[id]; key != nil {
		return key, nil
	}
	return nil, ErrUnauthenticated
}

func (c *iapKeyCache) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, iapKeysURL, nil)
	if err != nil {
		return nil, ErrIAPKeysUnavailable
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, ErrIAPKeysUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrIAPKeysUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, iapMaxJWKSBytes+1))
	if err != nil || len(body) > iapMaxJWKSBytes {
		return nil, ErrIAPKeysUnavailable
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal(body, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 64 {
		return nil, ErrIAPKeysUnavailable
	}
	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		key, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok || !jwk.Valid() || key.Curve != elliptic.P256() || jwk.KeyID == "" || len(jwk.KeyID) > 128 ||
			(jwk.Algorithm != "" && jwk.Algorithm != string(jose.ES256)) || (jwk.Use != "" && jwk.Use != "sig") ||
			keys[jwk.KeyID] != nil {
			return nil, ErrIAPKeysUnavailable
		}
		keys[jwk.KeyID] = key
	}
	return keys, nil
}
