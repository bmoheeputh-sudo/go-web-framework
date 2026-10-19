package authconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestKeyringHistoricalCompatibility(t *testing.T) {
	encoded := func() string {
		t.Helper()
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("random source unavailable")
		}
		defer clear(key[:])
		return base64.StdEncoding.EncodeToString(key[:])
	}
	oldKey, newKey := encoded(), encoded()
	old, err := CipherFromEnv(func(k string) string {
		if k == "AUTH_ENCRYPTION_KEY_ID" {
			return "old"
		}
		return oldKey
	})
	if err != nil {
		t.Fatal(err)
	}
	m, secret := testMetadata(), NewSecret([]byte("synthetic-keyring-secret"))
	historical, err := old.seal(m, secret)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"old": oldKey, "current": newKey}
	ring, err := NewKeyring("current", keys)
	if err != nil {
		t.Fatal(err)
	}
	delete(keys, "old") // caller mutation cannot remove keys from the constructed ring
	got, err := ring.open(m, historical)
	if err != nil || !bytes.Equal(got.Bytes(), secret.Bytes()) {
		t.Fatal("historical envelope not readable")
	}
	fresh, err := ring.seal(m, secret)
	if err != nil || fresh.keyID != "current" {
		t.Fatal("active encryption key not used")
	}
	current, _ := NewKeyring("current", map[string]string{"current": newKey})
	if _, err = current.open(m, fresh); err != nil {
		t.Fatal("current envelope not readable")
	}
	if _, err = current.open(m, historical); !errors.Is(err, ErrSecret) {
		t.Fatal("missing historical key accepted")
	}
	wrong, _ := NewKeyring("old", map[string]string{"old": newKey})
	if _, err = wrong.open(m, historical); !errors.Is(err, ErrSecret) {
		t.Fatal("wrong historical key accepted")
	}
	// Even two IDs using the same key cannot bypass the authenticated key ID.
	alias, _ := NewKeyring("old", map[string]string{"old": oldKey, "alias": oldKey})
	historical.keyID = "alias"
	if _, err = alias.open(m, historical); !errors.Is(err, ErrSecret) {
		t.Fatal("tampered key identifier accepted")
	}
	for _, value := range []string{fmt.Sprintf("%#v", ring), fmt.Sprintf("%+v", *ring)} {
		if strings.Contains(value, oldKey) || strings.Contains(value, newKey) {
			t.Fatal("key leaked")
		}
	}
	data, err := json.Marshal(ring)
	if err != nil || string(data) != "{}" {
		t.Fatal("keyring exposed fields")
	}
	for _, tc := range []struct {
		id   string
		keys map[string]string
	}{
		{"missing", map[string]string{"old": oldKey}}, {"current", nil},
		{"current", map[string]string{"current": newKey, "bad id": oldKey}},
		{"current", map[string]string{"current": newKey, "old": "invalid"}},
	} {
		if _, err := NewKeyring(tc.id, tc.keys); !errors.Is(err, ErrKey) {
			t.Fatal("invalid keyring accepted")
		}
	}
}
