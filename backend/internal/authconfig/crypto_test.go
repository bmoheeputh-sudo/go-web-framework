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

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func testCipher(t *testing.T, id string) *Cipher {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("random key unavailable")
	}
	c, err := CipherFromEnv(func(name string) string {
		if name == "AUTH_ENCRYPTION_KEY_ID" {
			return id
		}
		if name == "AUTH_ENCRYPTION_KEY" {
			return base64.StdEncoding.EncodeToString(key[:])
		}
		return ""
	})
	clear(key[:])
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func testMetadata() Metadata {
	return Metadata{ID: "11111111-1111-4111-8111-111111111111", Scope: Scope{"test-installation", "development"}, Version: 1, CreatedBy: "22222222-2222-4222-8222-222222222222", Settings: Settings{Provider: auth.OIDC, IssuerURL: "https://issuer.example.test", ClientID: "test-client", RedirectURI: "https://app.example.test/api/auth/callback"}}
}
func TestEncryption(t *testing.T) {
	c := testCipher(t, "key-v1")
	m := testMetadata()
	secret := NewSecret([]byte("test-only-secret-never-log"))
	e, err := c.seal(m, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.open(m, e)
	if err != nil || !bytes.Equal(got.Bytes(), secret.Bytes()) {
		t.Fatal("encryption round trip failed")
	}
	seen := map[string]bool{}
	for range 100 {
		encrypted, err := c.seal(m, secret)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(encrypted.nonce)] {
			t.Fatal("repeated nonce")
		}
		seen[string(encrypted.nonce)] = true
		if bytes.Contains(encrypted.ciphertext, secret.value) {
			t.Fatal("plaintext ciphertext")
		}
	}
	t.Run("wrong key", func(t *testing.T) {
		if _, err := testCipher(t, "key-v1").open(m, e); !errors.Is(err, ErrSecret) {
			t.Fatal("wrong key accepted")
		}
	})
	for name, modify := range map[string]func(*encryptedSecret){
		"format": func(e *encryptedSecret) { e.format++ }, "key id": func(e *encryptedSecret) { e.keyID = "other" }, "nonce": func(e *encryptedSecret) { e.nonce[0] ^= 1 }, "ciphertext": func(e *encryptedSecret) { e.ciphertext[0] ^= 1 }, "tag": func(e *encryptedSecret) { e.ciphertext[len(e.ciphertext)-1] ^= 1 }, "short nonce": func(e *encryptedSecret) { e.nonce = nil }, "short ciphertext": func(e *encryptedSecret) { e.ciphertext = e.ciphertext[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			copy := e
			copy.nonce = bytes.Clone(e.nonce)
			copy.ciphertext = bytes.Clone(e.ciphertext)
			modify(&copy)
			if _, err := c.open(m, copy); !errors.Is(err, ErrSecret) {
				t.Fatal("invalid ciphertext accepted")
			}
		})
	}
	for name, modify := range map[string]func(*Metadata){
		"deployment": func(m *Metadata) { m.DeploymentID = "other" }, "environment": func(m *Metadata) { m.Environment = "production" }, "revision": func(m *Metadata) { m.ID = "33333333-3333-4333-8333-333333333333" }, "version": func(m *Metadata) { m.Version++ }, "creator": func(m *Metadata) { m.CreatedBy = "33333333-3333-4333-8333-333333333333" }, "issuer": func(m *Metadata) { m.IssuerURL += "/other" }, "client": func(m *Metadata) { m.ClientID = "other" }, "redirect": func(m *Metadata) { m.RedirectURI = "https://other.test/api/auth/callback" }, "audience": func(m *Metadata) { m.IAPAudience = "other" }, "provider": func(m *Metadata) { m.Provider = auth.GoogleIAP }, "http": func(m *Metadata) { m.AllowHTTPDevelopment = true },
	} {
		t.Run("metadata "+name, func(t *testing.T) {
			copy := m
			modify(&copy)
			if _, err := c.open(copy, e); !errors.Is(err, ErrSecret) {
				t.Fatal("tampered AAD accepted")
			}
		})
	}
	t.Run("redaction", func(t *testing.T) {
		for _, value := range []any{secret, &secret, c, &e, struct{ Secret Secret }{secret}} {
			for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
				if strings.Contains(fmt.Sprintf(format, value), string(secret.value)) {
					t.Fatal("secret leaked through formatting")
				}
			}
		}
		if _, err := json.Marshal(secret); err == nil {
			t.Fatal("secret is JSON serializable")
		}
		data, err := json.Marshal(m)
		if err != nil || bytes.Contains(data, secret.value) {
			t.Fatal("metadata leaks secret")
		}
	})
}
func TestEncryptionKeyValidation(t *testing.T) {
	var random [32]byte
	_, _ = rand.Read(random[:])
	valid := base64.StdEncoding.EncodeToString(random[:])
	clear(random[:])
	for _, encoded := range []string{"", "password", "%%%", valid + "\n", valid[:43], base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), base64.StdEncoding.EncodeToString(make([]byte, 16)), base64.StdEncoding.EncodeToString(make([]byte, 64))} {
		_, err := CipherFromEnv(func(name string) string {
			if name == "AUTH_ENCRYPTION_KEY_ID" {
				return "v1"
			}
			if name == "AUTH_ENCRYPTION_KEY" {
				return encoded
			}
			return ""
		})
		if !errors.Is(err, ErrKey) {
			t.Fatal("invalid or missing key accepted")
		}
		if strings.Contains(err.Error(), valid) {
			t.Fatal("key leaked in error")
		}
	}
	for _, id := range []string{"", "../bad", " bad", "key\n", strings.Repeat("a", 65)} {
		_, err := CipherFromEnv(func(name string) string {
			if name == "AUTH_ENCRYPTION_KEY_ID" {
				return id
			}
			if name == "AUTH_ENCRYPTION_KEY" {
				return valid
			}
			return ""
		})
		if !errors.Is(err, ErrKey) {
			t.Fatal("invalid key identifier accepted")
		}
	}
}

func TestAADFormatV1(t *testing.T) {
	// Synthetic, public metadata. This freezes the format against future Settings
	// additions silently making historical ciphertext undecryptable.
	want := `{"Purpose":"gwf.auth-config.oidc-client-secret","Format":1,"KeyID":"key-v1","DeploymentID":"test-installation","Environment":"development","RevisionID":"11111111-1111-4111-8111-111111111111","ConfigurationVersion":1,"Creator":"22222222-2222-4222-8222-222222222222","Provider":"oidc","IssuerURL":"https://issuer.example.test","ClientID":"test-client","RedirectURI":"https://app.example.test/api/auth/callback","IAPAudience":"","AllowHTTPDevelopment":false}`
	if string(aad(testMetadata(), 1, "key-v1")) != want {
		t.Fatal("format-v1 AAD changed")
	}
}

func TestCipherFromEnvMultipleKeys(t *testing.T) {
	oldBytes, newBytes := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(oldBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(newBytes); err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := base64.StdEncoding.EncodeToString(oldBytes), base64.StdEncoding.EncodeToString(newBytes)
	raw := `{"old":"` + oldKey + `","current":"` + newKey + `"}`
	env := map[string]string{"AUTH_ENCRYPTION_KEY_ID": "current", "AUTH_ENCRYPTION_KEYS_JSON": raw}
	get := func(k string) string { return env[k] }
	c, err := CipherFromEnv(get)
	if err != nil || c.keyID != "current" || len(c.keys) != 2 {
		t.Fatal("valid keyring rejected")
	}
	for _, bad := range []string{`{}`, `null`, `[]`, `{"old":"` + oldKey + `"}`, `{"current":null}`, `{"current":"` + newKey + `","current":"` + newKey + `"}`, raw + `{}`, `{"current":"invalid"}`} {
		env["AUTH_ENCRYPTION_KEYS_JSON"] = bad
		if _, err := CipherFromEnv(get); !errors.Is(err, ErrKey) {
			t.Fatal("malformed keyring accepted")
		}
	}
	env["AUTH_ENCRYPTION_KEYS_JSON"] = raw
	env["AUTH_ENCRYPTION_KEY"] = newKey
	if _, err := CipherFromEnv(get); !errors.Is(err, ErrKey) {
		t.Fatal("ambiguous key sources accepted")
	}
}
