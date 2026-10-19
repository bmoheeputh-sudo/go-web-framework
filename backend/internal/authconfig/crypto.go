// Package authconfig stores future authentication settings. It is deliberately
// not connected to provider startup, HTTP endpoints, or the running auth session.
package authconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

var (
	ErrKey    = errors.New("auth_config_invalid_encryption_key")
	ErrCrypto = errors.New("auth_config_encryption_failed")
	ErrSecret = errors.New("auth_config_secret_unavailable")
)
var keyIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// Secret is never serializable or printable. Bytes is an explicit trusted-code
// escape hatch; callers must not log, persist, or return the revealed plaintext.
type Secret struct{ value []byte }

func NewSecret(value []byte) Secret         { return Secret{value: append([]byte(nil), value...)} }
func (s Secret) Bytes() []byte              { return append([]byte(nil), s.value...) }
func (Secret) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "[REDACTED]") }
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrSecret }

type encryptedSecret struct {
	format            int
	keyID             string
	nonce, ciphertext []byte
}

func (encryptedSecret) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[ENCRYPTED]") }

type Cipher struct {
	keyID string
	aead  cipher.AEAD
}

func (*Cipher) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[REDACTED]") }

// Encoding is canonical padded RFC 4648 standard base64, exactly 32 decoded
// bytes. Random origin is an operator requirement; entropy cannot be proved by
// inspecting a key. Reject trivially constant keys as an additional guard.
func CipherFromEnv(getenv func(string) string) (*Cipher, error) {
	encoded, id := getenv("AUTH_ENCRYPTION_KEY"), getenv("AUTH_ENCRYPTION_KEY_ID")
	if len(encoded) != 44 || !keyIdentifier.MatchString(id) {
		return nil, ErrKey
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, ErrKey
	}
	defer clear(key)
	constant := true
	for _, b := range key[1:] {
		if b != key[0] {
			constant = false
		}
	}
	if constant {
		return nil, ErrKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKey
	}
	return &Cipher{keyID: id, aead: aead}, nil
}

// AAD binds purpose, envelope metadata, deployment, immutable revision identity
// and ALL non-secret configuration settings. JSON field order is format-v1's
// fixed struct order. Lifecycle state is intentionally excluded.
func aad(metadata Metadata, format int, keyID string) []byte {
	// Keep this explicit v1 structure frozen; extending Settings must not alter
	// historical ciphertext authentication. New AAD layouts need a new format.
	value := struct {
		Purpose              string
		Format               int
		KeyID                string
		DeploymentID         string
		Environment          string
		RevisionID           string
		ConfigurationVersion int64
		Creator              string
		Provider             string
		IssuerURL            string
		ClientID             string
		RedirectURI          string
		IAPAudience          string
		AllowHTTPDevelopment bool
	}{"gwf.auth-config.oidc-client-secret", format, keyID, metadata.DeploymentID, metadata.Environment, metadata.ID, metadata.Version, metadata.CreatedBy,
		string(metadata.Provider), metadata.IssuerURL, metadata.ClientID, metadata.RedirectURI, metadata.IAPAudience, metadata.AllowHTTPDevelopment}

	data, _ := json.Marshal(value) // Struct contains only supported scalar values.
	return data
}
func (c *Cipher) seal(metadata Metadata, secret Secret) (encryptedSecret, error) {
	if c == nil || c.aead == nil || len(secret.value) == 0 || len(secret.value) > 4096 {
		return encryptedSecret{}, ErrCrypto
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedSecret{}, ErrCrypto
	}
	encrypted := c.aead.Seal(nil, nonce, secret.value, aad(metadata, 1, c.keyID))
	return encryptedSecret{1, c.keyID, nonce, encrypted}, nil
}
func (c *Cipher) open(metadata Metadata, encrypted encryptedSecret) (Secret, error) {
	if c == nil || c.aead == nil || encrypted.format != 1 || encrypted.keyID != c.keyID || len(encrypted.nonce) != 12 || len(encrypted.ciphertext) < 17 || len(encrypted.ciphertext) > 4112 {
		return Secret{}, ErrSecret
	}
	plaintext, err := c.aead.Open(nil, encrypted.nonce, encrypted.ciphertext, aad(metadata, encrypted.format, encrypted.keyID))
	if err != nil {
		return Secret{}, ErrSecret
	}
	return Secret{value: plaintext}, nil
}
