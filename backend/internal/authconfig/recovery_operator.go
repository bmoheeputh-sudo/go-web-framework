package authconfig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sync"
)

var recoveryOperatorID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{2,127}$`)

// OfflineOperator is an environment-provisioned break-glass capability. Its
// fields are private so request/flag data cannot manufacture an operator.
type OfflineOperator struct {
	mu          *sync.Mutex
	id, keyID   string
	key         []byte
	fingerprint [32]byte
	closed      bool
}

func (OfflineOperator) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[OFFLINE RECOVERY OPERATOR]")
}

func OfflineOperatorFromEnv(getenv func(string) string) (*OfflineOperator, error) {
	if getenv == nil || getenv("AUTH_RECOVERY_ENABLED") != "true" {
		return nil, ErrDenied
	}
	id, keyID, encoded := getenv("AUTH_RECOVERY_OPERATOR_ID"), getenv("AUTH_RECOVERY_AUTHORIZATION_KEY_ID"), getenv("AUTH_RECOVERY_AUTHORIZATION_KEY")
	if !recoveryOperatorID.MatchString(id) || !keyIdentifier.MatchString(keyID) || len(encoded) != 44 || encoded == getenv("AUTH_ENCRYPTION_KEY") {
		return nil, ErrDenied
	}
	if raw := getenv("AUTH_ENCRYPTION_KEYS_JSON"); raw != "" {
		var encryptionKeys map[string]string
		if json.Unmarshal([]byte(raw), &encryptionKeys) != nil {
			return nil, ErrDenied
		}
		for _, encryptionKey := range encryptionKeys {
			if hmac.Equal([]byte(encryptionKey), []byte(encoded)) {
				return nil, ErrDenied
			}
		}
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return nil, ErrDenied
	}
	constant := true
	for _, value := range key[1:] {
		if value != key[0] {
			constant = false
		}
	}
	if constant {
		clear(key)
		return nil, ErrDenied
	}
	return &OfflineOperator{mu: &sync.Mutex{}, id: id, keyID: keyID, key: key, fingerprint: sha256.Sum256(key)}, nil
}

func (o *OfflineOperator) Close() {
	if o != nil {
		if o.mu == nil {
			return
		}
		o.mu.Lock()
		if !o.closed {
			clear(o.key)
			o.closed = true
		}
		o.mu.Unlock()
	}
}

func (o *OfflineOperator) available() bool {
	if o == nil || o.mu == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.closed && len(o.key) == 32
}

type recoveryAuthorization struct {
	nonce, tag []byte
}

func (o *OfflineOperator) authorize(eventID string, scope Scope, expected int64, target, source, reason string) (recoveryAuthorization, error) {
	if o == nil || o.mu == nil || !validID(eventID) || !scope.valid() || expected < 1 || !validID(target) || !validID(source) || target == source {
		return recoveryAuthorization{}, ErrDenied
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || len(o.key) != 32 {
		return recoveryAuthorization{}, ErrDenied
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return recoveryAuthorization{}, ErrUnavailable
	}
	payload, _ := json.Marshal(struct {
		Purpose, EventID, Deployment, Environment, Operator, KeyID, Target, Source, Reason string
		ExpectedGeneration                                                                 int64
	}{"gwf.offline-auth-recovery.v1", eventID, scope.DeploymentID, scope.Environment, o.id, o.keyID, target, source, reason, expected})
	mac := hmac.New(sha256.New, o.key)
	_, _ = mac.Write(nonce)
	_, _ = mac.Write(payload)
	return recoveryAuthorization{nonce: nonce, tag: mac.Sum(nil)}, nil
}
