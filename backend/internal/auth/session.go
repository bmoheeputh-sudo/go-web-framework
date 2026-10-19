package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	loginLifetime   = 10 * time.Minute
	sessionLifetime = 8 * time.Hour
)

type loginFlow struct {
	State, Nonce, Verifier string
	Expires                time.Time
}

type session struct {
	Identity Identity
	Expires  time.Time
}

// memoryStore is intentionally process-local and development-only. Sessions hold
// only public identity data, never OAuth tokens. Cookie IDs are stored as hashes.
// Production needs shared, persistent sessions AND shared one-use login state.
type memoryStore struct {
	mu       sync.Mutex
	sessions map[[32]byte]session
	flows    map[[32]byte]loginFlow
	limit    int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{sessions: make(map[[32]byte]session), flows: make(map[[32]byte]loginFlow), limit: 4096}
}

// prune runs under the lock. Expiration is also checked on every lookup; cleanup
// on insertion bounds memory without a background goroutine or shutdown lifecycle.
func (s *memoryStore) prune() {
	now := time.Now()
	for key, value := range s.sessions {
		if !now.Before(value.Expires) {
			delete(s.sessions, key)
		}
	}
	for key, value := range s.flows {
		if !now.Before(value.Expires) {
			delete(s.flows, key)
		}
	}
}

func (s *memoryStore) addFlow(flow loginFlow) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if len(s.flows) >= s.limit {
		return "", errors.New("login capacity reached")
	}
	id := oauth2.GenerateVerifier()
	s.flows[sha256.Sum256([]byte(id))] = flow
	return id, nil
}

// takeFlow atomically consumes the browser-bound transaction, even on failure.
// A state value alone is insufficient: the HttpOnly flow cookie is also required.
func (s *memoryStore) takeFlow(id, state string) (loginFlow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(id))
	flow, ok := s.flows[key]
	delete(s.flows, key)
	return flow, ok && time.Now().Before(flow.Expires) &&
		subtle.ConstantTimeCompare([]byte(flow.State), []byte(state)) == 1
}

func (s *memoryStore) addSession(identity Identity, expires time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if len(s.sessions) >= s.limit {
		return "", errors.New("session capacity reached")
	}
	id := oauth2.GenerateVerifier()
	s.sessions[sha256.Sum256([]byte(id))] = session{Identity: identity, Expires: expires}
	return id, nil
}

func (s *memoryStore) identity(id string) (Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(id))
	value, ok := s.sessions[key]
	if !ok || !time.Now().Before(value.Expires) {
		delete(s.sessions, key)
		return Identity{}, false
	}
	return value.Identity, true
}

func (s *memoryStore) deleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sha256.Sum256([]byte(id)))
}
