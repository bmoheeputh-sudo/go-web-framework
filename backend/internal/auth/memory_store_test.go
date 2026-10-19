package auth

// This test double is never compiled into the application. Production has no
// in-memory session fallback when PostgreSQL is unavailable.
import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type testSession struct {
	Identity Identity
	Expires  time.Time
}
type memoryStore struct {
	mu       sync.Mutex
	sessions map[[32]byte]testSession
	flows    map[[32]byte]loginFlow
}

func newMemoryStore() *memoryStore {
	return &memoryStore{sessions: make(map[[32]byte]testSession), flows: make(map[[32]byte]loginFlow)}
}
func (s *memoryStore) addSession(_ context.Context, identity Identity, expires time.Time, previous string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := oauth2.GenerateVerifier()
	delete(s.sessions, sha256.Sum256([]byte(previous)))
	s.sessions[sha256.Sum256([]byte(token))] = testSession{identity, expires}
	return token, nil
}
func (s *memoryStore) identity(_ context.Context, token string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[sha256.Sum256([]byte(token))]
	if !ok || !time.Now().Before(value.Expires) {
		return Identity{}, ErrUnauthenticated
	}
	return value.Identity, nil
}
func (s *memoryStore) deleteSession(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sha256.Sum256([]byte(token)))
	return nil
}
func (s *memoryStore) addFlow(_ context.Context, flow loginFlow) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := oauth2.GenerateVerifier()
	s.flows[sha256.Sum256([]byte(token))] = flow
	return token, nil
}
func (s *memoryStore) takeFlow(_ context.Context, token, state string) (loginFlow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	flow, ok := s.flows[key]
	delete(s.flows, key)
	if !ok || !time.Now().Before(flow.Expires) || subtle.ConstantTimeCompare([]byte(flow.State), []byte(state)) != 1 {
		return loginFlow{}, ErrUnauthenticated
	}
	return flow, nil
}

func testSessionConfig() SessionConfig {
	return SessionConfig{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 8 * time.Hour}
}
