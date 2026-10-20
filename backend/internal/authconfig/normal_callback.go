package authconfig

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

// NormalCallbackResult is internal, safe metadata only. There is no HTTP start
// or status API in this phase. A future admin UI must add its own protected adapter.
type NormalCallbackResult struct {
	mu       sync.Mutex
	evidence TestEvidence
}

func (r *NormalCallbackResult) Evidence() (TestEvidence, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evidence, r.evidence.ID != ""
}

// BeginNormalCallbackTest explicitly exercises the configured normal redirect
// URI with the candidate verifier, without sessions or a provider switch. The
// initiator is the existing verified administrator, rechecked on completion.
func (s *ActivationService) BeginNormalCallbackTest(p *PreparedActivation, w http.ResponseWriter, r *http.Request) (*NormalCallbackResult, error) {
	actor, ok := access.Principal(r.Context())
	if !ok || p == nil || p.service != s || actor.ID != p.actor || !time.Now().Before(p.expires) {
		return nil, ErrDenied
	}
	if _, err := s.repo.testTransaction(r.Context(), p.metadata.ID, p.metadata.Generation, "", "auth_config.normal_test_started", "checking", nil, nil); err != nil {
		return nil, err
	}
	original := context.WithoutCancel(r.Context())
	expires := time.Now().Add(5 * time.Minute)
	result := &NormalCallbackResult{}
	err := s.runtime.BeginReadiness(p.provider, w, r, func(callback context.Context, identity auth.Identity) error {
		ctx, cancel := context.WithTimeout(valueContext{callback, original}, 5*time.Second)
		defer cancel()
		if !time.Now().Before(expires) {
			return ErrConflict
		}
		now := time.Now()
		evidence, err := s.repo.recordTestEvidence(ctx, verifiedTestEvidence{revisionID: p.metadata.ID, revisionGeneration: p.metadata.Generation, identity: identity, purpose: NormalCallback, completedAt: now, expiresAt: now.Add(5 * time.Minute)})
		if err != nil {
			return err
		}
		result.mu.Lock()
		result.evidence = evidence
		result.mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}
