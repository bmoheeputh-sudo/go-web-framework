package authconfig

import (
	"context"
	"strings"
)

// PrepareRecoveryDraft copies historical immutable settings into a new draft.
// The existing cipher seals against a new revision ID/version with a fresh nonce.
// Approval, both readiness tests and explicit activation remain mandatory.
func (r *Repository) PrepareRecoveryDraft(ctx context.Context, historicalID string, expectedLatestVersion int64) (Metadata, error) {
	return r.prepareRecoveryDraft(ctx, historicalID, expectedLatestVersion, "")
}

// PrepareRecoveryDraftWithReason is used by the protected HTTP control plane.
// It records the administrator's confirmed reason in the same transaction as
// the immutable recovery draft. It never changes the active configuration.
func (r *Repository) PrepareRecoveryDraftWithReason(ctx context.Context, historicalID string, expectedLatestVersion int64, reason string) (Metadata, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 512 || strings.ContainsAny(reason, "\r\n\x00") {
		return Metadata{}, ErrInvalid
	}
	return r.prepareRecoveryDraft(ctx, historicalID, expectedLatestVersion, reason)
}

func (r *Repository) prepareRecoveryDraft(ctx context.Context, historicalID string, expectedLatestVersion int64, reason string) (Metadata, error) {
	historical, err := r.Read(ctx, historicalID)
	if err != nil {
		return Metadata{}, err
	}
	if historical.Status != Superseded {
		return Metadata{}, ErrConflict
	}
	secret, err := r.ReadSecretPrivileged(ctx, historicalID)
	if err != nil {
		return Metadata{}, err
	}
	defer clear(secret.value)
	return r.createDraft(ctx, expectedLatestVersion, historical.Settings, secret, historical.ID, reason)
}
