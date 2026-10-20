package authconfig

import "context"

// PrepareRecoveryDraft copies historical immutable settings into a new draft.
// The existing cipher seals against a new revision ID/version with a fresh nonce.
// Approval, both readiness tests and explicit activation remain mandatory.
func (r *Repository) PrepareRecoveryDraft(ctx context.Context, historicalID string, expectedLatestVersion int64) (Metadata, error) {
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
	return r.createDraft(ctx, expectedLatestVersion, historical.Settings, secret, historical.ID)
}
