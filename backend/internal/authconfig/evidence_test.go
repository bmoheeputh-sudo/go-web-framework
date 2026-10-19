package authconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func TestDurableEvidence(t *testing.T) {
	f := newFixture(t)
	m := approvedRevision(t, f, 0)
	ctx := context.Background()
	reader, _ := NewActivationReader(f.pool, f.repo.scope)
	proof := func(p EvidencePurpose) verifiedTestEvidence {
		now := time.Now()
		return verifiedTestEvidence{
			revisionID: m.ID, revisionGeneration: m.Generation, identity: auth.Identity{Issuer: m.IssuerURL, Subject: "synthetic-tested-admin", Provider: auth.OIDC},
			purpose: p, completedAt: now, expiresAt: now.Add(time.Minute)}
	}
	record := func(p verifiedTestEvidence) TestEvidence {
		t.Helper()
		var result TestEvidence
		f.run(t, func(ctx context.Context) {
			var err error
			result, err = f.repo.recordTestEvidence(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
		})
		return result
	}
	first := record(proof(IsolatedConnection))
	second := record(proof(NormalCallback))
	if first.ID == second.ID || first.ActorUserID != m.CreatedBy {
		t.Fatal("evidence ID or verified actor incorrect")
	}
	t.Run("reads are scoped generation and purpose bound", func(t *testing.T) {
		got, err := reader.Evidence(ctx, second.ID, m.ID, m.Generation, NormalCallback)
		if err != nil || got.Subject != "synthetic-tested-admin" || got.VerificationVersion != 1 {
			t.Fatal("missing durable evidence")
		}
		if _, err := reader.Evidence(ctx, first.ID, m.ID, m.Generation, NormalCallback); !errors.Is(err, ErrNotFound) {
			t.Fatal("isolated proof qualified for activation")
		}
		if _, err := reader.Evidence(ctx, second.ID, m.ID, m.Generation+1, NormalCallback); !errors.Is(err, ErrNotFound) {
			t.Fatal("mismatched generation accepted")
		}
		if _, err := reader.Evidence(ctx, second.ID, "99999999-9999-4999-8999-999999999999", m.Generation, NormalCallback); !errors.Is(err, ErrNotFound) {
			t.Fatal("wrong revision accepted")
		}
		for _, scope := range []Scope{{"other", "development"}, {m.DeploymentID, "production"}} {
			other, _ := NewActivationReader(f.pool, scope)
			if _, err := other.Evidence(ctx, second.ID, m.ID, m.Generation, NormalCallback); !errors.Is(err, ErrNotFound) {
				t.Fatal("cross-scope evidence leaked")
			}
		}
	})
	t.Run("no arbitrary JSON proof and no unauthenticated write", func(t *testing.T) {
		var forged verifiedTestEvidence
		if err := json.Unmarshal([]byte(`{"revisionID":"`+m.ID+`","revisionGeneration":3,"purpose":"normal_callback","success":true}`), &forged); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.recordTestEvidence(ctx, forged); !errors.Is(err, ErrInvalid) {
			t.Fatal("forged JSON proof accepted")
		}
		if _, err := f.repo.recordTestEvidence(ctx, proof(NormalCallback)); !errors.Is(err, ErrDenied) {
			t.Fatal("missing principal accepted")
		}
	})
	t.Run("invalid proofs rejected", func(t *testing.T) {
		for name, edit := range map[string]func(*verifiedTestEvidence){
			"issuer":   func(p *verifiedTestEvidence) { p.identity.Issuer = "https://wrong.example.test" },
			"subject":  func(p *verifiedTestEvidence) { p.identity.Subject = "" },
			"provider": func(p *verifiedTestEvidence) { p.identity.Provider = auth.LocalDev },
			"future":   func(p *verifiedTestEvidence) { p.completedAt = time.Now().Add(time.Minute) },
			"expired": func(p *verifiedTestEvidence) {
				p.completedAt = time.Now().Add(-2 * time.Minute)
				p.expiresAt = time.Now().Add(-time.Minute)
			},
			"too long": func(p *verifiedTestEvidence) { p.expiresAt = p.completedAt.Add(6 * time.Minute) },
			"purpose":  func(p *verifiedTestEvidence) { p.purpose = "unknown" },
		} {
			t.Run(name, func(t *testing.T) {
				p := proof(NormalCallback)
				edit(&p)
				f.run(t, func(ctx context.Context) {
					if _, err := f.repo.recordTestEvidence(ctx, p); !errors.Is(err, ErrInvalid) {
						t.Fatal("invalid evidence accepted", err)
					}
				})
			})
		}
		f.run(t, func(ctx context.Context) {
			p := proof(NormalCallback)
			p.revisionGeneration++
			if _, err := f.repo.recordTestEvidence(ctx, p); !errors.Is(err, ErrConflict) {
				t.Fatal("stale revision accepted")
			}
		})
	})
	t.Run("evidence and audit atomic", func(t *testing.T) {
		var countBefore, auditBefore int
		if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM framework.auth_test_evidence),(SELECT count(*) FROM framework.audit_log WHERE action='auth_config.test_evidence_recorded')`).Scan(&countBefore, &auditBefore); err != nil {
			t.Fatal(err)
		}
		if countBefore != 2 || auditBefore != 2 {
			t.Fatal("missing atomic audit")
		}
		_, err := f.owner.Exec(ctx, `CREATE FUNCTION framework.fail_evidence_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='auth_config.test_evidence_recorded' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_evidence_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.fail_evidence_audit()`)
		if err != nil {
			t.Fatal(err)
		}
		f.run(t, func(ctx context.Context) {
			if _, err := f.repo.recordTestEvidence(ctx, proof(NormalCallback)); !errors.Is(err, ErrAudit) {
				t.Fatal("audit failure not returned")
			}
		})
		if _, err := f.owner.Exec(ctx, `DROP TRIGGER fail_evidence_audit ON framework.audit_log; DROP FUNCTION framework.fail_evidence_audit()`); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.auth_test_evidence`).Scan(&n); err != nil || n != countBefore {
			t.Fatal("failed audit persisted evidence")
		}
	})
	t.Run("immutable and duplicate evidence", func(t *testing.T) {
		for _, sql := range []string{`UPDATE framework.auth_test_evidence SET subject='forged'`, `DELETE FROM framework.auth_test_evidence`, `TRUNCATE framework.auth_test_evidence`, `INSERT INTO framework.auth_test_evidence SELECT * FROM framework.auth_test_evidence`} {
			if _, err := f.owner.Exec(ctx, sql); err == nil {
				t.Fatal("evidence mutation accepted")
			}
		}
	})
	t.Run("expired proof cannot qualify", func(t *testing.T) {
		p := proof(NormalCallback)
		p.expiresAt = p.completedAt.Add(300 * time.Millisecond)
		e := record(p)
		time.Sleep(350 * time.Millisecond)
		if _, err := reader.Evidence(ctx, e.ID, m.ID, m.Generation, NormalCallback); !errors.Is(err, ErrNotFound) {
			t.Fatal("expired evidence accepted")
		}
	})
	t.Run("authorization rechecked", func(t *testing.T) {
		f.run(t, func(ctx context.Context) {
			if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=false WHERE id=$1`, m.CreatedBy); err != nil {
				t.Fatal(err)
			}
			if _, err := f.repo.recordTestEvidence(ctx, proof(NormalCallback)); !errors.Is(err, ErrDenied) {
				t.Fatal("revoked administrator accepted")
			}
			if _, err := f.owner.Exec(ctx, `UPDATE framework.users SET active=true WHERE id=$1`, m.CreatedBy); err != nil {
				t.Fatal(err)
			}
		})
	})
	if err := activationFixture(t, f, m, 1, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Evidence(ctx, second.ID, m.ID, m.Generation, NormalCallback); !errors.Is(err, ErrNotFound) {
		t.Fatal("proof reused after revision transition")
	}
}
