package authconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

func csvPreviewInput(e InvitationExpectation, csv string) CSVPreviewRequest {
	return CSVPreviewRequest{CSV: csv, ImportExpectation: ImportExpectation{e.Generation, e.ActivationGeneration, e.RevisionID, e.RevisionGeneration}}
}
func csvImportInput(p CSVPreview, input CSVPreviewRequest, id int) CSVImportRequest {
	input.ImportExpectation = p.ImportExpectation
	input.SelectedRows = p.SelectedRows
	input.ExpirationDays = p.ExpirationDays
	return CSVImportRequest{CSVPreviewRequest: input, ImportID: fmt.Sprintf("%08x-0000-4000-8000-000000000001", id), IdempotencyKey: fmt.Sprintf("%08x-0000-4000-8000-000000000002", id), PreviewDigest: p.PreviewDigest, PreviewExpiresAt: p.ExpiresAt, Reason: "approved bulk employee onboarding", Confirm: true}
}
func TestCSVParser(t *testing.T) {
	for _, contents := range []string{"email\na+tag@VOPAK.COM\n", "\ufeffemail,display_name\r\na@vopak.com,\"Name, One\"\r\n", "display_name,email\nEmployee,a@vopak.com\n"} {
		rows, err := parseInvitationCSV(contents)
		if err != nil || len(rows) != 1 || rows[0].Status != "ready" {
			t.Fatal("valid CSV rejected", err)
		}
	}
	for name, contents := range map[string]string{"utf8": "email\na@vopak.com," + string([]byte{0xff}), "quote": "email,display_name\na@vopak.com,\"unterminated", "extra": "email\na@vopak.com,Admin", "role": "email,role\na@vopak.com,Admin", "permission": "email,permission\na@vopak.com,admin.manage", "issuer": "email,issuer\na@vopak.com,issuer", "subject": "email,subject\na@vopak.com,subject", "duplicate header": "email,email\na@vopak.com,b@vopak.com", "unknown": "display_name\nEmployee"} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInvitationCSV(contents); !errors.Is(err, ErrCSVFormat) {
				t.Fatal("unsafe CSV accepted", err)
			}
		})
	}
	for name, contents := range map[string]string{"empty": "", "header only": "email\n"} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInvitationCSV(contents); !errors.Is(err, ErrCSVEmpty) {
				t.Fatal(err)
			}
		})
	}
	if _, err := parseInvitationCSV(strings.Repeat("a", CSVMaxBytes+1)); !errors.Is(err, ErrCSVSize) {
		t.Fatal("unbounded CSV", err)
	}
	if _, err := parseInvitationCSV("email\n" + strings.Repeat("a@vopak.com\n", 501)); !errors.Is(err, ErrCSVRows) {
		t.Fatal("unbounded rows", err)
	}
	rows, err := parseInvitationCSV("email,display_name\nEmployee@vopak.com,A\nemployee@VOPAK.COM,B\nfirst.last+tag@vopak.com,C\n,Blank\ninvalid,Name\na@vopak.com,\"Line\nbreak\"\n")
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range []string{"duplicate_csv", "duplicate_csv", "ready", "invalid_email", "invalid_email", "invalid_display_name"} {
		if rows[n].Status != want {
			t.Fatal("wrong classification", n, rows[n].Status)
		}
	}
	for _, raw := range []string{`{"csv":"\ud800"}`, `{"csv":"\udc00"}`, "{\"csv\":\"" + string([]byte{0xff}) + "\"}"} {
		if validJSONUnicode([]byte(raw)) {
			t.Fatal("invalid Unicode accepted")
		}
	}
	if !validJSONUnicode([]byte(`{"csv":"email,display_name\na@vopak.com,\ud83d\ude00"}`)) {
		t.Fatal("valid surrogate pair rejected")
	}
}
func TestCSVImportMeasured500(t *testing.T) {
	f, r, e := invitationFixture(t)
	var data strings.Builder
	data.WriteString("email,display_name\r\n")
	for n := 0; n < CSVMaxRows; n++ {
		fmt.Fprintf(&data, "employee%03d@vopak.com,Employee %d\r\n", n, n)
	}
	input := csvPreviewInput(e, data.String())
	f.run(t, func(ctx context.Context) {
		before := invitationState(t, f)
		p, err := r.PreviewInvitationCSV(ctx, input)
		if err != nil || p.Ready != 500 || p.WillCreate != 500 {
			t.Fatal("preview failed", err)
		}
		if invitationState(t, f) != before {
			t.Fatal("preview changed identity state")
		}
		var count int
		if err = f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.oidc_invitations`).Scan(&count); err != nil || count != 0 {
			t.Fatal("preview wrote invitations", err)
		}
		request := csvImportInput(p, input, 1)
		started := time.Now()
		result, err := r.ImportInvitationCSV(ctx, request)
		elapsed := time.Since(started)
		t.Logf("500-row import transaction including audits and receipt: %s", elapsed)
		if err != nil || result.Created != 500 || len(result.InvitationIDs) != 500 || result.Outcome != "completed" {
			t.Fatal("import failed", err)
		}
		if elapsed >= 4*time.Second {
			t.Fatal("500-row transaction lacks margin inside the existing five-second deadline", elapsed)
		}
		if invitationState(t, f) != before {
			t.Fatal("import changed users, approvals, roles, sessions or configuration")
		}
		again, err := r.ImportInvitationCSV(ctx, request)
		if err != nil || again.ID != result.ID || again.CompletedAt != result.CompletedAt {
			t.Fatal("identical retry failed", err)
		}
		if err = f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.oidc_invitations WHERE source='csv' AND import_id=$1`, result.ID).Scan(&count); err != nil || count != 500 {
			t.Fatal("duplicate/missing import", err, count)
		}
		receipt, err := r.ReadInvitationImport(ctx, result.ID)
		if err != nil || receipt.Created != 500 {
			t.Fatal("receipt unavailable", err)
		}
		raw, _ := json.Marshal(receipt)
		if strings.Contains(string(raw), "employee000") || strings.Contains(string(raw), request.IdempotencyKey) {
			t.Fatal("receipt retained raw CSV or idempotency material")
		}
		var totalAudits int
		if err = f.owner.QueryRow(ctx, `SELECT count(*) FROM framework.audit_log WHERE action='oidc_access.invitation_imported' AND target_id=$1`, result.ID).Scan(&totalAudits); err != nil || totalAudits != 1 {
			t.Fatal("duplicate/missing batch audit", err)
		}
		for _, change := range []func(*CSVImportRequest){func(i *CSVImportRequest) { i.Reason += " changed" }, func(i *CSVImportRequest) { i.CSV = strings.Replace(i.CSV, "Employee 0", "Changed 0", 1) }, func(i *CSVImportRequest) { i.ImportID = "11111111-1111-4111-8111-111111111111" }, func(i *CSVImportRequest) { i.SelectedRows = i.SelectedRows[:1] }} {
			altered := request
			change(&altered)
			if _, err := r.ImportInvitationCSV(ctx, altered); !errors.Is(err, ErrConflict) {
				t.Fatal("changed idempotent request accepted", err)
			}
		}
	})
}
func TestCSVPreviewClassificationsAndReadOnly(t *testing.T) {
	f, r, e := invitationFixture(t)
	policyUser(t, f, "review-inactive", "review@vopak.com", "User", false)
	f.run(t, func(ctx context.Context) {
		if _, err := r.CreateInvitation(ctx, e, invitationInput("pending@vopak.com")); err != nil {
			t.Fatal(err)
		}
		before := invitationState(t, f)
		var rowsBefore string
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(i) ORDER BY id)::text FROM framework.oidc_invitations i`).Scan(&rowsBefore); err != nil {
			t.Fatal(err)
		}
		p, err := r.PreviewInvitationCSV(ctx, csvPreviewInput(e, "email\nready@vopak.com\npending@vopak.com\nreview@vopak.com\noutside@other.test\nA@vopak.com\na@vopak.com\nbad\n"))
		if err != nil {
			t.Fatal(err)
		}
		for n, want := range []string{"ready", "existing_pending", "existing_user_review", "blocked_domain", "duplicate_csv", "duplicate_csv", "invalid_email"} {
			if p.Rows[n].Status != want {
				t.Fatal("classification", n, p.Rows[n].Status)
			}
		}
		if p.Ready != 1 || p.Invalid != 2 || p.Skipped != 4 || p.WillCreate != 1 {
			t.Fatal("incorrect counts", p.Ready, p.Invalid, p.Skipped)
		}
		stale := csvPreviewInput(e, "email\na@vopak.com\n")
		stale.PolicyGeneration++
		p, err = r.PreviewInvitationCSV(ctx, stale)
		if err != nil || p.Rows[0].Status != "stale_configuration_or_policy" || p.PreviewDigest != "" {
			t.Fatal("stale preview accepted", err)
		}
		var rowsAfter string
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(i) ORDER BY id)::text FROM framework.oidc_invitations i`).Scan(&rowsAfter); err != nil || rowsAfter != rowsBefore || invitationState(t, f) != before {
			t.Fatal("preview wrote records", err)
		}
	})
}
func TestCSVImportSelectionProofAndGenerations(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := csvPreviewInput(e, "email\na@vopak.com\nb@vopak.com\nbad\n")
		input.SelectedRows = []int{2}
		p, err := r.PreviewInvitationCSV(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		request := csvImportInput(p, input, 2)
		for _, change := range []func(*CSVImportRequest){func(i *CSVImportRequest) { i.SelectedRows = []int{} }, func(i *CSVImportRequest) { i.SelectedRows = []int{1, 1} }, func(i *CSVImportRequest) { i.SelectedRows = []int{3} }, func(i *CSVImportRequest) { i.SelectedRows = []int{4} }, func(i *CSVImportRequest) { i.SelectedRows = []int{1} }, func(i *CSVImportRequest) { i.CSV = strings.ReplaceAll(i.CSV, "a@", "c@") }, func(i *CSVImportRequest) { i.ExpirationDays = 30 }, func(i *CSVImportRequest) { i.PolicyGeneration++ }, func(i *CSVImportRequest) { i.ActivationGeneration++ }, func(i *CSVImportRequest) { i.RevisionGeneration++ }, func(i *CSVImportRequest) { i.RevisionID = "11111111-1111-4111-8111-111111111111" }, func(i *CSVImportRequest) { i.PreviewExpiresAt = time.Now().Add(-time.Minute) }, func(i *CSVImportRequest) { i.PreviewDigest = strings.Repeat("0", 64) }, func(i *CSVImportRequest) { i.Confirm = false }, func(i *CSVImportRequest) { i.Reason = "审核人" }} {
			altered := request
			change(&altered)
			if _, err := r.ImportInvitationCSV(ctx, altered); err == nil {
				t.Fatal("unreviewed/tampered import accepted")
			}
		}
		result, err := r.ImportInvitationCSV(ctx, request)
		if err != nil || result.Created != 1 || result.Skipped != 1 || result.Rejected != 1 {
			t.Fatal("selected import", err)
		}
		for _, sql := range []string{`UPDATE framework.oidc_invitation_imports SET reason='changed audit reason' WHERE id=$1`, `DELETE FROM framework.oidc_invitation_imports WHERE id=$1`} {
			if _, err = f.owner.Exec(ctx, sql, result.ID); err == nil {
				t.Fatal("receipt history mutable")
			}
		}
		if _, err = f.owner.Exec(ctx, `TRUNCATE framework.oidc_invitation_imports`); err == nil {
			t.Fatal("receipt truncate allowed")
		}
	})
}
func TestCSVImportConcurrentAndRollback(t *testing.T) {
	for _, failAudit := range []bool{false, true} {
		t.Run(fmt.Sprint(failAudit), func(t *testing.T) {
			f, r, e := invitationFixture(t)
			f.run(t, func(ctx context.Context) {
				input := csvPreviewInput(e, "email\na@vopak.com\nb@vopak.com\n")
				p, err := r.PreviewInvitationCSV(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
				request := csvImportInput(p, input, 3)
				if failAudit {
					if _, err = f.owner.Exec(ctx, `CREATE FUNCTION framework.reject_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='oidc_access.invitation_imported' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_import BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_import()`); err != nil {
						t.Fatal(err)
					}
				}
				var wg sync.WaitGroup
				results := make(chan error, 4)
				for n := 0; n < 4; n++ {
					wg.Add(1)
					go func() { defer wg.Done(); _, err := r.ImportInvitationCSV(ctx, request); results <- err }()
				}
				wg.Wait()
				close(results)
				for err := range results {
					if failAudit && err == nil || !failAudit && err != nil {
						t.Fatal("concurrent result", err)
					}
				}
				var invitations, receipts int
				if err = f.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM framework.oidc_invitations),(SELECT count(*) FROM framework.oidc_invitation_imports)`).Scan(&invitations, &receipts); err != nil {
					t.Fatal(err)
				}
				if failAudit && (invitations != 0 || receipts != 0) || !failAudit && (invitations != 2 || receipts != 1) {
					t.Fatal("partial or duplicate transaction", invitations, receipts)
				}
			})
		})
	}
}
func TestCSVImportCommitUncertainty(t *testing.T) {
	f, r, e := invitationFixture(t)
	trace := &invitationCommitLoss{}
	config := f.pool.Config()
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	uncertain, _ := NewAccessPolicyRepository(access.New(pool), f.repo.scope)
	f.run(t, func(ctx context.Context) {
		input := csvPreviewInput(e, "email\nuncertain@vopak.com\n")
		p, err := r.PreviewInvitationCSV(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		request := csvImportInput(p, input, 4)
		trace.armed.Store(true)
		receipt, err := uncertain.ImportInvitationCSV(ctx, request)
		if !errors.Is(err, ErrCommitUncertain) || receipt.ID != "" || trace.commits.Load() != 1 || trace.err != nil {
			t.Fatal("uncertain commit retried or exposed success", err)
		}
		receipt, err = r.ReadInvitationImport(ctx, request.ImportID)
		if err != nil || receipt.Created != 1 {
			t.Fatal("authoritative inspection failed", err)
		}
		sum := sha256.Sum256([]byte(input.CSV))
		if receipt.ContentDigest != fmt.Sprintf("%x", sum) {
			t.Fatal("receipt digest mismatch")
		}
	})
}
func TestCSVImportHTTP(t *testing.T) {
	f, r, e := invitationFixture(t)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	base := accessPolicyPath + "/invitations"
	input := csvPreviewInput(e, "email\nhttp@vopak.com\n")
	w := apiRequest(t, h, "POST", base+"/import/preview", input, 200)
	var p CSVPreview
	if json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatal("invalid preview response")
	}
	request := csvImportInput(p, input, 5)
	apiRequest(t, h, "POST", base+"/import", request, 200)
	apiRequest(t, h, "GET", base+"/imports/"+request.ImportID, nil, 200)
	filtered := apiRequest(t, h, "GET", base+"?import_id="+request.ImportID+"&limit=1", nil, 200)
	var page Invitations
	if json.Unmarshal(filtered.Body.Bytes(), &page) != nil || page.Total != 1 || page.Items[0].ImportID != request.ImportID {
		t.Fatal("import-filtered listing failed")
	}
	apiRequest(t, h, "GET", base+"?import_id=not-a-uuid", nil, 400)
	apiRequest(t, h, "GET", base+"?import_id="+request.ImportID+"&import_id="+request.ImportID, nil, 400)
	oversized := input
	oversized.CSV = strings.Repeat("a", CSVMaxBytes+1)
	apiRequest(t, h, "POST", base+"/import/preview", oversized, 413)

	apiRequest(t, h, "GET", base+"/imports/11111111-1111-4111-8111-111111111111", nil, 404)
	apiRequest(t, h, "GET", base+"/imports/not-a-uuid", nil, 400)
	for _, body := range []string{`{"csv":"email\na@vopak.com\n","role":"Admin"}`, `{"csv":"a","csv":"b"}`, `{"csv":"a","CSV":"b"}`, `{"csv":"\ud800"}`, `{} {}`} {
		req := httptest.NewRequest("POST", base+"/import/preview", strings.NewReader(body))
		req.Header.Set("Origin", apiOrigin)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != 400 {
			t.Fatal("unsafe JSON accepted", out.Code)
		}
	}
	u := policyUser(t, f, "csv-nonadmin", "user@vopak.com", "Viewer", true)
	denied := policyHTTP(f, r, fixedAuth{auth.Identity{Issuer: u.Issuer, Subject: u.Subject, Provider: auth.OIDC}})
	apiRequest(t, denied, "POST", base+"/import/preview", input, 403)
	apiRequest(t, denied, "POST", base+"/import", request, 403)
	apiRequest(t, denied, "GET", base+"/imports/"+request.ImportID, nil, 403)
	apiRequest(t, policyHTTP(f, r, nil), "POST", base+"/import/preview", input, 401)
	for _, headers := range [][2]string{{"https://untrusted.test", "application/json"}, {apiOrigin, "text/plain"}} {
		req := httptest.NewRequest("POST", base+"/import", strings.NewReader("{}"))
		req.Header.Set("Origin", headers[0])
		req.Header.Set("Content-Type", headers[1])
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != 403 {
			t.Fatal("write protection bypass")
		}
	}
}

func TestCSVImportBothModesAndClaimingRegression(t *testing.T) {
	for _, mode := range []string{"allow_all", "approved_users_only"} {
		t.Run(mode, func(t *testing.T) {
			a := newAdmissionFixture(t)
			a.changePolicy(t, mode, "User", []string{"example.test"})
			var request CSVImportRequest
			a.f.run(t, func(ctx context.Context) {
				current, err := a.policy.ListInvitations(ctx, "", "", 0, 1)
				if err != nil {
					t.Fatal(err)
				}
				e := InvitationExpectation{PolicyExpectation{current.PolicyGeneration, current.ActivationGeneration}, current.RevisionID, current.RevisionGeneration}
				input := csvPreviewInput(e, "email,display_name\ncsv-employee@example.test,CSV suggestion\ncsv-revoked@example.test,Revoked employee\n")
				p, err := a.policy.PreviewInvitationCSV(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
				request = csvImportInput(p, input, 10)
				before := invitationState(t, a.f)
				if _, err = a.policy.ImportInvitationCSV(ctx, request); err != nil {
					t.Fatal(err)
				}
				if invitationState(t, a.f) != before {
					t.Fatal("import granted roles or created users/approvals")
				}
			})
			sessionCookieFor(t, a.login(t, "csv-exact-employee", "csv-employee@example.test", true))
			a.approval(t, probeIssuer, "csv-revoked-subject", "approved", 0)
			a.approval(t, probeIssuer, "csv-revoked-subject", "revoked", 1)
			if !loginDenied(a.login(t, "csv-revoked-subject", "csv-revoked@example.test", true)) {
				t.Fatal("CSV bypassed exact revocation")
			}
			a.f.run(t, func(ctx context.Context) {
				p, err := a.policy.PreviewInvitationCSV(ctx, csvPreviewInput(InvitationExpectation{PolicyExpectation{request.PolicyGeneration, request.ActivationGeneration}, request.RevisionID, request.RevisionGeneration}, "email\ncsv-employee@example.test\n"))
				if err != nil || p.Rows[0].Status != "already_claimed" {
					t.Fatal("historical claim not recognized", err)
				}
				var role, display string
				if err = a.f.owner.QueryRow(ctx, `SELECT r.role,u.display_name FROM framework.users u JOIN framework.user_roles r ON r.user_id=u.id WHERE subject='csv-exact-employee'`).Scan(&role, &display); err != nil || role != "User" || display == "CSV suggestion" {
					t.Fatal("claim role/profile regression", err)
				}
			})
		})
	}
}
func TestCSVImportDatabaseRollbackAndExpiredReplacement(t *testing.T) {
	f, r, e := invitationFixture(t)
	f.run(t, func(ctx context.Context) {
		input := csvPreviewInput(e, "email\na@vopak.com\nb@vopak.com\n")
		p, err := r.PreviewInvitationCSV(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		request := csvImportInput(p, input, 11)
		if _, err = f.owner.Exec(ctx, `CREATE FUNCTION framework.reject_csv_row() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.email='b@vopak.com' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_csv_row BEFORE INSERT ON framework.oidc_invitations FOR EACH ROW EXECUTE FUNCTION framework.reject_csv_row()`); err != nil {
			t.Fatal(err)
		}
		if _, err = r.ImportInvitationCSV(ctx, request); err == nil {
			t.Fatal("partial CSV accepted")
		}
		var count int
		if err = f.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM framework.oidc_invitations)+(SELECT count(*) FROM framework.oidc_invitation_imports)+(SELECT count(*) FROM framework.audit_log WHERE action LIKE 'oidc_access.invitation_%')`).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial rows, audits or receipt survived", err)
		}
		if _, err = f.owner.Exec(ctx, `DROP TRIGGER reject_csv_row ON framework.oidc_invitations`); err != nil {
			t.Fatal(err)
		}
		var expiry time.Time
		if err = f.owner.QueryRow(ctx, `SELECT clock_timestamp()+interval '500 milliseconds'`).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		old, err := r.CreateInvitation(ctx, e, InvitationInput{Email: "a@vopak.com", Reason: "temporary reviewed invitation", ExpiresAt: &expiry})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(600 * time.Millisecond)
		input.ExpirationDays = 30
		p, err = r.PreviewInvitationCSV(ctx, input)
		if err != nil || p.Ready != 2 {
			t.Fatal("expired invitation not replaceable", err)
		}
		request = csvImportInput(p, input, 12)
		result, err := r.ImportInvitationCSV(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		historical, err := r.ReadInvitation(ctx, old.ID)
		if err != nil || historical.Status != "expired" || historical.Generation != 2 {
			t.Fatal("old invitation reset or not retired", err)
		}
		fresh, err := r.ReadInvitation(ctx, result.InvitationIDs[0])
		if err != nil || fresh.ID == old.ID || fresh.ExpiresAt.Sub(fresh.CreatedAt) > 30*24*time.Hour || fresh.ExpiresAt.Sub(fresh.CreatedAt) < 30*24*time.Hour-time.Second {
			t.Fatal("custom expiry or replacement provenance", err)
		}
		page, err := r.ListInvitations(ctx, "", "", 0, 20, result.ID)
		if err != nil || page.Total != 2 {
			t.Fatal("import filter failed", err)
		}
	})
}
func TestCSVImportScopeActorAndReceipts(t *testing.T) {
	f, r, e := invitationFixture(t)
	if _, err := r.PreviewInvitationCSV(context.Background(), csvPreviewInput(e, "email\na@vopak.com\n")); !errors.Is(err, ErrDenied) {
		t.Fatal("unverified preview accepted", err)
	}
	var request CSVImportRequest
	f.run(t, func(ctx context.Context) {
		input := csvPreviewInput(e, "email\na@vopak.com\n")
		p, err := r.PreviewInvitationCSV(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		request = csvImportInput(p, input, 13)
	})
	original := f.identity
	other := policyUser(t, f, "csv-other-admin", "other@vopak.com", "Admin", true)
	f.run(t, func(ctx context.Context) {
		if _, err := r.SetApproval(ctx, PolicyExpectation{e.Generation, e.ActivationGeneration}, OIDCIdentityKey{other.Issuer, other.Subject}, 0, "approved", "explicit second administrator approval"); err != nil {
			t.Fatal(err)
		}
	})
	f.identity = auth.Identity{Issuer: other.Issuer, Subject: other.Subject, Provider: auth.OIDC, Email: other.Email, EmailVerified: true}
	f.run(t, func(ctx context.Context) {
		if _, err := r.ImportInvitationCSV(ctx, request); !errors.Is(err, ErrConflict) {
			t.Fatal("preview crossed administrator", err)
		}
	})
	f.identity = original
	f.run(t, func(ctx context.Context) {
		result, err := r.ImportInvitationCSV(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		foreign, _ := NewAccessPolicyRepository(f.store, Scope{"another-installation", "development"})
		if _, err = foreign.ReadInvitationImport(ctx, result.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-scope receipt leaked", err)
		}
		if _, err = f.pool.Exec(ctx, `UPDATE framework.oidc_invitation_import_keys SET signing_key=decode(repeat('ab',32),'hex')`); err == nil {
			t.Fatal("runtime key update allowed")
		}
		if _, err = f.pool.Exec(ctx, `DELETE FROM framework.oidc_invitation_imports WHERE id=$1`, result.ID); err == nil {
			t.Fatal("runtime receipt deletion allowed")
		}
	})
}

func TestCSVBlankRowsAreNotSilentlySkipped(t *testing.T) {
	rows, err := parseInvitationCSV("email,display_name\r\n\r\na@vopak.com,Employee\r\n\n")
	if err != nil || len(rows) != 3 || rows[0].Status != "invalid_email" || rows[1].Status != "ready" || rows[2].Status != "invalid_email" {
		t.Fatal("blank email records were silently omitted", rows, err)
	}
}
