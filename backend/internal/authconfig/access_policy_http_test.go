package authconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"golang.org/x/oauth2"
)

func policyHTTP(f *fixture, r *AccessPolicyRepository, provider auth.Authenticator) http.Handler {
	mux := http.NewServeMux()
	RegisterAccessPolicy(mux, provider, f.store, apiOrigin, r)
	return mux
}
func policyBody(mode, role string, domains []string, generation int64) map[string]any {
	return map[string]any{"mode": mode, "default_role": role, "allowed_email_domains": domains, "expected_policy_generation": generation, "expected_activation_generation": 1, "reason": "explicit policy administration"}
}
func approvalBody(policy, generation int64) map[string]any {
	return map[string]any{"expected_policy_generation": policy, "expected_activation_generation": 1, "expected_approval_generation": generation, "reason": "explicit identity approval decision"}
}
func policyUser(t *testing.T, f *fixture, subject, email, role string, active bool) access.User {
	t.Helper()
	u, err := f.store.Resolve(context.Background(), auth.Identity{Issuer: f.identity.Issuer, Subject: subject, Provider: auth.OIDC, Email: email, EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.user_roles VALUES($1,$2);`, u.ID, role); err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(context.Background(), `UPDATE framework.users SET active=$2 WHERE id=$1`, u.ID, active); err != nil {
		t.Fatal(err)
	}
	return u
}
func TestAccessPolicyHTTPManagement(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	user := policyUser(t, f, "approved-target", "user@vopak.com", "Viewer", true)
	other := policyUser(t, f, "inactive-target", "inactive@vopak.com", "User", false)
	apiRequest(t, h, "GET", accessPolicyPath, nil, 200)
	apiRequest(t, h, "GET", accessPolicyPath+"/overview", nil, 200)
	response := apiRequest(t, h, "GET", accessPolicyPath+"/approvals?search=approved-target&offset=0&limit=1", nil, 200)
	var page AccessIdentities
	if json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ApprovalStatus != "not_approved" || page.Items[0].Email != "user@vopak.com" {
		t.Fatal("incorrect identity listing")
	}
	apiRequest(t, h, "GET", accessPolicyPath+"/approvals?limit=1&offset=1", nil, 200)
	for _, raw := range []string{"?limit=0", "?search=a&search=b", "?offset=-1", "?deployment_id=other", "?status=invalid"} {
		apiRequest(t, h, "GET", accessPolicyPath+"/approvals"+raw, nil, 400)
	}
	path := accessPolicyPath + "/approvals/" + user.ID
	apiRequest(t, h, "POST", path+"/approve", approvalBody(1, 0), 200)
	apiRequest(t, h, "GET", path, nil, 200)
	apiRequest(t, h, "POST", path+"/approve", approvalBody(1, 0), 409)
	response = apiRequest(t, h, "GET", accessPolicyPath+"/approvals?status=approved", nil, 200)
	if json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Total != 2 {
		t.Fatal("approval counts/filter")
	}
	// Inactive users may have approval, but approval never reactivates them or changes roles.
	apiRequest(t, h, "POST", accessPolicyPath+"/approvals/"+other.ID+"/approve", approvalBody(1, 0), 200)
	var active bool
	var roles []string
	if err := f.owner.QueryRow(context.Background(), `SELECT active,ARRAY(SELECT role FROM framework.user_roles WHERE user_id=u.id) FROM framework.users u WHERE id=$1`, other.ID).Scan(&active, &roles); err != nil || active || strings.Join(roles, ",") != "User" {
		t.Fatal("approval elevated or reactivated user", err)
	}
	forged := approvalBody(1, 1)
	forged["issuer"] = "https://forged.test"
	apiRequest(t, h, "POST", path+"/revoke", forged, 400)
	apiRequest(t, h, "POST", accessPolicyPath+"/approvals/not-a-uuid/approve", approvalBody(1, 0), 400)
	apiRequest(t, h, "POST", accessPolicyPath+"/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/approve", approvalBody(1, 0), 404)
	hash := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at) VALUES($1,$2,$3,'oidc',clock_timestamp()+interval '1 hour')`, hash[:], user.Issuer, user.Subject); err != nil {
		t.Fatal(err)
	}
	apiRequest(t, h, "POST", path+"/revoke", approvalBody(1, 1), 200)
	var count int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions WHERE subject=$1`, user.Subject).Scan(&count); err != nil || count != 0 {
		t.Fatal("revocation retained session")
	}
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.audit_log WHERE action='oidc_access.approval_changed'`).Scan(&count); err != nil || count != 3 {
		t.Fatal("approval audit missing", err, count)
	}
	// The only eligible administrator cannot revoke their own approval.
	var adminID string
	if err := f.owner.QueryRow(context.Background(), `SELECT id::text FROM framework.users WHERE subject=$1`, f.identity.Subject).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	response = apiRequest(t, h, "POST", accessPolicyPath+"/approvals/"+adminID+"/revoke", approvalBody(1, 1), 409)
	if !strings.Contains(response.Body.String(), "access_policy_last_oidc_administrator") {
		t.Fatal("unsafe error mapping")
	}
}
func TestAccessPolicyHTTPPreviewAndConflicts(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	policyUser(t, f, "outside", "outside@other.test", "User", true)
	body := policyBody("allow_all", "User", []string{}, 1)
	apiRequest(t, h, "POST", accessPolicyPath+"/preview", body, 200)
	apiRequest(t, h, "PUT", accessPolicyPath, body, 200)
	for _, bad := range []map[string]any{policyBody("allow_all", "Admin", []string{}, 2), policyBody("allow_all", "Viewer", []string{"*.vopak.com"}, 2), policyBody("unknown", "Viewer", []string{}, 2)} {
		apiRequest(t, h, "PUT", accessPolicyPath, bad, 400)
	}
	apiRequest(t, h, "PUT", accessPolicyPath, body, 409)
	restrictive := policyBody("approved_users_only", "Viewer", []string{"vopak.com"}, 2)
	before := policyExistingState(t, f)
	response := apiRequest(t, h, "POST", accessPolicyPath+"/preview", restrictive, 200)
	var p PolicyPreview
	if json.Unmarshal(response.Body.Bytes(), &p) != nil || p.AffectedUsers != 1 || !p.CanApply || p.CurrentAdministratorLosesAccess {
		t.Fatal("incorrect impact preview", response.Body.String())
	}
	if policyExistingState(t, f) != before {
		t.Fatal("preview wrote data")
	}
	// Restriction revokes credentials rather than allowing later policy relaxation to resurrect them.
	hash := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.sessions(token_hash,issuer,subject,email,email_verified,provider,expires_at) VALUES($1,$2,'outside','outside@other.test',true,'oidc',clock_timestamp()+interval '1 hour')`, hash[:], f.identity.Issuer); err != nil {
		t.Fatal(err)
	}
	apiRequest(t, h, "PUT", accessPolicyPath, restrictive, 200)
	var sessions int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions WHERE subject='outside'`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("restrictive update retained sessions")
	}
	blocked := policyBody("approved_users_only", "Viewer", []string{"other.test"}, 3)
	response = apiRequest(t, h, "POST", accessPolicyPath+"/preview", blocked, 200)
	if json.Unmarshal(response.Body.Bytes(), &p) != nil || p.CanApply || !p.CurrentAdministratorLosesAccess {
		t.Fatal("unsafe preview")
	}
	apiRequest(t, h, "PUT", accessPolicyPath, blocked, 409)
	// Preview cannot authorize a later write after the generation changes.
	apiRequest(t, h, "POST", accessPolicyPath+"/preview", restrictive, 409)
}
func TestAccessPolicyHTTPAuthorizationAndSetup(t *testing.T) {
	f, r := policyFixture(t)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	apiRequest(t, h, "GET", accessPolicyPath, nil, 404)
	var count int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.oidc_access_policies`).Scan(&count); err != nil || count != 0 {
		t.Fatal("HTTP silently bootstrapped")
	}
	bootstrapPolicy(t, f, r)
	for _, role := range []string{"User", "Viewer"} {
		u := policyUser(t, f, "non-admin-"+role, "user@vopak.com", role, true)
		f.run(t, func(ctx context.Context) {
			if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, OIDCIdentityKey{u.Issuer, u.Subject}, 0, "approved", "approve ordinary test identity"); err != nil {
				t.Fatal(err)
			}
		})
		denied := policyHTTP(f, r, fixedAuth{auth.Identity{Issuer: u.Issuer, Subject: u.Subject, Email: u.Email, EmailVerified: true, Provider: auth.OIDC}})
		for _, method := range []string{"GET", "PUT"} {
			apiRequest(t, denied, method, accessPolicyPath, policyBody("allow_all", "Viewer", []string{}, 1), 403)
		}
	}
	apiRequest(t, policyHTTP(f, r, nil), "GET", accessPolicyPath, nil, 401)
	req := httptest.NewRequest("PUT", accessPolicyPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://untrusted.test")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != 403 {
		t.Fatal("origin bypass")
	}
	req = httptest.NewRequest("PUT", accessPolicyPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", apiOrigin)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != 403 {
		t.Fatal("JSON protection bypass")
	}
}
func TestAccessPolicyHTTPSelfLossRequiresConfirmation(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	other := policyUser(t, f, "other-admin", "admin@other.test", "Admin", true)
	f.run(t, func(ctx context.Context) {
		if _, err := r.SetApproval(ctx, PolicyExpectation{1, 1}, OIDCIdentityKey{other.Issuer, other.Subject}, 0, "approved", "explicit alternate admin approval"); err != nil {
			t.Fatal(err)
		}
	})
	body := policyBody("allow_all", "Viewer", []string{"other.test"}, 1)
	apiRequest(t, h, "PUT", accessPolicyPath, body, 409)
	body["confirm_access_loss"] = true
	apiRequest(t, h, "PUT", accessPolicyPath, body, 200)
	apiRequest(t, h, "GET", accessPolicyPath, nil, 403)
}

func TestAccessPolicyHTTPInitialRevocationAndAuditRollback(t *testing.T) {
	f, r := policyFixture(t)
	bootstrapPolicy(t, f, r)
	h := policyHTTP(f, r, fixedAuth{f.identity})
	user := policyUser(t, f, "allow-all-user", "user@vopak.com", "Viewer", true)
	apiRequest(t, h, "PUT", accessPolicyPath, policyBody("allow_all", "Viewer", []string{}, 1), 200)
	hash := sha256.Sum256([]byte(oauth2.GenerateVerifier()))
	if _, err := f.owner.Exec(context.Background(), `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at) VALUES($1,$2,$3,'oidc',clock_timestamp()+interval '1 hour')`, hash[:], user.Issuer, user.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(context.Background(), `CREATE FUNCTION framework.reject_access_api_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='oidc_access.approval_changed' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_access_api_audit BEFORE INSERT ON framework.audit_log FOR EACH ROW EXECUTE FUNCTION framework.reject_access_api_audit()`); err != nil {
		t.Fatal(err)
	}
	before := policyExistingState(t, f)
	path := accessPolicyPath + "/approvals/" + user.ID + "/revoke"
	apiRequest(t, h, "POST", path, approvalBody(2, 0), 503)
	if policyExistingState(t, f) != before {
		t.Fatal("audit failure left approval/session changes")
	}
	if _, err := f.owner.Exec(context.Background(), `DROP TRIGGER reject_access_api_audit ON framework.audit_log`); err != nil {
		t.Fatal(err)
	}
	apiRequest(t, h, "POST", path, approvalBody(2, 0), 200)
	var status string
	var sessions int
	if err := f.owner.QueryRow(context.Background(), `SELECT status,(SELECT count(*) FROM framework.sessions WHERE subject=$1) FROM framework.oidc_identity_approvals WHERE subject=$1`, user.Subject).Scan(&status, &sessions); err != nil || status != "revoked" || sessions != 0 {
		t.Fatal("initial denial did not revoke access", err)
	}
}
