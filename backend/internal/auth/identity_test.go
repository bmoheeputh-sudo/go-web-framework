package auth

import "testing"

func TestIdentityValidation(t *testing.T) {
	valid := Identity{
		Issuer: "https://identity.example.invalid", Subject: "stable-user-id",
		Email: "developer@example.invalid", DisplayName: "Example Developer", Provider: OIDC,
	}
	tests := []struct {
		name      string
		change    func(*Identity)
		wantError bool
	}{
		{"valid", func(*Identity) {}, false},
		{"verified email", func(i *Identity) { i.EmailVerified = true }, false},
		{"optional profile", func(i *Identity) { i.Email = ""; i.DisplayName = "" }, false},
		{"retired IAP", func(i *Identity) { i.Provider = "google_iap" }, true},
		{"local", func(i *Identity) { i.Provider = LocalDev; i.Issuer = LocalDevIssuer }, false},
		{"no issuer", func(i *Identity) { i.Issuer = "" }, true},
		{"no subject", func(i *Identity) { i.Subject = "" }, true},
		{"blank subject", func(i *Identity) { i.Subject = " " }, true},
		{"padded issuer", func(i *Identity) { i.Issuer += " " }, true},
		{"control character", func(i *Identity) { i.Subject = "user\nadmin" }, true},
		{"invalid email", func(i *Identity) { i.Email = "not-an-email" }, true},
		{"email display syntax", func(i *Identity) { i.Email = "User <user@example.invalid>" }, true},
		{"verified without email", func(i *Identity) { i.Email = ""; i.EmailVerified = true }, true},
		{"no provider", func(i *Identity) { i.Provider = "" }, true},
		{"unknown provider", func(i *Identity) { i.Provider = "other" }, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := valid
			test.change(&identity)
			if err := identity.Validate(); (err != nil) != test.wantError {
				t.Fatalf("Validate() = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
