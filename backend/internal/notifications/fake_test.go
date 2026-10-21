package notifications

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestTemplateContract(t *testing.T) {
	template, err := NewTemplate("https://vgca.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"en", "nl", "fr", "es", "pt-BR", "zh-CN", "id", "ms", "th", "vi", "hi", "ar"} {
		m, err := template.Render("invitation", TemplateVersion, locale, "sender@example.test", "recipient@example.test", "<script>alert(1)</script>", "vgca.11111111-1111-4111-8111-111111111111")
		if err != nil || strings.Contains(m.HTML(), "<script>") || !strings.Contains(m.Text(), "https://vgca.example.test/api/auth/login") || strings.Contains(fmt.Sprint(m), "recipient@example.test") {
			t.Fatal("unsafe template", err)
		}
	}
	for _, origin := range []string{"http://vgca.example.test", "https://user:pass@vgca.example.test", "https://vgca.example.test/?next=evil", "https://vgca.example.test#x"} {
		if _, err := NewTemplate(origin); err == nil {
			t.Fatal("unsafe URL")
		}
	}
	if _, err := template.Render("invitation", TemplateVersion, "en", "sender@example.test", "recipient@example.test", "Name\r\nBcc: victim@example.test", "vgca.11111111-1111-4111-8111-111111111111"); err == nil {
		t.Fatal("header controls accepted")
	}
	for _, p := range []string{"gmail", "ses"} {
		f := NewFake(p, Result{Outcome: Accepted, ProviderMessageID: "fake-id"})
		if f.Provider() != p || f.Send(context.Background(), Message{}).Outcome != Accepted {
			t.Fatal("fake adapter")
		}
	}
}
