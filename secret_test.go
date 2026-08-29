package paymos

import (
	"strings"
	"testing"
)

func TestPackThenParseFullAndReadOnly(t *testing.T) {
	full, err := ParseSecret(PackSecret("vk_live_abc123", 42, `{"share":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if full.APIKey != "vk_live_abc123" || full.VaultID != 42 || !full.HasShare() {
		t.Fatalf("full = %+v", full)
	}

	read, err := ParseSecret(PackSecret("vk_live_abc123", 42, ""))
	if err != nil {
		t.Fatal(err)
	}
	if read.HasShare() || read.Share != "" {
		t.Fatalf("read-only secret carries a share: %+v", read)
	}
}

func TestRejectsAnythingThatIsNotAVaultSecret(t *testing.T) {
	for _, bad := range []string{"sk_prod_not_ours", "vk_test_dev_key", "", "vs_live_@@@"} {
		if _, err := ParseSecret(bad); err == nil {
			t.Fatalf("ParseSecret(%q) should have failed", bad)
		}
	}
}

func TestRejectsASecretWhoseAPIKeyIsNotOurs(t *testing.T) {
	if _, err := ParseSecret(PackSecret("nope", 1, "")); err == nil {
		t.Fatal("a secret without a vk_live_ key should fail")
	}
}

func TestNeverRendersTheShareAndMasksTheKey(t *testing.T) {
	s, err := ParseSecret(PackSecret("vk_live_abc123", 42, `{"share":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	rendered := s.String()
	if strings.Contains(rendered, `share":"x`) {
		t.Fatal("the share must never be rendered")
	}
	if strings.Contains(rendered, "abc123") {
		t.Fatal("the key must be masked")
	}
	if !strings.Contains(rendered, "vk_live_") {
		t.Fatal("the non-secret prefix is fine to show")
	}
}
