package paymos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
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

// Every printer a log line reaches for — every fmt verb, %+v and %#v included, encoding/json, both
// slog handlers — on the secret, the wallet, or a struct of the caller's holding them.
func TestNoPrinterRendersTheSecretOrTheWallet(t *testing.T) {
	packed := PackSecret("vk_live_abc123", 42, `{"share":"x"}`)
	s, err := ParseSecret(packed)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWallet(packed, "https://vault.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	type job struct {
		Wallet *Wallet
		Secret VaultSecret
		Ptr    *VaultSecret
		wallet *Wallet // unexported: printed by reflection as an address
	}
	held := job{Wallet: w, Secret: s, Ptr: &s, wallet: w}
	// A copy of the Wallet struct itself, taken without vet's copylocks objecting: its secret is a
	// pointer, so reflection prints an address, never the fields.
	walletCopy := reflect.ValueOf(w).Elem().Interface()

	var rendered []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, v := range []any{s, &s, w, held, &held, walletCopy} {
			rendered = append(rendered, fmt.Sprintf(verb, v))
		}
	}
	rendered = append(rendered, fmt.Sprint(s, w), fmt.Sprintln(held))
	for _, v := range []any{s, &s, w, held} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		rendered = append(rendered, string(b))
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("job", "secret", s, "wallet", w, "held", held)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("job", "secret", s, "wallet", w, "held", held)
	rendered = append(rendered, logs.String())

	for _, r := range rendered {
		if strings.Contains(r, "abc123") || strings.Contains(r, `share":"x`) || strings.Contains(r, `share\":\"x`) {
			t.Errorf("a printer leaked the secret: %s", r)
		}
	}
	if got := fmt.Sprintf("%+v", w); got != "Wallet(vaultId=42, hasShare=true, apiKey=vk_live_…, baseURL=https://vault.test)" {
		t.Errorf("%%+v of a wallet = %s", got)
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
