// The blind-sign guard, case by case, with the same refusals as Python's
// _verify_signing_disclosure: a package that does not bind to the disclosed message, anything but
// a single transfer, a transfer from another vault, of another token, of an amount that is not a
// positive integer, or sources that move more than the approved debit — each one refused before a
// share exists.

package paymos

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const (
	guardSigner    = "ab12cd34"
	guardKeyPkg    = `{"verifying_key":"AB12CD34"}`
	guardToken     = "usdc-base"
	guardRecipient = "recipient.example"
)

// The USDC@base fingerprint in sdk/contract/fixtures/assets.json is sha256("usdc-base").
var guardFingerprint = []string{tokenFingerprint(guardToken)}

func guardSource(t *testing.T, message string, nonceByte byte) (pkg, disclosure json.RawMessage) {
	t.Helper()
	nonce := make([]byte, 32)
	nonce[0] = nonceByte
	digest, err := PayloadDigestHex(message, nonce, guardRecipient, "")
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ = json.Marshal(map[string]string{"message": digest})
	disclosure, _ = json.Marshal(map[string]string{
		"message": message, "nonce": hex.EncodeToString(nonce), "recipient": guardRecipient,
	})
	return pkg, disclosure
}

func transferMessage(signer string, tokens map[string]string) string {
	m, _ := json.Marshal(map[string]any{
		"signer_id": signer,
		"intents":   []map[string]any{{"intent": "transfer", "receiver_id": "receiver.example", "tokens": tokens}},
	})
	return string(m)
}

func guardQuote() *Quote {
	return &Quote{Send: Amount{Amount: "100", Asset: "USDC@base"}, Debit: Amount{Amount: "100", Asset: "USDC@base"}}
}

func TestTokenFingerprintMatchesTheContract(t *testing.T) {
	if got := tokenFingerprint("usdc-base"); got != "a42c7e46411394e7c7719eef5be19239b2716b91d3a4a843fd3d2c0b6ca16b7c" {
		t.Fatalf("sha256(usdc-base) = %s", got)
	}
}

func TestBlindSignGuard(t *testing.T) {
	quote := guardQuote()
	one := func(amount string) string {
		return transferMessage(guardSigner, map[string]string{guardToken: amount})
	}

	okPkg1, okDisc1 := guardSource(t, one("60"), 1)
	okPkg2, okDisc2 := guardSource(t, one("40"), 2)
	if err := verifySigningDisclosure(quote, []json.RawMessage{okPkg1, okPkg2},
		[]json.RawMessage{okDisc1, okDisc2}, guardKeyPkg, guardFingerprint); err != nil {
		t.Fatalf("an honest two-source disclosure must pass: %v", err)
	}

	overPkg, overDisc := guardSource(t, one("41"), 3)
	_, otherDisc := guardSource(t, one("50"), 4)
	notTransfer, _ := json.Marshal(map[string]any{"signer_id": guardSigner,
		"intents": []map[string]any{{"intent": "token_diff", "diff": map[string]string{guardToken: "-1"}}}})
	twoIntents, _ := json.Marshal(map[string]any{"signer_id": guardSigner, "intents": []map[string]any{
		{"intent": "transfer", "tokens": map[string]string{guardToken: "1"}},
		{"intent": "transfer", "tokens": map[string]string{guardToken: "1"}}}})
	numberAmount, _ := json.Marshal(map[string]any{"signer_id": guardSigner,
		"intents": []map[string]any{{"intent": "transfer", "tokens": map[string]any{guardToken: 5}}}})
	shortNonce, _ := json.Marshal(map[string]string{"message": one("1"), "nonce": "00ff", "recipient": "r"})

	type guardCase struct {
		packages, messages []json.RawMessage
		want               string
	}
	cases := map[string]guardCase{
		"no disclosure":       {[]json.RawMessage{okPkg1}, nil, "blind-sign"},
		"fewer disclosures":   {[]json.RawMessage{okPkg1, okPkg2}, []json.RawMessage{okDisc1}, "blind-sign"},
		"package binds other": {[]json.RawMessage{okPkg1}, []json.RawMessage{otherDisc}, "does not bind"},
		"short nonce":         {[]json.RawMessage{okPkg1}, []json.RawMessage{shortNonce}, "co-sign refused"},
		"inflated total":      {[]json.RawMessage{okPkg1, overPkg}, []json.RawMessage{okDisc1, overDisc}, "above the approved debit"},
	}
	for name, message := range map[string]string{
		"not a transfer":  string(notTransfer),
		"two intents":     string(twoIntents),
		"another vault":   transferMessage("ffff", map[string]string{guardToken: "1"}),
		"two tokens":      transferMessage(guardSigner, map[string]string{guardToken: "1", "usdt-base": "1"}),
		"another token":   transferMessage(guardSigner, map[string]string{"usdt-base": "1"}),
		"bad amount":      transferMessage(guardSigner, map[string]string{guardToken: "1e3"}),
		"number amount":   string(numberAmount),
		"unreadable json": "not json",
	} {
		p, d := guardSource(t, message, 9)
		cases[name] = guardCase{[]json.RawMessage{p}, []json.RawMessage{d}, "co-sign refused"}
	}
	for name, tc := range cases {
		err := verifySigningDisclosure(quote, tc.packages, tc.messages, guardKeyPkg, guardFingerprint)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want a refusal containing %q, got %v", name, tc.want, err)
		}
	}
}

// The token is bound, not only the amount: a transfer whose token id hashes to ANOTHER catalog
// asset's fingerprint (USDT@base here) is refused, however honest the amount.
func TestBlindSignGuardBindsTheToken(t *testing.T) {
	usdt := "4aa51775b928a58a1ff49de71caf2cd78e1bf728d2853d7193d14cf30728f039" // USDT@base in assets.json
	p, d := guardSource(t, transferMessage(guardSigner, map[string]string{guardToken: "100"}), 1)
	err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, []string{usdt})
	if err == nil || !strings.Contains(err.Error(), "different token") {
		t.Fatalf("a USDC transfer against the USDT fingerprint must be refused, got %v", err)
	}
	// No fingerprint published: refuse, never skip.
	err = verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, nil)
	if err == nil || !strings.Contains(err.Error(), "did not publish an asset fingerprint") {
		t.Fatalf("a missing fingerprint must be refused, got %v", err)
	}
}

// A key package without its verifying key leaves nothing to check the signer against: refuse.
func TestBlindSignGuardNeedsTheVerifyingKey(t *testing.T) {
	p, d := guardSource(t, transferMessage(guardSigner, map[string]string{guardToken: "100"}), 1)
	for _, kp := range []string{`{}`, `{"verifying_key":""}`, `not json`} {
		err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, kp, guardFingerprint)
		if err == nil || !strings.Contains(err.Error(), "no verifying key") {
			t.Errorf("key package %s: want a refusal, got %v", kp, err)
		}
	}
}

// Every per-source amount is ASCII digits and above zero. Anything a big-integer parser would
// also accept — a sign, an empty string, zero — is refused before a share exists.
func TestBlindSignGuardRefusesUnsignedAmountTricks(t *testing.T) {
	quote := guardQuote()
	for _, amount := range []string{"-900", "-1", "+5", "", "0", "00", "000", " 5", "5 ", "0x10", "1_000"} {
		p, d := guardSource(t, transferMessage(guardSigner, map[string]string{guardToken: amount}), 7)
		err := verifySigningDisclosure(quote, []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint)
		if err == nil || !strings.Contains(err.Error(), "co-sign refused") {
			t.Errorf("amount %q: want a co-sign refusal, got %v", amount, err)
		}
	}

	// The bypass itself: A = 2D and B = -D total D, which equals the approved debit, while A
	// alone moves twice what was approved.
	a, da := guardSource(t, transferMessage(guardSigner, map[string]string{guardToken: "200"}), 1)
	b, db := guardSource(t, transferMessage(guardSigner, map[string]string{guardToken: "-100"}), 2)
	err := verifySigningDisclosure(quote, []json.RawMessage{a, b}, []json.RawMessage{da, db}, guardKeyPkg, guardFingerprint)
	if err == nil || !strings.Contains(err.Error(), "co-sign refused") {
		t.Fatalf("2D/-D disclosure must be refused, got %v", err)
	}
}

// One label may carry several fingerprints (two contracts of one coin): a transfer of either
// passes, a transfer of neither is refused. Comparison ignores case.
func TestBlindSignGuardAcceptsAnyFingerprintOfTheLabel(t *testing.T) {
	set := []string{tokenFingerprint("usdc-base-legacy"), strings.ToUpper(tokenFingerprint(guardToken))}
	for token, ok := range map[string]bool{guardToken: true, "usdc-base-legacy": true, "usdt-base": false} {
		p, d := guardSource(t, transferMessage(guardSigner, map[string]string{token: "100"}), 1)
		err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, set)
		if ok && err != nil {
			t.Errorf("%s is one of the label's fingerprints, must pass: %v", token, err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "different token")) {
			t.Errorf("%s matches no fingerprint of the label, must be refused: %v", token, err)
		}
	}
}
