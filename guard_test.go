// The blind-sign guard, case by case, with the same refusals as Python's
// _verify_signing_disclosure: a package that does not bind to the disclosed message, anything but
// a single transfer, a transfer from another vault, of another token, of an amount that is not a
// positive integer, or sources that move more than the approved debit — each one refused before a
// share exists.

package paymos

import (
	"encoding/hex"
	"encoding/json"
	"os"
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

// ── the guard reads the message the chain reads ─────────────────────────────

// legacyRead decodes a message the way this guard used to: encoding/json into a struct, which
// matches keys case-insensitively and keeps the last of a repeated one. The decoy tests below
// first prove their payload fools it — so a payload that stops being a decoy fails here, instead
// of the test going on to "pass" against nothing.
func legacyRead(t *testing.T, message string) (signer, intent string, tokens map[string]string) {
	t.Helper()
	var parsed struct {
		SignerID string `json:"signer_id"`
		Intents  []struct {
			Intent string            `json:"intent"`
			Tokens map[string]string `json:"tokens"`
		} `json:"intents"`
	}
	if err := json.Unmarshal([]byte(message), &parsed); err != nil || len(parsed.Intents) != 1 {
		t.Fatalf("encoding/json does not read %s as one intent: %v", message, err)
	}
	return parsed.SignerID, parsed.Intents[0].Intent, parsed.Intents[0].Tokens
}

const (
	// What the on-chain verifier would execute: 5000 USDC to the attacker, against a debit of 100.
	realIntent = `{"intent":"transfer","receiver_id":"attacker.example","tokens":{"usdc-base":"5000000000"}}`
	// What a case-insensitive, last-key-wins reader is shown instead: 10, within the debit.
	decoyIntent = `{"intent":"transfer","receiver_id":"receiver.example","tokens":{"usdc-base":"10"}}`
)

// The audit's payload, and every other place it fits. encoding/json reads the decoy in each — that
// is asserted first — while the digest binds the exact text and the case-sensitive verifier on
// chain executes the real transfer. The guard must refuse every one before a share exists.
func TestBlindSignGuardRefusesADecoyBehindASecondSpelling(t *testing.T) {
	signer := `"signer_id":"` + guardSigner + `"`
	for name, message := range map[string]string{
		"Intents after intents": `{` + signer + `,"intents":[` + realIntent + `],"Intents":[` + decoyIntent + `]}`,
		"INTENTS after intents": `{` + signer + `,"intents":[` + realIntent + `],"INTENTS":[` + decoyIntent + `]}`,
		// Another vault's signer under the exact key, this vault's under a second spelling.
		"Signer_id after signer_id": `{"signer_id":"ffff","intents":[` + decoyIntent + `],"Signer_id":"` + guardSigner + `"}`,
		// U+017F, LATIN SMALL LETTER LONG S: encoding/json folds it to "S".
		"long-s signer_id": `{"signer_id":"ffff","intents":[` + decoyIntent + `],"ſigner_id":"` + guardSigner + `"}`,
		"Tokens after tokens": `{` + signer + `,"intents":[{"intent":"transfer","receiver_id":"attacker.example",` +
			`"tokens":{"usdc-base":"5000000000"},"Tokens":{"usdc-base":"10"}}]}`,
		// U+212A, KELVIN SIGN: folds to "K".
		"kelvin-sign tokens": `{` + signer + `,"intents":[{"intent":"transfer","receiver_id":"attacker.example",` +
			`"tokens":{"usdc-base":"5000000000"},"to` + "K" + `ens":{"usdc-base":"10"}}]}`,
		// A withdrawal the chain executes, read as a transfer.
		"Intent after intent": `{` + signer + `,"intents":[{"intent":"ft_withdraw","token":"usdc-base",` +
			`"receiver_id":"attacker.example","amount":"5000000000","Intent":"transfer","tokens":{"usdc-base":"10"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			gotSigner, gotIntent, gotTokens := legacyRead(t, message)
			if gotSigner != guardSigner || gotIntent != "transfer" || len(gotTokens) != 1 || gotTokens[guardToken] != "10" {
				t.Fatalf("not a decoy: encoding/json reads signer %q intent %q tokens %v", gotSigner, gotIntent, gotTokens)
			}
			p, d := guardSource(t, message, 5)
			err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint)
			if err == nil || !strings.Contains(err.Error(), "co-sign refused") {
				t.Fatalf("a message that reads two ways must be refused, got %v", err)
			}
		})
	}
}

// A key that appears twice in one object is refused wherever the guard reads: the message, its
// intent, its tokens, the disclosure around it, the signing package, the vault's own key package.
// Spelled with an escape, "intents" is still "intents".
func TestBlindSignGuardRefusesARepeatedKey(t *testing.T) {
	signer := `"signer_id":"` + guardSigner + `"`
	quote := guardQuote()
	for name, message := range map[string]string{
		"intents twice":         `{` + signer + `,"intents":[` + realIntent + `],"intents":[` + decoyIntent + `]}`,
		"intents escaped":       `{` + signer + `,"intents":[` + realIntent + `],"intents":[` + decoyIntent + `]}`,
		"signer_id twice":       `{"signer_id":"ffff","intents":[` + decoyIntent + `],` + signer + `}`,
		"intent twice":          `{` + signer + `,"intents":[{"intent":"ft_withdraw","intent":"transfer","tokens":{"usdc-base":"10"}}]}`,
		"tokens twice":          `{` + signer + `,"intents":[{"intent":"transfer","tokens":{"usdc-base":"5000000000"},"tokens":{"usdc-base":"10"}}]}`,
		"one token twice":       `{` + signer + `,"intents":[{"intent":"transfer","tokens":{"usdc-base":"5000000000","usdc-base":"10"}}]}`,
		"deeper, unread field":  `{` + signer + `,"intents":[{"intent":"transfer","tokens":{"usdc-base":"10"},"memo":{"a":1,"a":2}}]}`,
		"trailing second value": `{` + signer + `,"intents":[` + decoyIntent + `]} {"intents":[]}`,
	} {
		p, d := guardSource(t, message, 6)
		err := verifySigningDisclosure(quote, []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint)
		if err == nil || !strings.Contains(err.Error(), "co-sign refused") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}

	honest := transferMessage(guardSigner, map[string]string{guardToken: "10"})
	p, d := guardSource(t, honest, 7)
	var pkg map[string]string
	_ = json.Unmarshal(p, &pkg)
	nonce := make([]byte, 32)
	nonce[0] = 7
	other, _ := PayloadDigestHex(transferMessage(guardSigner, map[string]string{guardToken: "11"}), nonce, guardRecipient, "")
	quoted, _ := json.Marshal(honest)
	nonceHex := hex.EncodeToString(nonce)

	for name, tc := range map[string]struct{ pkg, disc, kp string }{
		"disclosure message twice": {string(p),
			`{"message":` + string(quoted) + `,"nonce":"` + nonceHex + `","recipient":"` + guardRecipient + `","message":"{}"}`, guardKeyPkg},
		"disclosure Message": {string(p),
			`{"message":` + string(quoted) + `,"nonce":"` + nonceHex + `","recipient":"` + guardRecipient + `","Message":"{}"}`, guardKeyPkg},
		"disclosure Recipient": {string(p),
			`{"message":` + string(quoted) + `,"nonce":"` + nonceHex + `","recipient":"` + guardRecipient + `","Recipient":"x"}`, guardKeyPkg},
		"package message twice": {`{"message":"` + other + `","message":"` + pkg["message"] + `"}`, string(d), guardKeyPkg},
		"package Message":       {`{"message":"` + other + `","Message":"` + pkg["message"] + `"}`, string(d), guardKeyPkg},
		"key package twice":     {string(p), string(d), `{"verifying_key":"FFFF","verifying_key":"AB12CD34"}`},
		"key package Verifying": {string(p), string(d), `{"verifying_key":"FFFF","Verifying_key":"AB12CD34"}`},
	} {
		err := verifySigningDisclosure(quote, []json.RawMessage{json.RawMessage(tc.pkg)},
			[]json.RawMessage{json.RawMessage(tc.disc)}, tc.kp, guardFingerprint)
		if err == nil || !strings.Contains(err.Error(), "co-sign refused") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}

	// The same honest source, unaltered, still signs: the refusals above are about the second key.
	if err := verifySigningDisclosure(quote, []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint); err != nil {
		t.Fatalf("the honest source must pass: %v", err)
	}
}

// A message shaped exactly as the server builds it (the server's Nep413Signer.BuildTransferIntentMessage:
// deadline, one transfer with receiver_id and tokens, signer_id last), escapes included, still signs.
func TestBlindSignGuardAcceptsTheServersMessageShape(t *testing.T) {
	message := `{"deadline":"2026-01-01T00:00:00.000Z","intents":[{"intent":"transfer",` +
		`"receiver_id":"deposit\"route\\.example","tokens":{"usdc-base":"100"}}],"signer_id":"` + guardSigner + `"}`
	p, d := guardSource(t, message, 8)
	if err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint); err != nil {
		t.Fatalf("the server's own message shape must sign: %v", err)
	}
}

// The sign/begin envelope is read by a case-insensitive struct decode, which is only trustworthy
// once no key it reads is repeated or spelled twice.
func TestSignBeginEnvelopeMustBeUnambiguous(t *testing.T) {
	keys := []string{"signing_packages", "messages", "token"}
	if err := requireStrictKeys([]byte(`{"token":"t","signing_packages":[],"messages":[],"extra":{"x":1}}`), keys...); err != nil {
		t.Fatalf("an honest envelope must pass: %v", err)
	}
	for _, body := range []string{
		`{"token":"t","signing_packages":[],"messages":[],"Messages":[]}`,
		`{"token":"t","signing_packages":[],"Signing_Packages":[],"messages":[]}`,
		`{"token":"t","token":"u","signing_packages":[],"messages":[]}`,
		`{"token":"t","signing_packages":[],"messages":[{"message":"a","message":"b"}]}`,
		`[]`,
		`not json`,
	} {
		if err := requireStrictKeys([]byte(body), keys...); err == nil {
			t.Errorf("%s: want a refusal", body)
		}
	}
}

// The strict reader recurses per bracket and json.Decoder.Token enforces no depth, so the reader
// enforces one: a server-written message nested a million deep is a refusal, not a goroutine
// stack the runtime aborts the whole process over.
func TestStrictParseRefusesNestingPastItsLimit(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	if _, err := strictParse([]byte(nest(strictMaxDepth))); err != nil {
		t.Fatalf("%d levels is within the limit: %v", strictMaxDepth, err)
	}
	if _, err := strictParse([]byte(nest(strictMaxDepth + 1))); err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("%d levels must be refused, got %v", strictMaxDepth+1, err)
	}

	deep := `{"signer_id":"` + guardSigner + `","intents":[` + decoyIntent + `],"memo":` + nest(1<<20) + `}`
	p, d := guardSource(t, deep, 9)
	err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint)
	if err == nil || !strings.Contains(err.Error(), "co-sign refused: unreadable message") || !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("a million-deep message must be the guard's refusal, got %v", err)
	}
	// The same message at an ordinary depth signs.
	ordinary := `{"signer_id":"` + guardSigner + `","intents":[` + decoyIntent + `],"memo":` + nest(8) + `}`
	p, d = guardSource(t, ordinary, 9)
	if err := verifySigningDisclosure(guardQuote(), []json.RawMessage{p}, []json.RawMessage{d}, guardKeyPkg, guardFingerprint); err != nil {
		t.Fatalf("an ordinary depth must pass: %v", err)
	}
	// A disclosure envelope or a sign/begin answer nested past the limit is refused the same way.
	if err := requireStrictKeys([]byte(`{"messages":`+nest(1<<16)+`}`), "messages"); err == nil {
		t.Fatal("a deep sign/begin answer must be refused")
	}
}

func TestStrictParse(t *testing.T) {
	v, err := strictParse([]byte(` {"a":[1,"2",true,null,{"b":12345678901234567890123}],"A":0} `))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(strictObject)
	if len(obj) != 2 {
		t.Fatalf("keys are kept exactly as written, case included: %v", obj)
	}
	big := obj["a"].([]any)[4].(strictObject)["b"]
	if n, ok := big.(json.Number); !ok || n.String() != "12345678901234567890123" {
		t.Fatalf("a number stays its exact digits, never a float: %#v", big)
	}
	if _, _, err := obj.field("a"); err == nil {
		t.Fatal(`"A" next to "a" must make "a" ambiguous`)
	}
	for _, bad := range []string{`{"a":1,"a":1}`, `{"a":1}{}`, `{"a":1,}`, `{a:1}`, `{"a":1`, ``} {
		if _, err := strictParse([]byte(bad)); err == nil {
			t.Errorf("%q must not parse", bad)
		}
	}
}

// Every response the real server recorded parses under the strict reader — whole files, and the
// message sign_begin.json discloses inside a string — so the strictness costs no legitimate
// answer. The recorded disclosure is still refused, and for the reason it always was (its nonce is
// a placeholder, not 32 bytes), not because it reads two ways.
func TestEveryContractFixtureParsesStrictly(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if _, err := strictParse(readFixtureFile(t, e.Name())); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
	}

	var begin struct {
		SigningPackages []json.RawMessage `json:"signing_packages"`
		Messages        []json.RawMessage `json:"messages"`
	}
	raw := loadFixture(t, "sign_begin.json").Response.Body
	if err := requireStrictKeys(raw, "signing_packages", "messages", "token"); err != nil {
		t.Fatalf("sign_begin.json: %v", err)
	}
	if err := json.Unmarshal(raw, &begin); err != nil || len(begin.Messages) != 1 {
		t.Fatalf("sign_begin.json: %v", err)
	}
	disc, err := strictParseObject(begin.Messages[0])
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := disc.stringField("message")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strictParseObject([]byte(message)); err != nil {
		t.Fatalf("the disclosed message %s: %v", message, err)
	}
	err = verifySigningDisclosure(guardQuote(), begin.SigningPackages, begin.Messages, guardKeyPkg, guardFingerprint)
	if err == nil || !strings.Contains(err.Error(), "nonce must be 32 bytes") {
		t.Fatalf("the recorded placeholder disclosure is refused for its nonce, got %v", err)
	}
}

// A pin that pins nothing is refused when the wallet is built. It used to be dropped, which left
// the label on the server's own published fingerprint — the value the pin was there to replace.
func TestPinnedFingerprintsRefusesAnEmptyOrMalformedPin(t *testing.T) {
	secret := PackSecret("vk_live_contract", 7, "")
	for name, pins := range map[string]map[string][]string{
		"no fingerprint":   {"USDC@base": {}},
		"nil list":         {"USDC@base": nil},
		"empty string":     {"USDC@base": {""}},
		"blank":            {"USDC@base": {"   "}},
		"one empty of two": {"USDC@base": {tokenFingerprint(guardToken), ""}},
		"not hex":          {"USDC@base": {strings.Repeat("z", 64)}},
		"too short":        {"USDC@base": {"a42c7e46"}},
		"0x prefixed":      {"USDC@base": {"0x" + tokenFingerprint(guardToken)}},
	} {
		w, err := NewWallet(secret, "https://vault.test", 0, PinnedFingerprints(pins))
		if err == nil || w != nil || !strings.Contains(err.Error(), "PinnedFingerprints") {
			t.Errorf("%s: want a construction error, got %v, %v", name, w, err)
		}
	}
	upper := strings.ToUpper(tokenFingerprint(guardToken))
	w, err := NewWallet(secret, "https://vault.test", 0, PinnedFingerprints(map[string][]string{"USDC@base": {" " + upper + " "}}))
	if err != nil || len(w.pinned["USDC@base"]) != 1 || w.pinned["USDC@base"][0] != tokenFingerprint(guardToken) {
		t.Fatalf("a well-formed pin, any case, surrounding space trimmed, must construct: %v", err)
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
