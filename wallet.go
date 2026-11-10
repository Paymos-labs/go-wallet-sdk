package paymos

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The entry point, ported from the Python SDK via the TypeScript, Rust and .NET ones. Same
// methods, same checks, same refusals.

// progressedStatuses are past "pending": the movement is already committed to the co-sign and
// relay pipeline, so a retry that replays it (same durable Idempotency-Key) converges instead of
// signing a second time. These are the server's public words — the same set as Python's
// _PROGRESSED_STATUSES. "failed" is deliberately absent: a failed movement is not a success to
// converge on, so the retry surfaces the error.
var progressedStatuses = map[string]bool{
	"processing": true, "completed": true, "refunded": true,
}

// terminalStatuses settle a movement: no more polling.
var terminalStatuses = map[string]bool{
	"completed": true, "failed": true, "refunded": true, "expired": true, "cancelled": true,
}

const defaultBaseURL = "https://wallet.paymos.io"

// SwapOptions are the optional knobs of Wallet.Swap. Zero values mean "the SDK default".
//
// SlippageBps: 0 — the zero value — means the DEFAULT 50 bps (0.5%), NOT zero slippage, and so does
// any negative value. This SDK cannot tell an unset field from an explicit 0, so SwapOptions{} and
// SwapOptions{SlippageBps: 0} both send 50. The other seven SDKs send 0 as 0; here the tightest
// tolerance you can ask for is SlippageBps: 1. (Changing what 0 sends now would change what every
// existing SwapOptions{} call sends.)
type SwapOptions struct {
	SlippageBps    int    // default 50 (= 0.5%); 0 and below also mean 50 — see above
	MinReceive     string // human decimal floor on the quote's minimum receive (receive.min)
	MaxDebit       string // human decimal ceiling on the total vault debit
	IdempotencyKey string // a durable payout id — see IdempotencyKey on WithdrawOptions
}

// WithdrawOptions are the optional knobs of Wallet.Withdraw. Zero values mean "the SDK default".
//
// IdempotencyKey (here and on SwapOptions): set it to a durable id (a payout or job id) and a retry
// under the same key replays the same movement instead of paying twice. Left empty, a fresh key is
// generated per call — Go cannot tell an unset field from an explicit "" — so a retry is a NEW
// payment. A key of only whitespace is refused: sent, the server reads it as no key at all.
type WithdrawOptions struct {
	Mode           string // "exact_out" (default) or "total_in"
	MaxDebit       string // human decimal ceiling on the total vault debit
	IdempotencyKey string // a durable payout id; empty means a fresh key per call (no dedup across retries)
}

// Wallet controls one vault. Construct with NewWallet or FromEnv. Not safe to copy after use.
//
// Printed with any fmt verb it shows the vault id, whether it holds a share and the key's vk_live_
// prefix — never the key or the share. Even a copy of the struct, walked field by field by
// reflection, cannot reach either (see sealedSecret).
type Wallet struct {
	secret     sealedSecret
	http       *httpTransport
	assetMu    sync.Mutex
	assetList  []Asset
	assetCache map[string]Asset
	// pinned maps an asset label to the fingerprints the caller trusts for it, lowercased. A pinned
	// label ignores whatever /assets publishes for it.
	pinned map[string][]string
	// configErr is the first error an Option reported. Option is func(*Wallet) and cannot return
	// one, so NewWallet does.
	configErr error
}

// Option configures a Wallet at construction.
type Option func(*Wallet)

// PinnedFingerprints pins asset fingerprints out of band — the Go form of Python's
// pinned_fingerprints. Keys are asset labels ("USDC@base"); values are the lowercase hex SHA-256
// of the asset's raw token id, one or several per label.
//
// Without a pin, the co-sign binds every disclosed transfer to the fingerprint /assets publishes.
// That catches a server bug or a compromised signing path, but the fingerprint comes from the same
// server that builds the messages, so a fully compromised server could publish a false one. A pin
// is a trust anchor that does not depend on the server: for a pinned label the co-sign accepts ONLY
// the pinned values and ignores /assets. Unpinned labels keep using the published set. Values are
// compared case-insensitively.
//
// A malformed pin is refused when the wallet is built — NewWallet returns the error: a label with
// no fingerprint, an empty one, or anything but 64 hex characters. An empty pin used to be dropped
// silently, which left the label on the server's published fingerprint: the very value the pin was
// there to stop trusting.
func PinnedFingerprints(pins map[string][]string) Option {
	return func(w *Wallet) {
		for label, fps := range pins {
			if len(fps) == 0 {
				w.refuse(localError("PinnedFingerprints[%q] pins no fingerprint — pin one, or leave the label out", label))
				return
			}
			lowered := make([]string, 0, len(fps))
			for _, fp := range fps {
				fp = strings.ToLower(strings.TrimSpace(fp))
				if _, err := hex.DecodeString(fp); len(fp) != 64 || err != nil {
					w.refuse(localError("PinnedFingerprints[%q]: %q is not a 64-character hex SHA-256 fingerprint", label, fp))
					return
				}
				lowered = append(lowered, fp)
			}
			if w.pinned == nil {
				w.pinned = map[string][]string{}
			}
			w.pinned[label] = lowered
		}
	}
}

// refuse records the first configuration error an Option meets.
func (w *Wallet) refuse(err error) {
	if w.configErr == nil {
		w.configErr = err
	}
}

// NewWallet parses the vs_live_ secret and points the client at baseURL (or PAYMOS_BASE_URL,
// or the production default). Options such as PinnedFingerprints follow.
func NewWallet(secret, baseURL string, timeout time.Duration, opts ...Option) (*Wallet, error) {
	s, err := ParseSecret(secret)
	if err != nil {
		return nil, err
	}
	if baseURL == "" {
		baseURL = os.Getenv("PAYMOS_BASE_URL")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	w := &Wallet{secret: sealSecret(s), http: newHTTP(baseURL, s.APIKey, timeout)}
	for _, opt := range opts {
		opt(w)
	}
	if w.configErr != nil {
		return nil, w.configErr
	}
	return w, nil
}

// String describes the wallet without its secret: vault id, whether it holds a share, the key's
// non-secret vk_live_ prefix and the base URL.
func (w *Wallet) String() string {
	if w == nil || w.secret == nil {
		return "Wallet(<unconfigured>)"
	}
	s := w.secret()
	base := ""
	if w.http != nil {
		base = w.http.baseURL
	}
	return fmt.Sprintf("Wallet(vaultId=%d, hasShare=%v, apiKey=%s, baseURL=%s)",
		s.VaultID, s.HasShare(), maskKey(s.APIKey), base)
}

// GoString is String: %#v must not print the fields either.
func (w *Wallet) GoString() string { return w.String() }

// Format makes every fmt verb print String — %+v and %#v included, which would otherwise walk the
// struct and print the secret's fields.
func (w *Wallet) Format(f fmt.State, verb rune) { formatRedacted(f, verb, w.String()) }

// FromEnv reads PAYMOS_VAULT_SECRET, the way a deployed process is configured.
func FromEnv(opts ...Option) (*Wallet, error) {
	secret := os.Getenv("PAYMOS_VAULT_SECRET")
	if secret == "" {
		return nil, localError("PAYMOS_VAULT_SECRET is not set")
	}
	return NewWallet(secret, "", 0, opts...)
}

// ── reads ────────────────────────────────────────────────────────────────────

// Assets returns the curated asset catalog (fetched once and cached per Wallet). The decimals
// every amount conversion needs come from this same call, so nothing guesses or refetches them.
//
// The server answers a bare JSON array. An earlier build read {"assets": [...]}, got an empty
// catalog without an error, and then refused every quote, swap and withdraw as "unknown asset".
func (w *Wallet) Assets() ([]Asset, error) {
	w.assetMu.Lock()
	defer w.assetMu.Unlock()
	if w.assetList == nil {
		body, err := w.http.get("/vault/v1/assets", nil)
		if err != nil {
			return nil, err
		}
		var list []Asset
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, localError("bad wire JSON from /assets: %v", err)
		}
		if list == nil {
			list = []Asset{}
		}
		w.assetList = list
		w.assetCache = make(map[string]Asset, len(list))
		// A label listed twice resolves to its FIRST entry, as it does on the server; the
		// fingerprint check alone accepts every entry of a label (see sendFingerprints).
		for _, a := range list {
			if _, seen := w.assetCache[a.Asset]; !seen {
				w.assetCache[a.Asset] = a
			}
		}
	}
	return append([]Asset(nil), w.assetList...), nil
}

// Balances returns per-asset vault balances. Like Assets, the server answers a bare JSON array.
func (w *Wallet) Balances() ([]Balance, error) {
	body, err := w.http.get("/vault/v1/balances", nil)
	if err != nil {
		return nil, err
	}
	var out []Balance
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, localError("bad wire JSON from /balances: %v", err)
	}
	return out, nil
}

// Movement fetches one movement, with its fee breakdown.
func (w *Wallet) Movement(movementID string) (*Movement, error) {
	body, err := w.http.get("/vault/v1/movements/"+url.PathEscape(movementID), nil)
	if err != nil {
		return nil, err
	}
	var mv Movement
	if err := json.Unmarshal(body, &mv); err != nil {
		return nil, localError("bad wire JSON: %v", err)
	}
	return &mv, nil
}

// Movements returns a page of the caller's movement history (newest first, summary rows without
// fee legs) and the next cursor; pass it back as cursor for the next page ("" when exhausted).
// The server speaks keyset pagination: items + next_cursor. A limit of 0 or less means the SDK
// default, 50.
func (w *Wallet) Movements(limit int, cursor string) (items []Movement, nextCursor string, err error) {
	if limit <= 0 {
		limit = 50
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	body, err := w.http.get("/vault/v1/movements", q)
	if err != nil {
		return nil, "", err
	}
	var out struct {
		Items      []Movement `json:"items"`
		NextCursor string     `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", localError("bad wire JSON: %v", err)
	}
	return out.Items, out.NextCursor, nil
}

// Wait polls until the movement reaches a terminal status
// (completed | failed | refunded | expired | cancelled).
func (w *Wallet) Wait(movementID string, timeout, interval time.Duration) (*Movement, error) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		mv, err := w.Movement(movementID)
		if err != nil {
			return nil, err
		}
		if terminalStatuses[mv.Status] {
			return mv, nil
		}
		if !time.Now().Before(deadline) {
			return nil, localError("timed out waiting for movement %s", movementID)
		}
		time.Sleep(interval)
	}
}

// ── quotes ───────────────────────────────────────────────────────────────────

// QuoteSwap is a dry preview. Nothing is created and nothing is signed.
//
// amount is a HUMAN decimal string in the send asset ("100", "0.5"); the server scales it by the
// asset's decimals. The quote that comes back carries raw integer strings. Never pass ParseUnits
// output here: "10000" is ten thousand of the asset, not 0.01.
//
// slippageBps of 0 or less means the default 50 bps (0.5%), not zero slippage — the same rule as
// SwapOptions.SlippageBps, so a preview quotes what the swap would send.
func (w *Wallet) QuoteSwap(send, receive, amount string, slippageBps int) (*Quote, error) {
	if slippageBps <= 0 {
		slippageBps = 50
	}
	if _, err := w.validateAmount(amount, send); err != nil {
		return nil, err
	}
	if _, err := w.decimalsOf(receive); err != nil {
		return nil, err
	}
	return w.quote("/vault/v1/quote/swap", swapBody(send, receive, amount, slippageBps), true, "")
}

// QuoteWithdraw is a dry preview. Nothing is created and nothing is signed.
//
// amount is a HUMAN decimal string in asset ("25", "0.01"); the server scales it. The quote that
// comes back carries raw integer strings. Never pass ParseUnits output here.
func (w *Wallet) QuoteWithdraw(asset, amount, to, mode string) (*Quote, error) {
	if mode == "" {
		mode = "exact_out"
	}
	if _, err := w.validateAmount(amount, asset); err != nil {
		return nil, err
	}
	return w.quote("/vault/v1/quote/withdraw", map[string]any{
		"asset": asset, "amount": amount, "to": to, "mode": mode,
	}, true, "")
}

// ── money ────────────────────────────────────────────────────────────────────

// Swap creates a real movement and drives the 2-of-2 co-sign. Full-key secrets only.
//
// amount, like opts.MinReceive and opts.MaxDebit, is a HUMAN decimal string ("100", "0.5") that the
// server scales by the asset's decimals — never ParseUnits output, which would be read as that many
// whole units. Swap("USDC@base", "USDT@base", "10000", …) swaps ten thousand USDC.
func (w *Wallet) Swap(send, receive, amount string, opts SwapOptions) (*Movement, error) {
	if err := w.requireShare("swap"); err != nil {
		return nil, err
	}
	idem, err := idempotencyKeyOf(opts.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	sendDec, err := w.validateAmount(amount, send)
	if err != nil {
		return nil, err
	}
	recvDec, err := w.decimalsOf(receive)
	if err != nil {
		return nil, err
	}
	slippageBps := opts.SlippageBps
	if slippageBps <= 0 {
		slippageBps = 50
	}

	q, err := w.quote("/vault/v1/quote/swap", swapBody(send, receive, amount, slippageBps), false, idem)
	if err != nil {
		return nil, err
	}

	if opts.MinReceive != "" {
		floorRaw, err := ParseUnits(opts.MinReceive, recvDec)
		if err != nil {
			return nil, err
		}
		floor, _ := rawInt(floorRaw) // caller-side, already validated by ParseUnits
		got, err := rawInt(q.Receive.Min)
		if err != nil {
			return nil, err
		}
		if got.Cmp(floor) < 0 {
			return nil, newError(KindSlippageExceeded, 0,
				"quoted minimum receive %s is below the requested minimum %s (%s %s)",
				q.Receive.Min, floor, opts.MinReceive, receive)
		}
	}
	// A swap is exact_in, so the send leg must be exactly what was approved.
	expectSendRaw, err := ParseUnits(amount, sendDec)
	if err != nil {
		return nil, err
	}
	if err := verifyQuoteEcho(q, send, receive, expectSendRaw, "", ""); err != nil {
		return nil, err
	}
	if err := enforceMaxDebit(q, opts.MaxDebit, sendDec); err != nil {
		return nil, err
	}
	if err := w.cosign(q); err != nil {
		return nil, err
	}
	mid, err := requireMovementID(q)
	if err != nil {
		return nil, err
	}
	return w.Movement(mid)
}

// Withdraw creates a real payout movement and drives the 2-of-2 co-sign. Full-key secrets only.
//
// amount, like opts.MaxDebit, is a HUMAN decimal string ("25", "0.01") that the server scales by
// the asset's decimals — never ParseUnits output. Withdraw("USDC@base", "10000", …), which is what
// ParseUnits("0.01", 6) returns, pays out ten thousand USDC; the SDK and the server agree on that
// number, so no check can tell it from an intended one.
func (w *Wallet) Withdraw(asset, amount, to string, opts WithdrawOptions) (*Movement, error) {
	if err := w.requireShare("withdraw"); err != nil {
		return nil, err
	}
	idem, err := idempotencyKeyOf(opts.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	mode := opts.Mode
	if mode == "" {
		mode = "exact_out"
	}
	dec, err := w.validateAmount(amount, asset)
	if err != nil {
		return nil, err
	}

	q, err := w.quote("/vault/v1/quote/withdraw", map[string]any{
		"asset": asset, "amount": amount, "to": to, "mode": mode,
	}, false, idem)
	if err != nil {
		return nil, err
	}

	// A withdraw is same-asset. For exact_out the approved amount is the requested OUT; for
	// total_in it is the total DEBIT — and the send leg is total minus fees, so pinning send
	// would false-fail every time.
	expectedRaw, err := ParseUnits(amount, dec)
	if err != nil {
		return nil, err
	}
	if mode == "total_in" {
		err = verifyQuoteEcho(q, asset, asset, "", "", expectedRaw)
	} else {
		err = verifyQuoteEcho(q, asset, asset, "", expectedRaw, "")
	}
	if err != nil {
		return nil, err
	}
	if err := enforceMaxDebit(q, opts.MaxDebit, dec); err != nil {
		return nil, err
	}
	if err := w.cosign(q); err != nil {
		return nil, err
	}
	mid, err := requireMovementID(q)
	if err != nil {
		return nil, err
	}
	return w.Movement(mid)
}

// ── internals ────────────────────────────────────────────────────────────────

// swapBody is the swap request. The swap surface is exact_in only; the mode is sent explicitly
// (the server's default is the same word) so the request says what the echo check assumes.
func swapBody(send, receive, amount string, slippageBps int) map[string]any {
	return map[string]any{
		"send": send, "receive": receive, "amount": amount, "mode": "exact_in", "slippage_bps": slippageBps,
	}
}

func (w *Wallet) requireShare(op string) error {
	if !w.secret().HasShare() {
		return localError("%s needs a full-scope secret: this one carries no co-signing share", op)
	}
	return nil
}

func (w *Wallet) assetMap() (map[string]Asset, error) {
	if _, err := w.Assets(); err != nil {
		return nil, err
	}
	w.assetMu.Lock()
	defer w.assetMu.Unlock()
	return w.assetCache, nil
}

func (w *Wallet) decimalsOf(asset string) (int, error) {
	m, err := w.assetMap()
	if err != nil {
		return 0, err
	}
	a, ok := m[asset]
	if !ok {
		return 0, localError("unknown asset: %s", asset)
	}
	return a.Decimals, nil
}

func (w *Wallet) validateAmount(amount, asset string) (int, error) {
	dec, err := w.decimalsOf(asset)
	if err != nil {
		return 0, err
	}
	if _, err := ParseUnits(amount, dec); err != nil {
		return 0, err // a bad decimal errors before anything reaches the server
	}
	return dec, nil
}

func (w *Wallet) quote(path string, body map[string]any, dry bool, idempotencyKey string) (*Quote, error) {
	body["dry"] = dry
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, localError("bad quote request: %v", err)
	}
	var headers map[string]string
	if idempotencyKey != "" {
		headers = map[string]string{"idempotency-key": idempotencyKey}
	}
	resp, err := w.http.post(path, raw, headers)
	if err != nil {
		return nil, err
	}
	var q Quote
	if err := json.Unmarshal(resp, &q); err != nil {
		return nil, localError("bad wire JSON: %v", err)
	}
	return &q, nil
}

func requireMovementID(q *Quote) (string, error) {
	if q.MovementID == "" {
		return "", localError("quote created no movement — cannot sign a dry preview")
	}
	return q.MovementID, nil
}

// cosign drives the 2-of-2 round: commit per source, verify the disclosure, sign, aggregate.
func (w *Wallet) cosign(q *Quote) error {
	mid, err := requireMovementID(q)
	if err != nil {
		return err
	}
	n := 0
	if q.Sources != nil {
		n = *q.Sources
	}
	if n < 1 {
		return localError("quote is missing its source count — cannot co-sign")
	}

	kp := w.secret().Share
	if kp == "" {
		return localError("this secret carries no co-signing share")
	}
	// The token every source must move is fixed before a single nonce exists: no fingerprint,
	// no co-sign.
	sendFingerprints, err := w.sendFingerprints(q)
	if err != nil {
		return err
	}
	commitments := make([]json.RawMessage, 0, n)
	nonces := make([]json.RawMessage, 0, n)
	for i := 0; i < n; i++ {
		c, nn, err := frostCommit([]byte(kp))
		if err != nil {
			return err
		}
		commitments = append(commitments, c)
		nonces = append(nonces, nn)
	}

	signPath := "/vault/v1/movements/" + url.PathEscape(mid)
	beginBody, _ := json.Marshal(map[string]any{"commitments": commitments})
	beginRaw, err := w.http.post(signPath+"/sign/begin", beginBody, nil)
	if err != nil {
		// An ambiguous failure after the server already progressed the movement is not a reason
		// to sign it a second time.
		mv, mErr := w.Movement(mid)
		if mErr == nil && progressedStatuses[mv.Status] {
			return nil
		}
		return err
	}

	// Opaque blobs must survive byte-exactly, so the envelope is parsed with RawMessage fields
	// rather than into map[string]any.
	var beginTyped struct {
		SigningPackages []json.RawMessage `json:"signing_packages"`
		Messages        []json.RawMessage `json:"messages"`
		Token           string            `json:"token"`
	}
	if err := json.Unmarshal(beginRaw, &beginTyped); err != nil {
		return localError("bad wire JSON from sign/begin: %v", err)
	}
	// That decode matches keys case-insensitively and keeps the last of a repeated one. Refusing
	// any repeated or second-spelled key first means it read the exact-case fields, and nothing
	// else (see strictjson.go).
	if err := requireStrictKeys(beginRaw, "signing_packages", "messages", "token"); err != nil {
		return localError("co-sign refused: the sign/begin answer is ambiguous: %v", err)
	}
	packages := beginTyped.SigningPackages
	if len(packages) != n {
		return localError("co-sign protocol mismatch: expected %d signing packages, got %d", n, len(packages))
	}
	if beginTyped.Token == "" {
		return localError("co-sign protocol mismatch: sign/begin returned no session token")
	}

	if err := verifySigningDisclosure(q, packages, beginTyped.Messages, kp, sendFingerprints); err != nil {
		return err
	}

	shares := make([]json.RawMessage, 0, n)
	for i := range packages {
		share, err := frostSign(packages[i], nonces[i], []byte(kp))
		if err != nil {
			return err
		}
		shares = append(shares, share)
	}
	return w.signAggregate(signPath, beginTyped.Token, shares)
}

// signAggregate ships round two. A failure here is a genuine crypto or relay rejection and always
// propagates; it is never converged on. The server answers {"ok":false,"status":"failed",
// "error":…} with a 400, which the transport already turns into a typed error; a 2xx that still
// says ok:false is refused here.
func (w *Wallet) signAggregate(signPath, token string, shares []json.RawMessage) error {
	aggBody, _ := json.Marshal(map[string]any{"token": token, "shares": shares})
	aggRaw, err := w.http.post(signPath+"/sign/aggregate", aggBody, nil)
	if err != nil {
		return err
	}
	var agg struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(aggRaw, &agg)
	if !agg.OK {
		if agg.Error != "" {
			return localError("%s", agg.Error)
		}
		return localError("sign failed")
	}
	return nil
}

// verifyQuoteEcho refuses to sign unless the server's quote echoes what the caller approved: the
// assets, and the one amount the caller fixed (the send leg of a swap, the out leg of an exact_out
// withdraw, the debit ceiling of a total_in one). A units bug, contract drift or a quote that
// differs from the request is caught before a commitment exists. It does not check the recipient,
// and for exact_out it does not bound the debit — the server computes that; MaxDebit caps it.
// Empty strings mark the checks the caller did not ask for.
func verifyQuoteEcho(q *Quote, sendAsset, receiveAsset, expectSendRaw, expectReceiveRaw, maxDebitRaw string) error {
	if q.Send.Asset != sendAsset || q.Receive.Asset != receiveAsset {
		return localError("quote is for %s→%s, not the %s→%s that was approved",
			q.Send.Asset, q.Receive.Asset, sendAsset, receiveAsset)
	}
	if expectSendRaw != "" {
		got, err := rawInt(q.Send.Amount)
		if err != nil {
			return err
		}
		want, _ := rawInt(expectSendRaw) // caller-side, already validated by ParseUnits
		if got.Cmp(want) != 0 {
			return localError("quote sends %s, not the approved %s", q.Send.Amount, expectSendRaw)
		}
	}
	if expectReceiveRaw != "" {
		// Pinned exactly, as in Python: an exact_out payout delivers the approved amount — not
		// less, and not more either (more out is more debited).
		got, err := rawInt(q.Receive.Amount)
		if err != nil {
			return err
		}
		want, _ := rawInt(expectReceiveRaw)
		if got.Cmp(want) != 0 {
			return localError("quote receives %s, not the approved %s", q.Receive.Amount, expectReceiveRaw)
		}
	}
	if maxDebitRaw != "" {
		got, err := rawInt(q.Debit.Amount)
		if err != nil {
			return err
		}
		want, _ := rawInt(maxDebitRaw)
		if got.Cmp(want) > 0 {
			return localError("quote debits %s, above the approved %s", q.Debit.Amount, maxDebitRaw)
		}
	}
	return nil
}

func enforceMaxDebit(q *Quote, maxDebit string, decimals int) error {
	if maxDebit == "" {
		return nil
	}
	capRaw, err := ParseUnits(maxDebit, decimals)
	if err != nil {
		return err
	}
	got, err := rawInt(q.Debit.Amount)
	if err != nil {
		return err
	}
	cap, _ := rawInt(capRaw)
	if got.Cmp(cap) > 0 {
		return localError("quote debits %s, above the cap %s (%s)", q.Debit.Amount, capRaw, maxDebit)
	}
	return nil
}

// rawInt parses a raw integer amount. An unparseable amount is an error — fail-closed, never
// rounded, never silently zero.
func rawInt(raw string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return nil, localError("bad raw amount: %q", raw)
	}
	return v, nil
}

// sendFingerprints are the fingerprints a disclosed transfer may hash to: the caller's pin for the
// quote's send label when there is one, else the fingerprints /assets publishes under that label.
// One label is one coin, so a label listed twice (two contracts of one coin — the server resolves
// the label to the first) accepts either — but only entries with the FIRST entry's decimals. The
// debit is in the first entry's raw units; a token with other decimals would make the same raw
// amount worth 10^Δ more, so its fingerprint is left out of the set. A pin is taken as given: the
// integrator vouches for it. With nothing to compare against, the co-sign is refused rather than
// the check skipped.
func (w *Wallet) sendFingerprints(q *Quote) ([]string, error) {
	if pinned := w.pinned[q.Send.Asset]; len(pinned) > 0 {
		return pinned, nil
	}
	if _, err := w.Assets(); err != nil {
		return nil, err
	}
	w.assetMu.Lock()
	defer w.assetMu.Unlock()
	first, listed := w.assetCache[q.Send.Asset]
	var fps []string
	for _, a := range w.assetList {
		if a.Asset != q.Send.Asset || a.Decimals != first.Decimals {
			continue
		}
		if a.Fingerprint != "" {
			fps = append(fps, strings.ToLower(a.Fingerprint))
		}
	}
	if !listed {
		return nil, localError("co-sign refused: the quote sends %q, which is not in the asset catalog", q.Send.Asset)
	}
	if len(fps) == 0 {
		return nil, localError("co-sign refused: the server did not publish an asset fingerprint — update the server")
	}
	return fps, nil
}

func fingerprintIn(fp string, set []string) bool {
	for _, want := range set {
		if strings.EqualFold(fp, want) {
			return true
		}
	}
	return false
}

// tokenFingerprint is how the catalog names a token without naming it: the lowercase hex SHA-256
// of the raw token id's UTF-8 bytes.
func tokenFingerprint(tokenID string) string {
	sum := sha256.Sum256([]byte(tokenID))
	return hex.EncodeToString(sum[:])
}

// verifySigningDisclosure refuses to blind-sign. The server discloses, per source, the
// plaintext message it wants signed. For each one this recomputes the digest and confirms the
// package about to be signed binds to exactly that message; confirms the message is a single
// transfer from THIS vault, of a positive amount of the send asset (its token id hashes to one of
// sendFingerprints); and confirms the sources together move no more than the approved debit. Any
// mismatch aborts before a share is produced.
//
// What this does not do: it does not check the recipient — the route's deposit address is chosen
// by the server and is taken as disclosed. "No more than the approved debit" is only as strong as
// that debit, which for an exact_out withdraw (and the input side of any quote) is server-computed
// unless the caller caps it with MaxDebit — recommended for unattended payouts. And the token check
// binds the token to the fingerprint the server publishes (or the caller pinned): against
// published values it catches a server bug or a compromised signing path; only a pin holds against
// a fully compromised server, which could publish a false fingerprint.
//
// Every object it reads — the key package, each disclosure, each signing package, the message and
// its intent — goes through strictParse and exact-case lookups, never encoding/json's struct
// decode: that decode matches keys case-insensitively and keeps the last of a repeated one, so a
// message carrying "intents" and then "Intents" would show this guard the second list while the
// case-sensitive verifier on chain executes the first. A repeated key, or a second spelling of a
// key read here, is refused.
func verifySigningDisclosure(q *Quote, packages, messages []json.RawMessage, keyPackage string, sendFingerprints []string) error {
	if len(messages) != len(packages) {
		return localError("co-sign refused: the server did not disclose the signing messages — refusing to blind-sign")
	}
	if len(sendFingerprints) == 0 {
		return localError("co-sign refused: the server did not publish an asset fingerprint — update the server")
	}
	expectedSigner, err := vaultSigner(keyPackage)
	if err != nil {
		return err
	}
	total := new(big.Int)

	for i, pkgRaw := range packages {
		disc, err := strictParseObject(messages[i])
		if err != nil {
			return localError("co-sign refused: malformed disclosure for source %d: %v", i, err)
		}
		message, okMessage, errMessage := disc.stringField("message")
		nonceHex, okNonce, errNonce := disc.stringField("nonce")
		recipient, okRecipient, errRecipient := disc.stringField("recipient")
		if err := errors.Join(errMessage, errNonce, errRecipient); err != nil {
			return localError("co-sign refused: malformed disclosure for source %d: %v", i, err)
		}
		if !okMessage || !okNonce || !okRecipient || message == "" || nonceHex == "" || recipient == "" {
			return localError("co-sign refused: malformed disclosure for source %d", i)
		}

		// (1) binding: the package about to be signed hashes to EXACTLY the disclosed message.
		nonce, err := hex.DecodeString(nonceHex)
		if err != nil {
			return localError("co-sign refused: bad nonce hex for source %d", i)
		}
		want, err := PayloadDigestHex(message, nonce, recipient, "")
		if err != nil {
			return localError("co-sign refused: bad disclosure for source %d: %v", i, err)
		}
		pkg, err := strictParseObject(pkgRaw)
		if err != nil {
			return localError("co-sign refused: signing package %d is unreadable: %v", i, err)
		}
		bound, _, err := pkg.stringField("message")
		if err != nil {
			return localError("co-sign refused: signing package %d is ambiguous: %v", i, err)
		}
		if !strings.EqualFold(bound, want) {
			return localError("co-sign refused: signing package %d does not bind to the disclosed message", i)
		}

		// (2) structure and own-vault: one transfer, signed from this vault and no other.
		amount, err := verifyTransferMessage(i, message, expectedSigner, sendFingerprints)
		if err != nil {
			return err
		}
		total.Add(total, amount)
	}

	// (3) no inflation: the sources together move no more than the approved debit.
	approved, err := rawInt(q.Debit.Amount)
	if err != nil {
		return err
	}
	if total.Cmp(approved) > 0 {
		return localError("co-sign refused: sources move %s, above the approved debit %s", total, approved)
	}
	return nil
}

// vaultSigner is this vault's group key, lowercased — what every disclosed signer_id must equal.
// Without it there is nothing to check the signer against, and an unchecked signer is a transfer
// from any vault the server likes, so its absence refuses.
func vaultSigner(keyPackage string) (string, error) {
	noKey := localError("co-sign refused: the vault key package has no verifying key to check the signer against")
	kp, err := strictParseObject([]byte(keyPackage))
	if err != nil {
		return "", noKey
	}
	vk, ok, err := kp.stringField("verifying_key")
	if err != nil {
		return "", localError("co-sign refused: the vault key package is ambiguous: %v", err)
	}
	if !ok || vk == "" {
		return "", noKey
	}
	return strings.ToLower(vk), nil
}

// verifyTransferMessage checks one disclosed message: a single transfer intent, signed from this
// vault, moving exactly one token whose id hashes to one of sendFingerprints, by a positive
// amount — which it returns. The message is read with strictParse and exact-case lookups, the way
// the on-chain verifier reads it.
func verifyTransferMessage(i int, message, expectedSigner string, sendFingerprints []string) (*big.Int, error) {
	root, err := strictParseObject([]byte(message))
	if err != nil {
		return nil, localError("co-sign refused: unreadable message for source %d: %v", i, err)
	}
	signerID, hasSigner, errSigner := root.stringField("signer_id")
	intentsRaw, _, errIntents := root.field("intents")
	if err := errors.Join(errSigner, errIntents); err != nil {
		return nil, localError("co-sign refused: unreadable message for source %d: %v", i, err)
	}
	intents, _ := intentsRaw.([]any)
	if len(intents) != 1 {
		return nil, localError("co-sign refused: source %d is not a single transfer", i)
	}
	intent, isObject := intents[0].(strictObject)
	if !isObject {
		return nil, localError("co-sign refused: source %d is not a single transfer", i)
	}
	kind, _, errKind := intent.stringField("intent")
	tokensRaw, _, errTokens := intent.field("tokens")
	if err := errors.Join(errKind, errTokens); err != nil {
		return nil, localError("co-sign refused: unreadable message for source %d: %v", i, err)
	}
	if kind != "transfer" {
		return nil, localError("co-sign refused: source %d is not a single transfer", i)
	}
	if !hasSigner || strings.ToLower(signerID) != expectedSigner {
		return nil, localError("co-sign refused: source %d signs from a different vault", i)
	}
	tokens, _ := tokensRaw.(strictObject)
	if len(tokens) != 1 {
		return nil, localError("co-sign refused: source %d does not transfer exactly one token", i)
	}
	for tokenID, value := range tokens {
		// The token, not only the amount: 10.025 of another asset is not the 10.025 USDC that
		// was approved.
		if !fingerprintIn(tokenFingerprint(tokenID), sendFingerprints) {
			return nil, localError("co-sign refused: source %d moves a different token than the approved send asset", i)
		}
		// A JSON string of ASCII digits, above zero. big.Int accepts a sign: a server could
		// disclose +2D on one source and -D on another, the total D would pass the debit check,
		// and the first source alone would move 2D. A transfer amount carries no sign and is
		// never zero; a JSON number is not what the server builds either.
		v, isString := value.(string)
		if !isString || !isDigits(v) {
			return nil, localError("co-sign refused: transfer amount for source %d is not a positive integer: %v", i, value)
		}
		amount, _ := new(big.Int).SetString(v, 10)
		if amount.Sign() <= 0 {
			return nil, localError("co-sign refused: transfer amount for source %d is not a positive integer: %q", i, v)
		}
		return amount, nil
	}
	return nil, localError("co-sign refused: source %d does not transfer exactly one token", i) // unreachable
}

// idempotencyKeyOf is the key a money call is sent under. "" — the zero value, which Go cannot
// tell from an explicit "" — is "none given" and gets a fresh key. A key of only whitespace is
// refused: sent, the server reads it as no key at all, and a retry would pay again while the caller
// believed it deduplicated.
func idempotencyKeyOf(key string) (string, error) {
	if key == "" {
		return freshIdempotencyKey(), nil
	}
	if strings.TrimSpace(key) == "" {
		return "", localError("IdempotencyKey is blank — pass a durable key (a payout or job id) so a retry replays the same movement, or leave it empty for a fresh one per call")
	}
	return key, nil
}

// freshIdempotencyKey returns uuid-v4-shaped hex without the dashes — the shape the other SDKs
// generate.
func freshIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}
