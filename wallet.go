package paymos

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The entry point, ported from the Python SDK via the TypeScript, Rust and .NET ones. Same
// methods, same guarantees, same refusals.

// progressedStatuses have already been signed; a retry must not sign again.
var progressedStatuses = map[string]bool{
	"signed": true, "relaying": true, "relayed": true,
	"settling": true, "completed": true, "failed": true,
}

// terminalStatuses settle a movement: no more polling.
var terminalStatuses = map[string]bool{
	"completed": true, "failed": true, "refunded": true, "expired": true, "cancelled": true,
}

const defaultBaseURL = "https://wallet.paymos.io"

// SwapOptions are the optional knobs of Wallet.Swap. Zero values mean "the SDK default".
type SwapOptions struct {
	SlippageBps    int    // default 50 (= 0.5%)
	MinReceive     string // human decimal floor on the guaranteed receive
	MaxDebit       string // human decimal ceiling on the total vault debit
	IdempotencyKey string // a durable payout id; a fresh one is generated when empty
}

// WithdrawOptions are the optional knobs of Wallet.Withdraw. Zero values mean "the SDK default".
type WithdrawOptions struct {
	Mode           string // "exact_out" (default) or "total_in"
	MaxDebit       string // human decimal ceiling on the total vault debit
	IdempotencyKey string // a durable payout id; a fresh one is generated when empty
}

// Wallet controls one vault. Construct with NewWallet or FromEnv. Not safe to copy after use.
type Wallet struct {
	secret     VaultSecret
	http       *httpTransport
	assetMu    sync.Mutex
	assetCache map[string]Asset
}

// NewWallet parses the vs_live_ secret and points the client at baseURL (or PAYMOS_BASE_URL,
// or the production default).
func NewWallet(secret, baseURL string, timeout time.Duration) (*Wallet, error) {
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
	return &Wallet{secret: s, http: newHTTP(baseURL, s.APIKey, timeout)}, nil
}

// FromEnv reads PAYMOS_VAULT_SECRET, the way a deployed process is configured.
func FromEnv() (*Wallet, error) {
	secret := os.Getenv("PAYMOS_VAULT_SECRET")
	if secret == "" {
		return nil, localError("PAYMOS_VAULT_SECRET is not set")
	}
	return NewWallet(secret, "", 0)
}

// ── reads ────────────────────────────────────────────────────────────────────

// Assets returns the curated asset catalog (fetched once and cached per Wallet).
func (w *Wallet) Assets() ([]Asset, error) {
	body, err := w.http.get("/vault/v1/assets", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Assets []Asset `json:"assets"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, localError("bad wire JSON: %v", err)
	}
	return out.Assets, nil
}

// Balances returns per-asset vault balances.
func (w *Wallet) Balances() ([]Balance, error) {
	body, err := w.http.get("/vault/v1/balances", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Balances []Balance `json:"balances"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, localError("bad wire JSON: %v", err)
	}
	return out.Balances, nil
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
// The server speaks keyset pagination: items + next_cursor.
func (w *Wallet) Movements(limit int, cursor string) (items []Movement, nextCursor string, err error) {
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
	return w.quote("/vault/v1/quote/swap", map[string]any{
		"send": send, "receive": receive, "amount": amount, "slippage_bps": slippageBps,
	}, true, "")
}

// QuoteWithdraw is a dry preview. Nothing is created and nothing is signed.
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
func (w *Wallet) Swap(send, receive, amount string, opts SwapOptions) (*Movement, error) {
	if err := w.requireShare("swap"); err != nil {
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
	idem := opts.IdempotencyKey
	if idem == "" {
		idem = freshIdempotencyKey()
	}

	q, err := w.quote("/vault/v1/quote/swap", map[string]any{
		"send": send, "receive": receive, "amount": amount, "slippage_bps": slippageBps,
	}, false, idem)
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
				"guaranteed receive %s is below the requested minimum %s (%s %s)",
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
func (w *Wallet) Withdraw(asset, amount, to string, opts WithdrawOptions) (*Movement, error) {
	if err := w.requireShare("withdraw"); err != nil {
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
	idem := opts.IdempotencyKey
	if idem == "" {
		idem = freshIdempotencyKey()
	}

	q, err := w.quote("/vault/v1/quote/withdraw", map[string]any{
		"asset": asset, "amount": amount, "to": to, "mode": mode,
	}, false, idem)
	if err != nil {
		return nil, err
	}

	// A withdraw is same-asset. For exact_out the approved amount is the guaranteed OUT; for
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

func (w *Wallet) requireShare(op string) error {
	if !w.secret.HasShare() {
		return localError("%s needs a full-scope secret: this one carries no co-signing share", op)
	}
	return nil
}

func (w *Wallet) assetMap() (map[string]Asset, error) {
	w.assetMu.Lock()
	defer w.assetMu.Unlock()
	if w.assetCache == nil {
		assets, err := w.Assets()
		if err != nil {
			return nil, err
		}
		w.assetCache = make(map[string]Asset, len(assets))
		for _, a := range assets {
			w.assetCache[a.Asset] = a
		}
	}
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

	kp := w.secret.Share
	if kp == "" {
		return localError("this secret carries no co-signing share")
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

	beginBody, _ := json.Marshal(map[string]any{"commitments": commitments})
	beginRaw, err := w.http.post("/vault/v1/movements/"+mid+"/sign/begin", beginBody, nil)
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
		Token           json.RawMessage   `json:"token"`
	}
	if err := json.Unmarshal(beginRaw, &beginTyped); err != nil {
		return localError("bad wire JSON: %v", err)
	}
	packages := beginTyped.SigningPackages
	if len(packages) != n {
		return localError("co-sign protocol mismatch: expected %d signing packages, got %d", n, len(packages))
	}

	if err := verifySigningDisclosure(q, packages, beginTyped.Messages, kp); err != nil {
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
	token := beginTyped.Token
	if len(token) == 0 {
		token = json.RawMessage("null")
	}
	aggBody, _ := json.Marshal(map[string]any{"token": token, "shares": shares})
	aggRaw, err := w.http.post("/vault/v1/movements/"+mid+"/sign/aggregate", aggBody, nil)
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

// verifyQuoteEcho refuses to sign unless the server's quote echoes what the caller approved.
// This is what makes co-signing a server-built movement safe: a units bug, contract drift or a
// compromised server changes one of these numbers, and the change is caught before a commitment
// exists. Empty strings mark the checks the caller did not ask for.
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
		got, err := rawInt(q.Receive.Min)
		if err != nil {
			return err
		}
		want, _ := rawInt(expectReceiveRaw)
		if got.Cmp(want) < 0 {
			return localError("quote guarantees %s, below the approved %s", q.Receive.Min, expectReceiveRaw)
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

// verifySigningDisclosure implements never blind-sign. The server discloses, per source, the
// plaintext message it wants signed. For each one this recomputes the digest and confirms the
// package about to be signed binds to exactly that message; confirms the message is a single
// transfer from THIS vault; and confirms the sources together move no more than the approved
// debit. Any mismatch aborts before a share is produced.
func verifySigningDisclosure(q *Quote, packages, messages []json.RawMessage, keyPackage string) error {
	if len(messages) != len(packages) {
		return localError("co-sign refused: the server did not disclose the signing messages — refusing to blind-sign")
	}
	var kp struct {
		VerifyingKey string `json:"verifying_key"`
	}
	_ = json.Unmarshal([]byte(keyPackage), &kp)
	expectedSigner := strings.ToLower(kp.VerifyingKey)
	total := new(big.Int)

	for i, pkgRaw := range packages {
		var disc struct {
			Message   string `json:"message"`
			Nonce     string `json:"nonce"`
			Recipient string `json:"recipient"`
		}
		if err := json.Unmarshal(messages[i], &disc); err != nil ||
			disc.Message == "" || disc.Nonce == "" || disc.Recipient == "" {
			return localError("co-sign refused: malformed disclosure for source %d", i)
		}

		// (1) binding: the package about to be signed hashes to EXACTLY the disclosed message.
		nonce, err := hex.DecodeString(disc.Nonce)
		if err != nil {
			return localError("co-sign refused: bad nonce hex for source %d", i)
		}
		want, err := PayloadDigestHex(disc.Message, nonce, disc.Recipient, "")
		if err != nil {
			return err
		}
		var pkg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(pkgRaw, &pkg)
		if !strings.EqualFold(pkg.Message, want) {
			return localError("co-sign refused: signing package %d does not bind to the disclosed message", i)
		}

		// (2) structure and own-vault: one transfer, signed from this vault and no other.
		var parsed struct {
			SignerID string `json:"signer_id"`
			Intents  []struct {
				Intent string            `json:"intent"`
				Tokens map[string]string `json:"tokens"`
			} `json:"intents"`
		}
		if err := json.Unmarshal([]byte(disc.Message), &parsed); err != nil {
			return localError("co-sign refused: unreadable message for source %d: %v", i, err)
		}
		if len(parsed.Intents) != 1 || parsed.Intents[0].Intent != "transfer" {
			return localError("co-sign refused: source %d is not a single transfer", i)
		}
		if expectedSigner != "" && strings.ToLower(parsed.SignerID) != expectedSigner {
			return localError("co-sign refused: source %d signs from a different vault", i)
		}
		tokens := parsed.Intents[0].Tokens
		if len(tokens) != 1 {
			return localError("co-sign refused: source %d does not transfer exactly one token", i)
		}
		for _, v := range tokens {
			amount, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return localError("co-sign refused: bad transfer amount for source %d", i)
			}
			total.Add(total, amount)
		}
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

// freshIdempotencyKey returns uuid-v4-shaped hex without the dashes — the shape the other SDKs
// generate.
func freshIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}
