// The wire contract: every response here is one the real server pipeline recorded
// (sdk/contract/fixtures), served through a mocked transport — no network, and no mock written
// from memory. Seven of eight SDKs once shipped reading {"assets": [...]} from an endpoint that
// has always answered a bare array, with suites that mocked the server their author imagined.
// This file exists so that cannot pass again: when a fixture changes, this suite notices.
//
// The fixtures are found by walking up from this file: contract/fixtures (the public mirror
// vendors them there), then sdk/contract/fixtures (the monorepo). Not finding them FAILS — a
// contract test that skips is a contract test that never runs.

package paymos

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

type wireFixture struct {
	Request struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	} `json:"request"`
	Response struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	} `json:"response"`
}

func fixturesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file to search for the contract fixtures")
	}
	start := filepath.Dir(file)
	for _, rel := range []string{filepath.Join("contract", "fixtures"), filepath.Join("sdk", "contract", "fixtures")} {
		for dir := start; ; {
			candidate := filepath.Join(dir, rel)
			if st, err := os.Stat(candidate); err == nil && st.IsDir() {
				return candidate
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	t.Fatalf("contract fixtures not found above %s (looked for contract/fixtures, then sdk/contract/fixtures)", start)
	return ""
}

func readFixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesDir(t), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func loadFixture(t *testing.T, name string) wireFixture {
	t.Helper()
	var f wireFixture
	if err := json.Unmarshal(readFixtureFile(t, name), &f); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return f
}

func decodeAny(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

// ── mocked transport ─────────────────────────────────────────────────────────

type sentRequest struct {
	Method string
	Target string // path, plus ?query when there is one
	Header http.Header
	Body   []byte
}

type cannedResponse struct {
	status      int
	contentType string
	body        []byte
}

// A proxy's 404 page: what an unrouted request gets, because that is what production answers
// when a path misses the API.
var htmlNotFound = cannedResponse{404, "text/html; charset=utf-8",
	[]byte("<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>")}

type wireMock struct {
	mu       sync.Mutex
	routes   map[string]cannedResponse
	handlers map[string]func(body []byte) cannedResponse
	requests []sentRequest
}

func (m *wireMock) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}
	target := r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	m.mu.Lock()
	m.requests = append(m.requests, sentRequest{r.Method, target, r.Header.Clone(), body})
	resp, ok := m.routes[r.Method+" "+target]
	handler := m.handlers[r.Method+" "+target]
	m.mu.Unlock()
	if handler != nil {
		resp, ok = handler(body), true
	}
	if !ok {
		resp = htmlNotFound
	}
	return &http.Response{
		StatusCode: resp.status,
		Header:     http.Header{"Content-Type": {resp.contentType}},
		Body:       io.NopCloser(bytes.NewReader(resp.body)),
		Request:    r,
	}, nil
}

func (m *wireMock) route(method, target string, status int, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[method+" "+target] = cannedResponse{status, "application/json; charset=utf-8", body}
}

// handle answers a route from the request body — the server half of a real co-sign.
func (m *wireMock) handle(method, target string, h func(body []byte) cannedResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[method+" "+target] = h
}

func (m *wireMock) serve(f wireFixture) {
	m.route(f.Request.Method, f.Request.Path, f.Response.Status, f.Response.Body)
}

func (m *wireMock) sent(method, target string) []sentRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sentRequest
	for _, r := range m.requests {
		if r.Method == method && r.Target == target {
			out = append(out, r)
		}
	}
	return out
}

func (m *wireMock) only(t *testing.T, method, target string) sentRequest {
	t.Helper()
	got := m.sent(method, target)
	if len(got) != 1 {
		t.Fatalf("%s %s sent %d times, want 1 (all: %v)", method, target, len(got), m.targets())
	}
	return got[0]
}

func (m *wireMock) targets() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.requests {
		out = append(out, r.Method+" "+r.Target)
	}
	return out
}

// contractWallet is a wallet whose every request goes to the mock. The catalog is served from
// its fixture, because every amount the SDK validates needs it.
func contractWallet(t *testing.T, share string) (*Wallet, *wireMock) {
	t.Helper()
	w, err := NewWallet(PackSecret("vk_live_contract", 7, share), "https://vault.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	m := &wireMock{routes: map[string]cannedResponse{}, handlers: map[string]func([]byte) cannedResponse{}}
	w.http.client.Transport = m
	m.serve(loadFixture(t, "assets.json"))
	return w, m
}

// realShare runs a local 2-of-2 DKG and returns this side's key package — the co-sign flow needs
// a key package the core accepts to get as far as sign/begin.
func realShare(t *testing.T) string {
	t.Helper()
	return realPair(t).client
}

// keyPair is both halves of one vault key: the client's key package (what a secret carries), the
// server's, and the public package the aggregate verifies against.
type keyPair struct {
	client, server string
	public         json.RawMessage
	verifyingKey   string
}

func realPair(t *testing.T) keyPair {
	t.Helper()
	a1 := callOp(t, `{"op":"dkg_part1","id":1,"max":2,"min":2}`)
	b1 := callOp(t, `{"op":"dkg_part1","id":2,"max":2,"min":2}`)
	a2 := callOp(t, `{"op":"dkg_part2","secret":`+string(rawOf(t, a1, "secret"))+
		`,"round1_packages":[[2,`+string(rawOf(t, b1, "package"))+`]]}`)
	b2 := callOp(t, `{"op":"dkg_part2","secret":`+string(rawOf(t, b1, "secret"))+
		`,"round1_packages":[[1,`+string(rawOf(t, a1, "package"))+`]]}`)
	a3 := callOp(t, `{"op":"dkg_part3","secret":`+string(rawOf(t, a2, "secret"))+
		`,"round1_packages":[[2,`+string(rawOf(t, b1, "package"))+`]],"round2_packages":[[2,`+
		string(packageFor(t, b2["packages"], 1))+`]]}`)
	b3 := callOp(t, `{"op":"dkg_part3","secret":`+string(rawOf(t, b2, "secret"))+
		`,"round1_packages":[[1,`+string(rawOf(t, a1, "package"))+`]],"round2_packages":[[1,`+
		string(packageFor(t, a2["packages"], 2))+`]]}`)
	kp := keyPair{
		client: string(rawOf(t, a3, "key_package")),
		server: string(rawOf(t, b3, "key_package")),
		public: rawOf(t, a3, "public_key_package"),
	}
	var vk struct {
		VerifyingKey string `json:"verifying_key"`
	}
	if err := json.Unmarshal([]byte(kp.client), &vk); err != nil || vk.VerifyingKey == "" {
		t.Fatalf("the client key package carries no verifying_key: %v", err)
	}
	kp.verifyingKey = vk.VerifyingKey
	return kp
}

// ── assertions ───────────────────────────────────────────────────────────────

// assertCovers checks that every field the server sent survives into the parsed model with its
// value: the model is marshalled back (its tags are the wire names) and each fixture leaf must be
// found in it. A field the model does not carry, or reads under the wrong name, fails here.
func assertCovers(t *testing.T, fixtureBody json.RawMessage, parsed any) {
	t.Helper()
	back, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	covers(t, decodeAny(t, fixtureBody), decodeAny(t, back), "$")
}

func covers(t *testing.T, want, got any, path string) {
	t.Helper()
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s: model has %T, the wire sent an object", path, got)
		}
		for k, v := range w {
			gv, present := g[k]
			if !present {
				t.Fatalf("%s.%s: sent by the server, missing from the model", path, k)
			}
			covers(t, v, gv, path+"."+k)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			t.Fatalf("%s: model has %v, the wire sent %d items", path, got, len(w))
		}
		for i := range w {
			covers(t, w[i], g[i], path+"["+strconv.Itoa(i)+"]")
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: model has %#v, the wire sent %#v", path, got, want)
		}
	}
}

// assertSentBody checks the request the SDK built against the recorded one: every field the
// fixture carries, with the same JSON type (amount a string, slippage_bps a number, dry a bool),
// and nothing else except dry:false, which the fixture leaves to the server's default.
func assertSentBody(t *testing.T, sent []byte, fixtureBody json.RawMessage) {
	t.Helper()
	got, ok := decodeAny(t, sent).(map[string]any)
	if !ok {
		t.Fatalf("sent body is not an object: %s", sent)
	}
	want := decodeAny(t, fixtureBody).(map[string]any)
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Fatalf("sent %q = %#v, the contract has %#v (sent %s)", k, got[k], v, sent)
		}
	}
	for k, v := range got {
		if _, inFixture := want[k]; inFixture {
			continue
		}
		if k == "dry" && v == false {
			continue
		}
		t.Fatalf("sent %q = %#v, which the contract request does not carry (sent %s)", k, v, sent)
	}
}

func asPaymosError(t *testing.T, err error) *Error {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("want *paymos.Error, got %T: %v", err, err)
	}
	return pe
}

// ── the suite knows every fixture ────────────────────────────────────────────

func TestContractEveryFixtureHasATest(t *testing.T) {
	covered := map[string]bool{
		"assets.json": true, "balances.json": true,
		"quote_withdraw_dry.json": true, "quote_withdraw.json": true, "quote_withdraw_total_in.json": true,
		"quote_swap_dry.json": true, "quote_swap.json": true,
		"movements_page.json": true, "movement.json": true,
		"sign_begin.json": true, "sign_begin_error.json": true,
		"sign_aggregate.json": true, "sign_aggregate_error.json": true,
		"vocabulary.json": true,
		"error_400.json":  true, "error_400_body.json": true, "error_401.json": true, "error_403.json": true,
		"error_404_movement.json": true, "error_404_path.json": true, "error_409_idempotency.json": true,
	}
	entries, err := os.ReadDir(fixturesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the fixtures directory is empty")
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && !covered[e.Name()] {
			t.Errorf("fixture %s has no contract test in the Go SDK — add one", e.Name())
		}
	}
}

// ── reads ────────────────────────────────────────────────────────────────────

func TestContractAssetsIsABareArray(t *testing.T) {
	w, m := contractWallet(t, "")
	f := loadFixture(t, "assets.json")
	assets, err := w.Assets()
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 || assets[0].Asset != "USDC@base" || assets[0].Decimals != 6 ||
		assets[0].Fingerprint != "a42c7e46411394e7c7719eef5be19239b2716b91d3a4a843fd3d2c0b6ca16b7c" {
		t.Fatalf("assets = %+v", assets)
	}
	assertCovers(t, f.Response.Body, assets)

	// Cached: the decimals every conversion needs come from the one call.
	if _, err := w.Assets(); err != nil {
		t.Fatal(err)
	}
	if dec, err := w.decimalsOf("USDT@base"); err != nil || dec != 6 {
		t.Fatalf("decimalsOf = %d, %v", dec, err)
	}
	m.only(t, "GET", "/vault/v1/assets")
}

func TestContractAssetsRefusesTheWrapperShapeLoudly(t *testing.T) {
	w, m := contractWallet(t, "")
	m.route("GET", "/vault/v1/assets", 200, []byte(`{"assets":[{"asset":"USDC@base","symbol":"USDC","chain":"base","decimals":6}]}`))
	if _, err := w.Assets(); err == nil {
		t.Fatal("an object where the contract has an array must fail, not read as an empty catalog")
	} else {
		asPaymosError(t, err)
	}
}

func TestContractBalances(t *testing.T) {
	w, m := contractWallet(t, "")
	f := loadFixture(t, "balances.json")
	m.serve(f)
	balances, err := w.Balances()
	if err != nil {
		t.Fatal(err)
	}
	if len(balances) != 1 || balances[0].AmountRaw != "1000000000" || balances[0].USD != "1000" {
		t.Fatalf("balances = %+v", balances)
	}
	assertCovers(t, f.Response.Body, balances)

	// usd is omitted, not null, when an asset is unpriced.
	m.route("GET", "/vault/v1/balances", 200,
		[]byte(`[{"asset":"USDC@base","symbol":"USDC","chain":"base","decimals":6,"amount_raw":"5"}]`))
	balances, err = w.Balances()
	if err != nil || len(balances) != 1 || balances[0].USD != "" || balances[0].AmountRaw != "5" {
		t.Fatalf("balances without usd = %+v, %v", balances, err)
	}
}

func TestContractMovementsPage(t *testing.T) {
	w, m := contractWallet(t, "")
	f := loadFixture(t, "movements_page.json")
	m.serve(f)
	items, next, err := w.Movements(2, "")
	if err != nil {
		t.Fatal(err)
	}
	m.only(t, "GET", "/vault/v1/movements?limit=2")
	if len(items) != 2 || next != "cursor_1" {
		t.Fatalf("items = %d, next = %q", len(items), next)
	}
	var body struct {
		Items json.RawMessage `json:"items"`
	}
	_ = json.Unmarshal(f.Response.Body, &body)
	assertCovers(t, body.Items, items)
	for _, mv := range items {
		// A list row carries no fee legs and no settlement yet: omitted on the wire.
		if mv.Fees != nil || mv.DestChainTxHash != "" || mv.CompletedAt != "" {
			t.Fatalf("summary row carried absent fields: %+v", mv)
		}
	}
	if items[1].Type != "withdrawal" || items[1].Receive.Min != "9975062" {
		t.Fatalf("second row = %+v", items[1])
	}

	// The cursor goes back verbatim; the last page omits next_cursor.
	m.route("GET", "/vault/v1/movements?cursor=cursor_1&limit=2", 200, []byte(`{"items":[]}`))
	items, next, err = w.Movements(2, next)
	if err != nil || len(items) != 0 || next != "" {
		t.Fatalf("last page = %v, %q, %v", items, next, err)
	}
}

func TestContractMovementWithFees(t *testing.T) {
	w, m := contractWallet(t, "")
	f := loadFixture(t, "movement.json")
	m.serve(f)
	mv, err := w.Movement("mv_3")
	if err != nil {
		t.Fatal(err)
	}
	assertCovers(t, f.Response.Body, mv)
	if mv.Fees == nil || mv.Fees.Route == nil || !mv.Fees.Route.Estimate || mv.Fees.USD["total"] != "0" {
		t.Fatalf("fees = %+v", mv.Fees)
	}
	if mv.Status != "pending" || mv.CompletedAt != "" || mv.DestChainExplorerURL != "" {
		t.Fatalf("movement = %+v", mv)
	}
}

// ── quotes ───────────────────────────────────────────────────────────────────

func TestContractQuoteWithdrawDry(t *testing.T) {
	w, m := contractWallet(t, "")
	f := loadFixture(t, "quote_withdraw_dry.json")
	m.serve(f)
	q, err := w.QuoteWithdraw("USDC@base", "10", "0xabc0000000000000000000000000000000000000", "exact_out")
	if err != nil {
		t.Fatal(err)
	}
	req := m.only(t, f.Request.Method, f.Request.Path)
	assertSentBody(t, req.Body, f.Request.Body)
	if req.Header.Get("Idempotency-Key") != "" {
		t.Fatal("a dry preview must not carry an Idempotency-Key")
	}
	assertCovers(t, f.Response.Body, q)
	// A preview persists nothing: no movement, nothing to sign.
	if q.MovementID != "" || q.Sources != nil {
		t.Fatalf("dry quote carried movement fields: %+v", q)
	}
	if q.Debit.Amount != "10025000" || q.Fees.Platform != "25000" || q.Fees.Route.Estimate {
		t.Fatalf("quote = %+v", q)
	}
}

func TestContractQuoteSwapDry(t *testing.T) {
	w, m := contractWallet(t, "")
	f := loadFixture(t, "quote_swap_dry.json")
	m.serve(f)
	q, err := w.QuoteSwap("USDC@base", "USDT@base", "5", 50)
	if err != nil {
		t.Fatal(err)
	}
	req := m.only(t, f.Request.Method, f.Request.Path)
	assertSentBody(t, req.Body, f.Request.Body)
	if req.Header.Get("Idempotency-Key") != "" {
		t.Fatal("a dry preview must not carry an Idempotency-Key")
	}
	assertCovers(t, f.Response.Body, q)
	if q.MovementID != "" || q.Sources != nil || q.Receive.Asset != "USDT@base" {
		t.Fatalf("quote = %+v", q)
	}
}

// The three quotes that create a movement parse in full, and the request carries the key.
func TestContractNonDryQuotesParse(t *testing.T) {
	for _, tc := range []struct {
		fixture, movementID string
		sources             int
	}{
		{"quote_withdraw.json", "mv_1", 2},
		{"quote_withdraw_total_in.json", "mv_2", 2},
		{"quote_swap.json", "mv_3", 1},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			w, m := contractWallet(t, "")
			f := loadFixture(t, tc.fixture)
			m.serve(f)
			var body map[string]any
			_ = json.Unmarshal(f.Request.Body, &body)
			q, err := w.quote(f.Request.Path, body, false, "idem-contract")
			if err != nil {
				t.Fatal(err)
			}
			req := m.only(t, f.Request.Method, f.Request.Path)
			assertSentBody(t, req.Body, f.Request.Body)
			if req.Header.Get("Idempotency-Key") != "idem-contract" {
				t.Fatalf("Idempotency-Key = %q", req.Header.Get("Idempotency-Key"))
			}
			assertCovers(t, f.Response.Body, q)
			if q.MovementID != tc.movementID || q.Sources == nil || *q.Sources != tc.sources {
				t.Fatalf("quote = %+v", q)
			}
		})
	}
}

// Withdraw sends exactly the recorded request, commits once per source, and — when sign/begin
// meets a proxy's HTML 404 — surfaces a typed error without ever reaching sign/aggregate.
func TestContractWithdrawSendsTheRecordedRequest(t *testing.T) {
	share := realShare(t)
	for _, tc := range []struct {
		fixture, mode, movementID string
	}{
		{"quote_withdraw.json", "exact_out", "mv_1"},
		{"quote_withdraw_total_in.json", "total_in", "mv_2"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			w, m := contractWallet(t, share)
			f := loadFixture(t, tc.fixture)
			m.serve(f)
			_, err := w.Withdraw("USDC@base", "10", "0xabc0000000000000000000000000000000000000",
				WithdrawOptions{Mode: tc.mode, IdempotencyKey: "payout-42"})
			pe := asPaymosError(t, err)
			if pe.Status != 404 || !strings.Contains(pe.Message, "HTML") || strings.Contains(pe.Message, "<") {
				t.Fatalf("error = %+v", pe)
			}

			req := m.only(t, f.Request.Method, f.Request.Path)
			assertSentBody(t, req.Body, f.Request.Body)
			if req.Header.Get("Idempotency-Key") != "payout-42" {
				t.Fatalf("Idempotency-Key = %q", req.Header.Get("Idempotency-Key"))
			}
			begin := m.only(t, "POST", "/vault/v1/movements/"+tc.movementID+"/sign/begin")
			var sent struct {
				Commitments []json.RawMessage `json:"commitments"`
			}
			_ = json.Unmarshal(begin.Body, &sent)
			if len(sent.Commitments) != 2 {
				t.Fatalf("sources: 2 → %d commitments", len(sent.Commitments))
			}
			if len(m.sent("POST", "/vault/v1/movements/"+tc.movementID+"/sign/aggregate")) != 0 {
				t.Fatal("sign/aggregate reached after a failed sign/begin")
			}
		})
	}
}

// ── co-sign ──────────────────────────────────────────────────────────────────

// The recorded sign/begin is placeholders that do not verify. That is exactly what the blind-sign
// guard is for: it must refuse before a single share is produced.
func TestContractSwapRefusesAnUnverifiableDisclosure(t *testing.T) {
	w, m := contractWallet(t, realShare(t))
	quote := loadFixture(t, "quote_swap.json")
	begin := loadFixture(t, "sign_begin.json")
	m.serve(quote)
	m.serve(begin)

	_, err := w.Swap("USDC@base", "USDT@base", "5", SwapOptions{IdempotencyKey: "swap-1"})
	pe := asPaymosError(t, err)
	if !strings.Contains(pe.Message, "co-sign refused") {
		t.Fatalf("error = %v", pe)
	}

	assertSentBody(t, m.only(t, quote.Request.Method, quote.Request.Path).Body, quote.Request.Body)
	var sent struct {
		Commitments []json.RawMessage `json:"commitments"`
	}
	_ = json.Unmarshal(m.only(t, begin.Request.Method, begin.Request.Path).Body, &sent)
	if len(sent.Commitments) != 1 {
		t.Fatalf("sources: 1 → %d commitments", len(sent.Commitments))
	}
	if len(m.sent("POST", "/vault/v1/movements/mv_3/sign/aggregate")) != 0 {
		t.Fatal("signed a disclosure that does not verify")
	}
}

// sign/begin rejected: converge on the movement only when it has progressed (Python's
// _PROGRESSED_STATUSES), for every status the server can report.
func TestContractSignBeginRejectionConvergesOnlyOnProgress(t *testing.T) {
	share := realShare(t)
	var vocab struct {
		MovementStatuses []string `json:"movement_statuses"`
	}
	if err := json.Unmarshal(readFixtureFile(t, "vocabulary.json"), &vocab); err != nil {
		t.Fatal(err)
	}
	pythonProgressed := map[string]bool{"processing": true, "completed": true, "refunded": true}
	beginErr := loadFixture(t, "sign_begin_error.json")
	movement := loadFixture(t, "movement.json")

	for _, status := range vocab.MovementStatuses {
		t.Run(status, func(t *testing.T) {
			w, m := contractWallet(t, share)
			m.serve(loadFixture(t, "quote_swap.json"))
			m.route("POST", "/vault/v1/movements/mv_3/sign/begin", beginErr.Response.Status, beginErr.Response.Body)
			var mv map[string]any
			_ = json.Unmarshal(movement.Response.Body, &mv)
			mv["status"] = status
			body, _ := json.Marshal(mv)
			m.route("GET", movement.Request.Path, 200, body)

			got, err := w.Swap("USDC@base", "USDT@base", "5", SwapOptions{})
			if pythonProgressed[status] {
				if err != nil || got == nil || got.Status != status {
					t.Fatalf("a %s movement must converge: %+v, %v", status, got, err)
				}
			} else {
				pe := asPaymosError(t, err)
				if pe.Status != 400 || pe.Message != "commitments are required" {
					t.Fatalf("a %s movement must surface the rejection: %+v", status, pe)
				}
			}
			if len(m.sent("POST", "/vault/v1/movements/mv_3/sign/aggregate")) != 0 {
				t.Fatal("sign/aggregate reached after a rejected sign/begin")
			}
		})
	}
}

func TestContractSignAggregate(t *testing.T) {
	ok := loadFixture(t, "sign_aggregate.json")
	var okReq struct {
		Token  string            `json:"token"`
		Shares []json.RawMessage `json:"shares"`
	}
	_ = json.Unmarshal(ok.Request.Body, &okReq)

	w, m := contractWallet(t, "")
	m.serve(ok)
	if err := w.signAggregate("/vault/v1/movements/mv_3", okReq.Token, okReq.Shares); err != nil {
		t.Fatalf("ok:true must pass: %v", err)
	}
	assertSentBody(t, m.only(t, ok.Request.Method, ok.Request.Path).Body, ok.Request.Body)

	// ok:false on a 400 is a typed error carrying the server's message.
	bad := loadFixture(t, "sign_aggregate_error.json")
	w, m = contractWallet(t, "")
	m.serve(bad)
	err := w.signAggregate("/vault/v1/movements/mv_3", "", []json.RawMessage{})
	pe := asPaymosError(t, err)
	if pe.Status != 400 || pe.Kind != KindGeneral || pe.Message != "token and shares are required" {
		t.Fatalf("error = %+v", pe)
	}
	assertSentBody(t, m.only(t, bad.Request.Method, bad.Request.Path).Body, bad.Request.Body)

	// ok:false on a 2xx is still a refusal, never a success.
	for body, want := range map[string]string{
		`{"ok":false,"status":"failed","error":"relay rejected"}`: "relay rejected",
		`{"ok":false,"status":"failed"}`:                          "sign failed",
	} {
		w, m = contractWallet(t, "")
		m.route("POST", "/vault/v1/movements/mv_3/sign/aggregate", 200, []byte(body))
		err := w.signAggregate("/vault/v1/movements/mv_3", "t", nil)
		if pe := asPaymosError(t, err); pe.Message != want {
			t.Fatalf("%s → %q, want %q", body, pe.Message, want)
		}
	}
}

// ── statuses ─────────────────────────────────────────────────────────────────

func TestContractStatusVocabulary(t *testing.T) {
	var vocab struct {
		MovementStatuses []string `json:"movement_statuses"`
		SignStatuses     []string `json:"sign_statuses"`
	}
	if err := json.Unmarshal(readFixtureFile(t, "vocabulary.json"), &vocab); err != nil {
		t.Fatal(err)
	}
	if len(vocab.MovementStatuses) == 0 {
		t.Fatal("vocabulary.json lists no movement statuses")
	}
	// Python's _TERMINAL_STATUSES and _PROGRESSED_STATUSES, verbatim.
	pythonTerminal := map[string]bool{"completed": true, "failed": true, "refunded": true, "expired": true, "cancelled": true}
	pythonProgressed := map[string]bool{"processing": true, "completed": true, "refunded": true}

	known := map[string]bool{}
	for _, s := range vocab.MovementStatuses {
		known[s] = true
		if terminalStatuses[s] != pythonTerminal[s] {
			t.Errorf("%q: terminal = %v, Python says %v", s, terminalStatuses[s], pythonTerminal[s])
		}
		if progressedStatuses[s] != pythonProgressed[s] {
			t.Errorf("%q: progressed = %v, Python says %v", s, progressedStatuses[s], pythonProgressed[s])
		}
	}
	// No word the server never sends: an invented status is a branch that never runs.
	for _, set := range []map[string]bool{terminalStatuses, progressedStatuses} {
		var words []string
		for s := range set {
			words = append(words, s)
		}
		sort.Strings(words)
		for _, s := range words {
			if !known[s] {
				t.Errorf("status %q is not in the server's vocabulary", s)
			}
		}
	}
	// The sign flow reports its own statuses; the aggregate fixtures use words from that list.
	signKnown := map[string]bool{}
	for _, s := range vocab.SignStatuses {
		signKnown[s] = true
	}
	for _, name := range []string{"sign_aggregate.json", "sign_aggregate_error.json"} {
		var body struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(loadFixture(t, name).Response.Body, &body)
		if !signKnown[body.Status] {
			t.Errorf("%s: sign status %q is not in the vocabulary", name, body.Status)
		}
	}
}

func TestContractWaitStopsExactlyOnTerminalStatuses(t *testing.T) {
	var vocab struct {
		MovementStatuses []string `json:"movement_statuses"`
	}
	_ = json.Unmarshal(readFixtureFile(t, "vocabulary.json"), &vocab)
	movement := loadFixture(t, "movement.json")
	for _, status := range vocab.MovementStatuses {
		w, m := contractWallet(t, "")
		var mv map[string]any
		_ = json.Unmarshal(movement.Response.Body, &mv)
		mv["status"] = status
		body, _ := json.Marshal(mv)
		m.route("GET", movement.Request.Path, 200, body)

		got, err := w.Wait("mv_3", time.Millisecond, time.Millisecond)
		if terminalStatuses[status] {
			if err != nil || got.Status != status {
				t.Fatalf("%s: Wait = %+v, %v", status, got, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("%s is not terminal, Wait must keep polling: %v", status, err)
		}
	}
}

// ── errors ───────────────────────────────────────────────────────────────────

func TestContractErrorsMapToTypedKinds(t *testing.T) {
	const to = "0xabc0000000000000000000000000000000000000"
	for _, tc := range []struct {
		fixture   string
		share     string
		call      func(*Wallet) error
		kind      Kind
		checkSent bool
	}{
		// The recorded 400 and 403 are movement-creating (non-dry) quotes: a withdraw.
		{"error_400.json", `{"k":1}`, func(w *Wallet) error {
			_, err := w.Withdraw("USDC@base", "10", to, WithdrawOptions{Mode: "exact-out"})
			return err
		}, KindGeneral, true},
		{"error_400_body.json", "", func(w *Wallet) error {
			_, err := w.QuoteWithdraw("USDC@base", "10", to, "exact_out")
			return err
		}, KindGeneral, false}, // the recorded request is malformed JSON, which the SDK cannot send
		{"error_401.json", "", func(w *Wallet) error {
			_, err := w.Balances()
			return err
		}, KindAuth, false},
		{"error_403.json", `{"k":1}`, func(w *Wallet) error {
			_, err := w.Withdraw("USDC@base", "10", to, WithdrawOptions{})
			return err
		}, KindForbidden, true},
		{"error_404_movement.json", "", func(w *Wallet) error {
			_, err := w.Movement("does-not-exist")
			return err
		}, KindGeneral, false},
		{"error_404_path.json", "", func(w *Wallet) error {
			_, err := w.http.get("/vault/v1/no-such-endpoint", nil)
			return err
		}, KindGeneral, false},
		{"error_409_idempotency.json", `{"k":1}`, func(w *Wallet) error {
			_, err := w.Withdraw("USDC@base", "11", to, WithdrawOptions{IdempotencyKey: "reused"})
			return err
		}, KindConflict, true},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			w, m := contractWallet(t, tc.share)
			f := loadFixture(t, tc.fixture)
			m.serve(f)
			pe := asPaymosError(t, tc.call(w))
			var body struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(f.Response.Body, &body)
			if pe.Kind != tc.kind || pe.Status != f.Response.Status || pe.Message != body.Error {
				t.Fatalf("got kind %v status %d %q, want kind %v status %d %q",
					pe.Kind, pe.Status, pe.Message, tc.kind, f.Response.Status, body.Error)
			}
			req := m.only(t, f.Request.Method, f.Request.Path)
			if tc.checkSent {
				assertSentBody(t, req.Body, f.Request.Body)
			}
		})
	}
}

func TestContractHTMLInsteadOfJSONIsATypedError(t *testing.T) {
	// A proxy's 404 page where the API should be.
	w, _ := contractWallet(t, "")
	_, err := w.Balances()
	pe := asPaymosError(t, err)
	if pe.Status != 404 || pe.Kind != KindGeneral || !strings.Contains(pe.Message, "HTML") ||
		strings.Contains(pe.Message, "<") {
		t.Fatalf("error = %+v", pe)
	}

	// The same page with a 200: a site's fallback route answering on the API's path.
	w, m := contractWallet(t, "")
	m.mu.Lock()
	m.routes["GET /vault/v1/balances"] = cannedResponse{200, "text/html", htmlNotFound.body}
	m.mu.Unlock()
	_, err = w.Balances()
	pe = asPaymosError(t, err)
	if pe.Status != 200 || !strings.Contains(pe.Message, "HTML") {
		t.Fatalf("error = %+v", pe)
	}
}

// ── a real co-sign against the fixtures ──────────────────────────────────────

// serverCosign plays the server's half for real: sign/begin commits with the server's key package
// and builds a signing package over the digest of the transfers it discloses; sign/aggregate
// signs, aggregates and answers ok only if the 2-of-2 signature verifies.
func serverCosign(t *testing.T, m *wireMock, pair keyPair, movementID string, transfers []map[string]string) *bool {
	t.Helper()
	verified := new(bool)
	var mu sync.Mutex
	var signingPackages []json.RawMessage
	var serverNonces []json.RawMessage
	base := "/vault/v1/movements/" + movementID

	m.handle("POST", base+"/sign/begin", func(body []byte) cannedResponse {
		var req struct {
			Commitments []json.RawMessage `json:"commitments"`
		}
		_ = json.Unmarshal(body, &req)
		if len(req.Commitments) != len(transfers) {
			return cannedResponse{400, "application/json", []byte(`{"error":"commitments do not match the sources"}`)}
		}
		var messages []json.RawMessage
		mu.Lock()
		defer mu.Unlock()
		for i, tokens := range transfers {
			message := transferMessage(pair.verifyingKey, tokens)
			nonce := make([]byte, 32)
			nonce[31] = byte(i + 1)
			digest, _ := PayloadDigestHex(message, nonce, guardRecipient, "")
			server := callOp(t, `{"op":"commit","key_package":`+pair.server+`}`)
			pkg := callOp(t, `{"op":"build_signing_package","commitments":[[1,`+string(req.Commitments[i])+
				`],[2,`+string(rawOf(t, server, "commitments"))+`]],"message_hex":"`+digest+`"}`)
			signingPackages = append(signingPackages, rawOf(t, pkg, "signing_package"))
			serverNonces = append(serverNonces, rawOf(t, server, "nonces"))
			d, _ := json.Marshal(map[string]string{
				"message": message, "nonce": hex.EncodeToString(nonce), "recipient": guardRecipient,
			})
			messages = append(messages, d)
		}
		out, _ := json.Marshal(map[string]any{
			"token": "sign-session-token", "signing_packages": signingPackages, "messages": messages,
		})
		return cannedResponse{200, "application/json", out}
	})

	m.handle("POST", base+"/sign/aggregate", func(body []byte) cannedResponse {
		var req struct {
			Token  string            `json:"token"`
			Shares []json.RawMessage `json:"shares"`
		}
		_ = json.Unmarshal(body, &req)
		mu.Lock()
		defer mu.Unlock()
		if req.Token != "sign-session-token" || len(req.Shares) != len(signingPackages) {
			return cannedResponse{400, "application/json", []byte(`{"ok":false,"status":"failed","error":"token and shares are required"}`)}
		}
		all := true
		for i, pkg := range signingPackages {
			serverShare := callOp(t, `{"op":"sign","signing_package":`+string(pkg)+
				`,"nonces":`+string(serverNonces[i])+`,"key_package":`+pair.server+`}`)
			agg := callOp(t, `{"op":"aggregate","signing_package":`+string(pkg)+
				`,"signature_shares":[[1,`+string(req.Shares[i])+`],[2,`+string(rawOf(t, serverShare, "signature_share"))+
				`]],"public_key_package":`+string(pair.public)+`}`)
			all = all && agg["verified"] == true
		}
		*verified = all
		if !all {
			return cannedResponse{400, "application/json", []byte(`{"ok":false,"status":"failed","error":"signature does not verify"}`)}
		}
		return cannedResponse{200, "application/json", []byte(`{"ok":true,"status":"processing"}`)}
	})
	return verified
}

// The honest path end to end: the recorded swap quote, a disclosure of the send asset's own token
// ("usdc-base", whose SHA-256 is USDC@base's fingerprint in assets.json), a real 2-of-2 signature.
func TestContractSwapCoSignsAnHonestDisclosureForReal(t *testing.T) {
	pair := realPair(t)
	w, m := contractWallet(t, pair.client)
	m.serve(loadFixture(t, "quote_swap.json"))
	m.serve(loadFixture(t, "movement.json"))
	verified := serverCosign(t, m, pair, "mv_3", []map[string]string{{"usdc-base": "5000000"}})

	mv, err := w.Swap("USDC@base", "USDT@base", "5", SwapOptions{})
	if err != nil {
		t.Fatalf("an honest disclosure must sign: %v", err)
	}
	if !*verified || mv.ID != "mv_3" {
		t.Fatalf("verified = %v, movement = %+v", *verified, mv)
	}
	m.only(t, "POST", "/vault/v1/movements/mv_3/sign/aggregate")
}

// Same flow, but the server discloses another catalog asset's token (USDT@base's) against a debit
// approved in USDC. Refused before a share exists.
func TestContractSwapRefusesAnotherAssetsToken(t *testing.T) {
	pair := realPair(t)
	w, m := contractWallet(t, pair.client)
	m.serve(loadFixture(t, "quote_swap.json"))
	serverCosign(t, m, pair, "mv_3", []map[string]string{{"usdt-base": "5000000"}})

	_, err := w.Swap("USDC@base", "USDT@base", "5", SwapOptions{})
	if pe := asPaymosError(t, err); !strings.Contains(pe.Message, "different token") {
		t.Fatalf("error = %v", pe)
	}
	if len(m.sent("POST", "/vault/v1/movements/mv_3/sign/aggregate")) != 0 {
		t.Fatal("a transfer of another asset reached sign/aggregate")
	}
}

// The sign-flaw that motivated the digit rule, end to end: 2D on one source and -D on another.
func TestContractSwapRefusesANegativeSourceDisclosure(t *testing.T) {
	pair := realPair(t)
	w, m := contractWallet(t, pair.client)
	var q map[string]any
	_ = json.Unmarshal(loadFixture(t, "quote_swap.json").Response.Body, &q)
	q["sources"] = 2 // approved debit D = 5000000
	body, _ := json.Marshal(q)
	m.route("POST", "/vault/v1/quote/swap", 200, body)
	serverCosign(t, m, pair, "mv_3", []map[string]string{{"usdc-base": "10000000"}, {"usdc-base": "-5000000"}})

	_, err := w.Swap("USDC@base", "USDT@base", "5", SwapOptions{})
	if pe := asPaymosError(t, err); !strings.Contains(pe.Message, "co-sign refused") {
		t.Fatalf("error = %v", pe)
	}
	if len(m.sent("POST", "/vault/v1/movements/mv_3/sign/aggregate")) != 0 {
		t.Fatal("a 2D/-D disclosure reached sign/aggregate")
	}
}

// A server that predates the fingerprint: reads keep working, a co-sign is refused before a
// nonce exists — not a single sign/begin is sent.
func TestContractNoFingerprintReadsButNeverCoSigns(t *testing.T) {
	pair := realPair(t)
	w, m := contractWallet(t, pair.client)
	var assets []map[string]any
	_ = json.Unmarshal(loadFixture(t, "assets.json").Response.Body, &assets)
	for _, a := range assets {
		delete(a, "fingerprint")
	}
	body, _ := json.Marshal(assets)
	m.route("GET", "/vault/v1/assets", 200, body)
	m.serve(loadFixture(t, "quote_swap.json"))
	serverCosign(t, m, pair, "mv_3", []map[string]string{{"usdc-base": "5000000"}})

	list, err := w.Assets()
	if err != nil || len(list) != 2 || list[0].Fingerprint != "" {
		t.Fatalf("assets without fingerprint = %+v, %v", list, err)
	}
	if _, err := w.QuoteSwap("USDC@base", "USDT@base", "5", 50); err != nil {
		t.Fatalf("a preview needs no fingerprint: %v", err)
	}

	_, err = w.Swap("USDC@base", "USDT@base", "5", SwapOptions{})
	if pe := asPaymosError(t, err); !strings.Contains(pe.Message, "did not publish an asset fingerprint") {
		t.Fatalf("error = %v", pe)
	}
	if n := len(m.sent("POST", "/vault/v1/movements/mv_3/sign/begin")); n != 0 {
		t.Fatalf("sign/begin sent %d times without a fingerprint", n)
	}
}

// ── one label, several fingerprints; pinned fingerprints ────────────────────

// catalogWith serves /assets as the fixture's catalog with USDC@base's entries replaced by one
// entry per given fingerprint ("" = the entry carries none).
func catalogWith(t *testing.T, m *wireMock, usdcFingerprints ...string) {
	t.Helper()
	var assets []map[string]any
	_ = json.Unmarshal(loadFixture(t, "assets.json").Response.Body, &assets)
	var out []map[string]any
	for _, a := range assets {
		if a["asset"] != "USDC@base" {
			out = append(out, a)
			continue
		}
		for _, fp := range usdcFingerprints {
			entry := map[string]any{}
			for k, v := range a {
				entry[k] = v
			}
			if fp == "" {
				delete(entry, "fingerprint")
			} else {
				entry["fingerprint"] = fp
			}
			out = append(out, entry)
		}
	}
	body, _ := json.Marshal(out)
	m.route("GET", "/vault/v1/assets", 200, body)
}

// swapWithToken runs the recorded swap through a real co-sign whose server discloses a transfer of
// token, and reports whether it signed and whether sign/aggregate was reached.
func swapWithToken(t *testing.T, pair keyPair, token string, setup func(*wireMock), opts ...Option) (bool, error) {
	t.Helper()
	w, err := NewWallet(PackSecret("vk_live_contract", 7, pair.client), "https://vault.test", 0, opts...)
	if err != nil {
		t.Fatal(err)
	}
	m := &wireMock{routes: map[string]cannedResponse{}, handlers: map[string]func([]byte) cannedResponse{}}
	w.http.client.Transport = m
	m.serve(loadFixture(t, "assets.json"))
	m.serve(loadFixture(t, "quote_swap.json"))
	m.serve(loadFixture(t, "movement.json"))
	setup(m)
	verified := serverCosign(t, m, pair, "mv_3", []map[string]string{{token: "5000000"}})
	_, err = w.Swap("USDC@base", "USDT@base", "5", SwapOptions{})
	reached := len(m.sent("POST", "/vault/v1/movements/mv_3/sign/aggregate")) > 0
	if err == nil && !*verified {
		t.Fatal("Swap returned success without a verified signature")
	}
	return reached, err
}

func TestContractOneLabelTwoFingerprintsAcceptsEither(t *testing.T) {
	pair := realPair(t)
	twoContracts := func(m *wireMock) {
		catalogWith(t, m, tokenFingerprint("usdc-base"), tokenFingerprint("usdc-base-bridged"))
	}
	for _, token := range []string{"usdc-base", "usdc-base-bridged"} {
		if reached, err := swapWithToken(t, pair, token, twoContracts); err != nil || !reached {
			t.Fatalf("%s is published under USDC@base, must sign: %v", token, err)
		}
	}
	reached, err := swapWithToken(t, pair, "usdt-base", twoContracts)
	if err == nil || reached || !strings.Contains(err.Error(), "different token") {
		t.Fatalf("a token under neither fingerprint must be refused: %v (aggregate reached: %v)", err, reached)
	}
	// Two entries, neither with a fingerprint: still nothing to check against.
	reached, err = swapWithToken(t, pair, "usdc-base", func(m *wireMock) { catalogWith(t, m, "", "") })
	if err == nil || reached || !strings.Contains(err.Error(), "did not publish an asset fingerprint") {
		t.Fatalf("no fingerprint under the label must be refused: %v", err)
	}
}

func TestContractPinnedFingerprintsOverrideTheServer(t *testing.T) {
	pair := realPair(t)
	pin := PinnedFingerprints(map[string][]string{"USDC@base": {strings.ToUpper(tokenFingerprint("usdc-base"))}})

	// Pinned value matches the disclosed token: signs, whatever /assets says — here a
	// fingerprint that matches nothing, and then no fingerprint at all.
	for name, catalog := range map[string]string{"publishes another": tokenFingerprint("elsewhere"), "publishes none": ""} {
		reached, err := swapWithToken(t, pair, "usdc-base", func(m *wireMock) { catalogWith(t, m, catalog) }, pin)
		if err != nil || !reached {
			t.Fatalf("%s: the pinned token must sign: %v", name, err)
		}
	}

	// The server publishes a different fingerprint than the pin and discloses the token behind
	// it: the published value is ignored, the pin refuses.
	reached, err := swapWithToken(t, pair, "substitute-token",
		func(m *wireMock) { catalogWith(t, m, tokenFingerprint("substitute-token")) }, pin)
	if err == nil || reached || !strings.Contains(err.Error(), "different token") {
		t.Fatalf("a token the pin does not name must be refused: %v (aggregate reached: %v)", err, reached)
	}

	// An unpinned label keeps using what /assets publishes.
	other := PinnedFingerprints(map[string][]string{"USDT@base": {tokenFingerprint("usdt-base")}})
	if reached, err := swapWithToken(t, pair, "usdc-base", func(*wireMock) {}, other); err != nil || !reached {
		t.Fatalf("USDC@base is unpinned, the published fingerprint must apply: %v", err)
	}
}

// A label listed twice resolves to its FIRST entry, as on the server: amount validation and the
// echo check use the first entry's decimals, never the last one's.
func TestContractDuplicateLabelUsesTheFirstEntrysDecimals(t *testing.T) {
	share := realShare(t)
	catalog := []byte(`[` +
		`{"asset":"USDC@base","symbol":"USDC","chain":"base","decimals":6,"fingerprint":"` + tokenFingerprint("usdc-base") + `"},` +
		`{"asset":"USDC@base","symbol":"USDC","chain":"base","decimals":2,"fingerprint":"` + tokenFingerprint("usdc-base-bridged") + `"},` +
		`{"asset":"USDT@base","symbol":"USDT","chain":"base","decimals":6}]`)

	// Amount conversion: six fractional digits are valid under the first entry, not the second.
	w, m := contractWallet(t, "")
	m.route("GET", "/vault/v1/assets", 200, catalog)
	m.serve(loadFixture(t, "quote_withdraw_dry.json"))
	if dec, err := w.decimalsOf("USDC@base"); err != nil || dec != 6 {
		t.Fatalf("decimalsOf = %d, %v; want the first entry's 6", dec, err)
	}
	if _, err := w.QuoteWithdraw("USDC@base", "1.123456", "0xabc0000000000000000000000000000000000000", "exact_out"); err != nil {
		t.Fatalf("1.123456 is valid at 6 decimals: %v", err)
	}

	// Echo check: "10" at 6 decimals is 10000000, what the recorded exact_out quote receives. At the
	// second entry's 2 decimals it would be 1000 and the withdraw would stop before sign/begin.
	w, m = contractWallet(t, share)
	m.route("GET", "/vault/v1/assets", 200, catalog)
	f := loadFixture(t, "quote_withdraw.json")
	m.serve(f)
	_, err := w.Withdraw("USDC@base", "10", "0xabc0000000000000000000000000000000000000", WithdrawOptions{})
	if pe := asPaymosError(t, err); strings.Contains(pe.Message, "not the approved") {
		t.Fatalf("the echo check used the wrong decimals: %v", pe)
	}
	if len(m.sent("POST", "/vault/v1/movements/mv_1/sign/begin")) != 1 {
		t.Fatalf("the echo check must pass on the first entry's decimals and reach sign/begin: %v", m.targets())
	}
}

// A label listed twice with DIFFERENT decimals: the debit is in the first entry's raw units, so
// the second entry's token — the same raw amount worth 10^Δ more — is refused before any share.
// With EQUAL decimals, either token still signs.
func TestContractDuplicateLabelFingerprintsMustShareTheFirstEntrysDecimals(t *testing.T) {
	pair := realPair(t)
	catalog := func(secondDecimals int) func(*wireMock) {
		return func(m *wireMock) {
			body, _ := json.Marshal([]map[string]any{
				{"asset": "USDC@base", "symbol": "USDC", "chain": "base", "decimals": 6, "fingerprint": tokenFingerprint("usdc-base")},
				{"asset": "USDC@base", "symbol": "USDC", "chain": "base", "decimals": secondDecimals, "fingerprint": tokenFingerprint("usdc-base-bridged")},
				{"asset": "USDT@base", "symbol": "USDT", "chain": "base", "decimals": 6, "fingerprint": tokenFingerprint("usdt-base")},
			})
			m.route("GET", "/vault/v1/assets", 200, body)
		}
	}

	// Different decimals (6, then 8): the first entry's token signs, the second's is refused.
	if reached, err := swapWithToken(t, pair, "usdc-base", catalog(8)); err != nil || !reached {
		t.Fatalf("the first entry's token must sign: %v", err)
	}
	reached, err := swapWithToken(t, pair, "usdc-base-bridged", catalog(8))
	if err == nil || reached || !strings.Contains(err.Error(), "different token") {
		t.Fatalf("a token with other decimals must be refused before any share: %v (aggregate reached: %v)", err, reached)
	}

	// Equal decimals: either token signs.
	for _, token := range []string{"usdc-base", "usdc-base-bridged"} {
		if reached, err := swapWithToken(t, pair, token, catalog(6)); err != nil || !reached {
			t.Fatalf("%s shares the first entry's decimals, must sign: %v", token, err)
		}
	}
}
