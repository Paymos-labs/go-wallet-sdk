// The error mapping, which is the whole reason this layer exists: a caller branches on a kind
// instead of matching a string, and the kinds must land the same way they do in Python.

package paymos

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func walletOver(t *testing.T, status int, body string, headers map[string]string) (*Wallet, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	w, err := NewWallet(PackSecret("vk_live_x", 1, ""), srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return w, srv
}

func kindOf(t *testing.T, err error) Kind {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("not a paymos.Error: %v", err)
	}
	return pe.Kind
}

// The server answers /assets with a bare array — never {"assets": [...]}. This test used to mock
// the wrapper, and the SDK passed it while every real quote failed as "unknown asset".
func TestReturnsParsedJSONOn2xx(t *testing.T) {
	w, _ := walletOver(t, 200, `[{"asset":"USDC@base","symbol":"USDC","chain":"base","decimals":6}]`, nil)
	assets, err := w.Assets()
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Asset != "USDC@base" {
		t.Fatalf("assets = %+v", assets)
	}
}

func TestMapsStatusCodesToKinds(t *testing.T) {
	cases := []struct {
		status int
		kind   Kind
	}{
		{401, KindAuth},
		{403, KindForbidden},
		{409, KindConflict},
		{404, KindGeneral},
		{500, KindGeneral},
	}
	for _, tc := range cases {
		w, _ := walletOver(t, tc.status, `{"error":"boom"}`, nil)
		_, err := w.Assets()
		if kind := kindOf(t, err); kind != tc.kind {
			t.Fatalf("status %d → kind %v, want %v", tc.status, kind, tc.kind)
		}
		var pe *Error
		errors.As(err, &pe)
		if pe.Status != tc.status {
			t.Fatalf("status not carried: %d", pe.Status)
		}
	}
}

func TestClassifies400ByMessageFirstMatchWins(t *testing.T) {
	cases := []struct {
		message string
		kind    Kind
	}{
		{"cross-asset withdraw is not allowed", KindCrossAssetWithdraw},
		{"slippage exceeded", KindSlippageExceeded},
		{"quote expired", KindQuoteExpired},
		{"insufficient balance", KindInsufficientFunds},
		{"available balance is lower", KindInsufficientFunds},
		{"No liquidity available, try again in a moment", KindRouteUnavailable},
		{"route can't be quoted", KindRouteUnavailable},
		{"something else entirely", KindGeneral},
	}
	for _, tc := range cases {
		body, _ := json.Marshal(map[string]string{"error": tc.message})
		w, _ := walletOver(t, 400, string(body), nil)
		_, err := w.Assets()
		if kind := kindOf(t, err); kind != tc.kind {
			t.Fatalf("%q → kind %v, want %v", tc.message, kind, tc.kind)
		}
	}
}

func TestCarriesRetryAfterOn429(t *testing.T) {
	w, _ := walletOver(t, 429, `{"error":"slow down"}`, map[string]string{"retry-after": "12"})
	_, err := w.Assets()
	var pe *Error
	errors.As(err, &pe)
	if pe.Kind != KindRateLimited || pe.RetryAfter != 12 {
		t.Fatalf("got %+v", pe)
	}

	w, _ = walletOver(t, 429, `{"error":"slow down"}`, nil)
	_, err = w.Assets()
	errors.As(err, &pe)
	if pe.Kind != KindRateLimited || pe.RetryAfter != 0 {
		t.Fatalf("got %+v", pe)
	}
}

func TestFallsBackToRawBodyWithoutEnvelope(t *testing.T) {
	w, _ := walletOver(t, 500, "upstream exploded", nil)
	_, err := w.Assets()
	var pe *Error
	errors.As(err, &pe)
	if pe.Message != "upstream exploded" {
		t.Fatalf("message = %q", pe.Message)
	}
}

func TestSendsTheBearerTokenAndIdempotencyKey(t *testing.T) {
	var seenAuth, seenIdem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vault/v1/assets":
			fmt.Fprint(w, `[{"asset":"USDC@base","symbol":"USDC","chain":"base","decimals":6}]`)
		case "/vault/v1/quote/withdraw":
			seenAuth = r.Header.Get("authorization")
			seenIdem = r.Header.Get("idempotency-key")
			// A deliberately wrong asset: the echo check fails AFTER the request was seen.
			fmt.Fprint(w, `{"movement_id":"m1","mode":"exact_out",`+
				`"send":{"amount":"24000000","asset":"OTHER"},`+
				`"debit":{"amount":"25000000","asset":"USDC@base"},`+
				`"receive":{"amount":"25000000","min":"25000000","asset":"USDC@base"},`+
				`"fees":null,"expires_at":"","sources":1}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	w, err := NewWallet(PackSecret("vk_live_secret", 1, `{"k":1}`), srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Withdraw("USDC@base", "25", "0xRecipient", WithdrawOptions{IdempotencyKey: "abc"})
	if err == nil {
		t.Fatal("the mismatched echo must fail")
	}
	if seenAuth != "Bearer vk_live_secret" {
		t.Fatalf("authorization = %q", seenAuth)
	}
	if seenIdem != "abc" {
		t.Fatalf("idempotency-key = %q", seenIdem)
	}
}
