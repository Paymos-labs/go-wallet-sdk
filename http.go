package paymos

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Authenticated transport, ported from the Python SDK so every language fails the same way.
//
// Attaches "Authorization: Bearer <api key>" to every request, returns parsed JSON on a 2xx, and
// maps anything else onto a typed error through the server's envelope. The server's contract:
// business errors are {"error": "…"} and the sign flow answers
// {"ok":false,"status":"failed","error":"…"} — both carry the message under "error". Those
// messages arrive already client-safe, so this layer maps them and never rewrites them, and it
// never logs or echoes a request body.
//
// Transport failures are wrapped into a typed error with no status, so a caller on the money
// path never catches a raw net/http error. The timeout is generous because the co-sign is a
// multi-round exchange that outlasts anything a default would allow.

// The sign/aggregate round can trigger a relay that takes a while.
const defaultTimeout = 60 * time.Second

type httpTransport struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func newHTTP(baseURL, apiKey string, timeout time.Duration) *httpTransport {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &httpTransport{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: timeout},
	}
}

func messageOf(body map[string]any, status int, text string) string {
	if body != nil {
		for _, key := range []string{"error", "detail"} {
			if msg, ok := body[key].(string); ok && msg != "" {
				return msg
			}
		}
	}
	trimmed := strings.TrimSpace(text)
	if trimmed != "" {
		return trimmed
	}
	return "request failed with status " + strconv.Itoa(status)
}

// classify400 maps a 400's message to a kind. First match wins, in this exact order.
func classify400(message string, status int) *Error {
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "cross-asset"):
		return newError(KindCrossAssetWithdraw, status, "%s", message)
	case strings.Contains(m, "slippage"):
		return newError(KindSlippageExceeded, status, "%s", message)
	case strings.Contains(m, "expired"):
		return newError(KindQuoteExpired, status, "%s", message)
	}
	for _, t := range []string{"insufficient", "not enough balance", "exceeds the vault", "available balance"} {
		if strings.Contains(m, t) {
			return newError(KindInsufficientFunds, status, "%s", message)
		}
	}
	// The server's route and liquidity rejections come back sounding transient — "No liquidity
	// available … try again in a moment", "route can't be quoted". That whole family is one kind.
	for _, t := range []string{"route", "can't be quoted", "liquidity", "try again in a moment"} {
		if strings.Contains(m, t) {
			return newError(KindRouteUnavailable, status, "%s", message)
		}
	}
	return newError(KindGeneral, status, "%s", message)
}

func raiseFor(status int, body map[string]any, text string, retryAfterHeader string) *Error {
	message := messageOf(body, status, text)
	switch status {
	case 401:
		return newError(KindAuth, status, "%s", message)
	case 403:
		return newError(KindForbidden, status, "%s", message)
	case 409:
		return newError(KindConflict, status, "%s", message)
	case 429:
		ra, _ := strconv.ParseInt(strings.TrimSpace(retryAfterHeader), 10, 64)
		err := newError(KindRateLimited, status, "%s", message)
		err.RetryAfter = ra
		return err
	case 400:
		return classify400(message, status)
	default:
		// 404 has no kind of its own by design; it and every other non-2xx land on the base kind.
		return newError(KindGeneral, status, "%s", message)
	}
}

func (h *httpTransport) do(req *http.Request) (json.RawMessage, error) {
	req.Header.Set("authorization", "Bearer "+h.apiKey)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, newError(KindGeneral, 0, "transport error: %v", err)
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, newError(KindGeneral, 0, "transport error: %v", err)
	}
	var body map[string]any
	if len(text) > 0 {
		// A non-object or non-JSON body stays nil — messageOf falls back to the raw text.
		_ = json.Unmarshal(text, &body)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if len(text) == 0 {
			return json.RawMessage("null"), nil
		}
		return json.RawMessage(text), nil
	}
	return nil, raiseFor(resp.StatusCode, body, string(text), resp.Header.Get("retry-after"))
}

func (h *httpTransport) get(path string, query url.Values) (json.RawMessage, error) {
	u := h.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, localError("bad request path: %v", err)
	}
	return h.do(req)
}

func (h *httpTransport) post(path string, jsonBody []byte, extraHeaders map[string]string) (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodPost, h.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, localError("bad request path: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return h.do(req)
}
