package paymos

import "fmt"

// Kind classifies an Error. The set is fixed by the SDK spec — deliberately no KindNotFound,
// since a 404 surfaces as KindGeneral. Branch on the kind instead of string-matching a message:
//
//	var pe *paymos.Error
//	if errors.As(err, &pe) && pe.Kind == paymos.KindRateLimited { … }
type Kind int

const (
	// KindGeneral is the base case: local refusals, 404s, 5xx, transport wraps.
	KindGeneral Kind = iota
	// KindAuth — 401: the API key is missing, malformed, or not recognised.
	KindAuth
	// KindForbidden — 403: the key is valid but lacks the scope this call requires.
	KindForbidden
	// KindInsufficientFunds — 400: the vault's available balance cannot cover the amount plus fees.
	KindInsufficientFunds
	// KindQuoteExpired — 400: the referenced quote has expired; fetch a fresh one and retry.
	KindQuoteExpired
	// KindSlippageExceeded — 400: the delivered amount fell outside the accepted slippage bound.
	KindSlippageExceeded
	// KindCrossAssetWithdraw — 400: a withdraw changed the asset; that is a swap, rejected here.
	KindCrossAssetWithdraw
	// KindRouteUnavailable — 400: no route could be quoted for this pair right now; retry shortly.
	KindRouteUnavailable
	// KindRateLimited — 429: too many requests. RetryAfter carries the Retry-After seconds when sent.
	KindRateLimited
	// KindConflict — 409: idempotency-key conflict: reused with a different request, or a quote still forming.
	KindConflict
)

// Error is the SDK's single error type. Message is the server's already client-safe reason;
// Status is the HTTP code that produced it, or 0 when the error did not come from a response;
// RetryAfter is the Retry-After seconds for KindRateLimited, or 0 when the server sent none.
type Error struct {
	Kind       Kind
	Message    string
	Status     int
	RetryAfter int64
}

func (e *Error) Error() string { return e.Message }

func newError(kind Kind, status int, format string, args ...any) *Error {
	return &Error{Kind: kind, Status: status, Message: fmt.Sprintf(format, args...)}
}

func localError(format string, args ...any) *Error {
	return &Error{Kind: KindGeneral, Message: fmt.Sprintf(format, args...)}
}
