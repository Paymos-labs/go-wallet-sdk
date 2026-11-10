package paymos

import (
	"strings"
)

// Human decimal ↔ raw integer, ported from the Python SDK.
//
// Raw amounts are strings rather than numbers on purpose. A token with 18 decimals overflows the
// exact range of an IEEE 754 double at nine significant digits of whole units, so a float would
// round silently — the one failure nobody notices until it is somebody's balance. These functions
// are string-only: no numeric conversion ever happens, so no amount is too long to parse exactly.

func isDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func stripLeadingZeros(s string) string {
	stripped := strings.TrimLeft(s, "0")
	if stripped == "" {
		return "0"
	}
	return stripped
}

// ParseUnits converts "1.5" with 6 decimals to "1500000". It rejects anything that is not a
// non-negative decimal.
//
// It is for comparing a human figure with a raw amount from a response — never for building the
// amount of QuoteSwap, QuoteWithdraw, Swap or Withdraw, or a MinReceive / MaxDebit option: those
// take the human string itself and the server scales it. Withdraw("USDC@base", "10000", …) — what
// ParseUnits("0.01", 6) returns — pays out 10 000 USDC.
func ParseUnits(human string, decimals int) (string, error) {
	if decimals < 0 {
		return "", localError("decimals must be >= 0")
	}
	s := strings.TrimSpace(human)
	whole, frac, found := strings.Cut(s, ".")
	// The wire format is ^\d+(\.\d+)?$ — a trailing dot is not a decimal.
	if !isDigits(whole) || (found && !isDigits(frac)) {
		return "", localError("not a non-negative decimal: %q", human)
	}
	if len(frac) > decimals {
		return "", localError("more than %d fractional digits: %q", decimals, human)
	}
	return stripLeadingZeros(whole + frac + strings.Repeat("0", decimals-len(frac))), nil
}

// FormatUnits converts "1500000" with 6 decimals back to "1.5" — a raw amount from a response, as
// a human decimal. Trailing zeros in the fraction are dropped.
func FormatUnits(raw string, decimals int) (string, error) {
	sign := ""
	digits := raw
	if strings.HasPrefix(digits, "-") {
		sign = "-"
		digits = digits[1:]
	}
	if !isDigits(digits) {
		return "", localError("not a raw integer amount: %q", raw)
	}
	digits = stripLeadingZeros(digits)
	if digits == "0" {
		sign = "" // the sign of nothing is nothing
	}
	if decimals == 0 {
		return sign + digits, nil
	}
	if len(digits) <= decimals {
		digits = strings.Repeat("0", decimals+1-len(digits)) + digits
	}
	whole := digits[:len(digits)-decimals]
	frac := strings.TrimRight(digits[len(digits)-decimals:], "0")
	if frac == "" {
		return sign + whole, nil
	}
	return sign + whole + "." + frac, nil
}
