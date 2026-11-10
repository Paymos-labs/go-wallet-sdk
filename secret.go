package paymos

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// VaultSecret is the "vs_live_…" vault secret: an API key, the vault id, and — for a full key —
// this side's FROST signing share. Ported from the Python SDK, same envelope, same field names,
// so one secret works with any of the SDKs.
//
// Printed with any fmt verb, or marshalled to JSON, it shows the key's vk_live_ prefix, the vault
// id and whether it has a share — never the key or the share. One limit fmt cannot be argued out
// of: held in an UNEXPORTED field of your own struct, a VaultSecret printed through that struct is
// walked by reflection, which cannot call its methods. Hold it by pointer there, or not at all.
type VaultSecret struct {
	APIKey  string
	VaultID int64
	// Share is this side's FROST key package JSON. Empty on a read-only secret. Never rendered.
	Share string
}

const secretPrefix = "vs_live_"

// HasShare reports whether this secret carries a co-signing share (a full key).
func (s VaultSecret) HasShare() bool { return s.Share != "" }

// Pack builds a vs_live_ secret string from its parts. Tests and the wallet's key-issuance use
// it; integrators normally receive the packed string.
func PackSecret(apiKey string, vaultID int64, share string) string {
	var s any
	if share == "" {
		s = nil
	} else {
		s = share
	}
	payload, _ := json.Marshal(map[string]any{"k": apiKey, "v": vaultID, "s": s})
	return secretPrefix + base64.RawURLEncoding.EncodeToString(payload)
}

// ParseSecret unpacks and validates a vs_live_ secret.
func ParseSecret(secret string) (VaultSecret, error) {
	if !strings.HasPrefix(secret, secretPrefix) {
		return VaultSecret{}, localError("not a vs_live_ vault secret")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(secret, secretPrefix))
	if err != nil {
		return VaultSecret{}, localError("malformed vault secret: %v", err)
	}
	var o struct {
		K string  `json:"k"`
		V int64   `json:"v"`
		S *string `json:"s"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return VaultSecret{}, localError("malformed vault secret: %v", err)
	}
	if !strings.HasPrefix(o.K, "vk_live_") {
		return VaultSecret{}, localError("vault secret carries no valid api key")
	}
	out := VaultSecret{APIKey: o.K, VaultID: o.V}
	if o.S != nil {
		out.Share = *o.S
	}
	return out, nil
}

// String never renders the share, and masks the key: a stray log line must not leak either.
func (s VaultSecret) String() string {
	return fmt.Sprintf("VaultSecret(apiKey=%s, vaultId=%d, hasShare=%v)", maskKey(s.APIKey), s.VaultID, s.HasShare())
}

// GoString is String: %#v must not print the fields either.
func (s VaultSecret) GoString() string { return s.String() }

// Format makes every fmt verb print String — %v, %+v and %#v, but also %d or %x, which without it
// print a struct field by field ("{%!d(string=vk_live_…)…}"), the share included.
func (s VaultSecret) Format(f fmt.State, verb rune) { formatRedacted(f, verb, s.String()) }

// MarshalJSON keeps the secret out of JSON as well: a structured logger (slog's JSONHandler, zap)
// serializes with encoding/json. The vs_live_ string from PackSecret is how a secret is stored.
func (s VaultSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"apiKey": maskKey(s.APIKey), "vaultId": s.VaultID, "hasShare": s.HasShare()})
}

// sealedSecret and sealedString hold a secret where no reflective printer reaches it. fmt walks a
// struct's fields when it cannot call a method — unexported fields, a struct passed by value — and
// with a verb that does not fit a pointer field (%s, %q) it prints what the pointer points at,
// field by field, methods or not. A func value is the one thing it only ever prints as an address.
type (
	sealedSecret func() *VaultSecret
	sealedString func() string
)

func sealSecret(s VaultSecret) sealedSecret { return func() *VaultSecret { return &s } }

func sealString(s string) sealedString { return func() string { return s } }

// maskKey shows only the non-secret vk_live_ prefix.
func maskKey(key string) string {
	if len(key) >= 8 {
		return key[:8] + "…"
	}
	return "…"
}

// formatRedacted writes text for any verb: quoted for %q, as it is for everything else.
func formatRedacted(f fmt.State, verb rune, text string) {
	if verb == 'q' {
		fmt.Fprintf(f, "%q", text)
		return
	}
	io.WriteString(f, text)
}
