package paymos

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// VaultSecret is the "vs_live_…" vault secret: an API key, the vault id, and — for a full key —
// this side's FROST signing share. Ported from the Python SDK, same envelope, same field names,
// so one secret works with any of the SDKs.
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
	mask := "…"
	if len(s.APIKey) >= 8 {
		mask = s.APIKey[:8] + "…"
	}
	return fmt.Sprintf("VaultSecret(apiKey=%s, vaultId=%d, hasShare=%v)", mask, s.VaultID, s.HasShare())
}
