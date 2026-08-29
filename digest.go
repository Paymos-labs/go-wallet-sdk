package paymos

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// The exact 32 bytes the vault's signature is computed over — a byte-for-byte port of the Python
// SDK's digest, which is itself pinned to the server by a cross-language golden vector.
//
// The SDK uses this to VERIFY, before a single FROST commitment leaves the process, that the
// server disclosed the true message it is asking the vault to sign. Never blind-sign.
//
// digest = sha256 of:
//
//	u32   tag                 fixed domain separation; must byte-match the server
//	string message            u32-LE length prefix + utf-8
//	bytes32 nonce             raw, exactly 32
//	string recipient          u32-LE length prefix + utf-8
//	option<string> callback   0x00 = none, else 0x01 + string
//
// Message and recipient are hashed as their EXACT utf-8 bytes. Re-formatting the payload changes
// the digest, which is precisely what the binding check is there to catch.

// msgTag is part of the wire contract. Change it and the client and server stop agreeing forever.
const msgTag uint32 = 2147484061

func lenPrefixedUtf8(s string) []byte {
	out := make([]byte, 4+len(s))
	binary.LittleEndian.PutUint32(out, uint32(len(s)))
	copy(out[4:], s)
	return out
}

// PayloadDigest returns the 32-byte sha256 digest the vault's ed25519 signature is over.
// nonce must be exactly 32 bytes.
func PayloadDigest(message string, nonce []byte, recipient string, callbackURL string) ([32]byte, error) {
	var zero [32]byte
	if len(nonce) != 32 {
		return zero, localError("nonce must be 32 bytes, got %d", len(nonce))
	}
	w := make([]byte, 0, 4+len(message)+32+len(recipient)+len(callbackURL)+8)
	var tag [4]byte
	binary.LittleEndian.PutUint32(tag[:], msgTag)
	w = append(w, tag[:]...)
	w = append(w, lenPrefixedUtf8(message)...)
	w = append(w, nonce...)
	w = append(w, lenPrefixedUtf8(recipient)...)
	if callbackURL == "" {
		w = append(w, 0x00)
	} else {
		w = append(w, 0x01)
		w = append(w, lenPrefixedUtf8(callbackURL)...)
	}
	return sha256.Sum256(w), nil
}

// PayloadDigestHex is PayloadDigest as lowercase hex — the form the FROST signing package
// carries, so the two compare.
func PayloadDigestHex(message string, nonce []byte, recipient string, callbackURL string) (string, error) {
	digest, err := PayloadDigest(message, nonce, recipient, callbackURL)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}
