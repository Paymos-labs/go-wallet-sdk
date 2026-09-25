// Package paymos is the Go port of the Paymos wallet SDK — same entry point, same method set,
// same ten error kinds, same refusals as the Python, TypeScript, Rust and .NET SDKs.
//
// Everything that moves money goes through a 2-of-2 co-sign in which this process holds one half
// of the key and never sends it anywhere. The server cannot sign alone and neither can this —
// which is only worth anything if this side refuses to sign things it has not checked, so it
// does: the quote must echo what was approved, MaxDebit caps a server-computed debit, and each
// disclosed message is checked before signing — signer, token, amount against the approved debit.
// The recipient is not checked: the route's deposit address is chosen by the server.
//
// The signing core is the same C ABI build the other SDKs load — downloaded once per platform
// from the paymos-wallet-core releases, SHA-256-verified, cached per user. Nobody reimplements
// FROST.
package paymos
