# go-wallet-sdk — Go SDK

Send, swap and bridge **USDT, USDC, BTC, ETH** and the rest of the wallet's catalogue from
Go — no browser, no wallet extension, and no seed phrase anywhere in your environment. It is
built for the services that pay people out: marketplaces, exchanges, payroll and treasury jobs.

Your process holds **one half** of the signing key; the Paymos server holds the other.
**Neither side alone can move funds** — every swap and withdrawal is co-signed, and your half
never reaches the server.

- **Non-custodial** — a leaked API key can't sign; your co-signing share stays in your process.
- **Fee-transparent** — every quote is a dry preview with a full `Platform / Network / Route`
  fee breakdown you see *before* signing anything.
- **Human amounts, no floats** — you pass decimal strings like `"100"` / `"0.5"`; responses come
  back as raw integer strings.
- **Zero dependencies** — the standard library only, plus the shared co-signing core loaded at
  runtime.

The SDK talks in plain asset terms (`USDC@base`, `ETH@arb`) and hides the routing and the
2-of-2 signing behind a small, safe surface.

## Install

```bash
go get github.com/paymos-labs/go-wallet-sdk@latest
```

Requires **Go ≥ 1.22** and cgo (the core is a C ABI library loaded at runtime — there is no
link-time dependency).

The native co-signing core is **not** inside the module. On first use the SDK downloads the
platform-matching build of the core version it is pinned to from the `paymos-wallet-core` releases,
verifies it, and caches it per user. When this SDK build carries a compiled-in SHA-256 for your
platform, that hash is the only one accepted — for the download and, re-checked on every load, for
the cached file. When it carries none, the download is checked against the `.sha256` published in
the same release, which catches a corrupted download but not a replaced release.

A prebuilt core exists for **Linux x86-64**, **Linux arm64** and **Windows x64**. The SDK also
recognises macOS on both architectures, but no macOS build is published yet — there is no Mac to
produce one on, and cross-compiling an Apple dylib elsewhere is not the same thing. On any platform
without a prebuilt core, build the crate yourself and set `PAYMOS_NATIVE_LIB` to the resulting
`libwallet_mpc.so` / `.dylib` / `wallet_mpc.dll`. The same variable skips the download when you want
it skipped: an offline host, or a corporate proxy that will not reach GitHub.

## Get access & your API key

The SDK controls a **Paymos vault**, which you own from the **Paymos wallet** — a Telegram-only
Mini App. Open **@Ox0000000000000000000Bot**, tap **Open Wallet**, then **Settings → Vault API**
and mint a key:

| Key | Can do | Carries |
|---|---|---|
| **read** | `Assets`, `Balances`, `QuoteSwap`, `QuoteWithdraw`, `Movement`, `Movements` | API key only |
| **full** | everything a read key does, **plus** `Swap` and `Withdraw` | API key **+** your co-signing share |

The key is a `vs_live_…` string. A full key's co-signing share is decrypted on your device and
**never leaves your process**. Treat a full secret like a private key.

```bash
export PAYMOS_VAULT_SECRET="vs_live_…"
# optional — defaults to https://wallet.paymos.io
# export PAYMOS_BASE_URL="https://wallet.paymos.io"
```

## Quickstart

```go
package main

import (
	"fmt"
	"log"

	paymos "github.com/paymos-labs/go-wallet-sdk"
)

func main() {
	w, err := paymos.FromEnv() // reads PAYMOS_VAULT_SECRET
	if err != nil {
		log.Fatal(err)
	}

	balances, err := w.Balances()
	if err != nil {
		log.Fatal(err)
	}
	for _, b := range balances {
		fmt.Println(b.Asset, b.AmountRaw, b.USD)
	}

	// Preview a withdraw — a dry, money-safe quote. Headline is the fee breakdown.
	q, err := w.QuoteWithdraw("USDC@base", "25", "0xRecipient…", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(q.Fees.Platform, q.Fees.Network, q.Fees.Total)

	// Move money (full key only). Amounts are human decimal strings.
	mv, err := w.Swap("USDC@base", "ETH@arb", "100", paymos.SwapOptions{})
	if err != nil {
		log.Fatal(err)
	}
	settled, err := w.Wait(mv.ID, 0, 0) // poll to a terminal status
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(settled.Status)
}
```

## Core concepts

**Amounts: human in, raw out.** Every amount you pass — the `amount` of `QuoteSwap`,
`QuoteWithdraw`, `Swap` and `Withdraw`, and `MinReceive` / `MaxDebit` — is a human decimal string
(`"100"`, `"0.5"`); the server owns each asset's decimals and scales it to raw. Every amount in a
response is a raw integer string (`"10000"` is 0.01 of a 6-decimal USDC). Never a float, in either
direction. `paymos.FormatUnits` turns a raw response amount into a human one for display;
`paymos.ParseUnits` turns a human figure into raw units to **compare** with a response amount. It is
never for building an argument: `w.Withdraw("USDC@base", raw, …)` with `raw` from
`ParseUnits("0.01", 6)` sends `"10000"` and pays out **10 000 USDC** — and since the SDK and the
server agree on that number, no check anywhere can tell it from an intended one.

**Moving money.** `Swap` and `Withdraw` (full key only) create a real movement and drive the
2-of-2 co-sign. Before any signature the SDK re-checks that the server's quote echoes exactly
the assets and amount you approved — a decimals bug, contract drift, or a quote that differs from
your request fails the call and **signs nothing**.

**Slippage: `0` means the default, not zero.** `SwapOptions{}` and `SwapOptions{SlippageBps: 0}`
both send **50 bps (0.5%)**, and so does a negative value; `QuoteSwap(…, 0)` quotes the same 50.
Go cannot tell an unset field from an explicit `0`, so unlike the other seven SDKs — which send `0`
as `0` — the tightest tolerance this one can request is `SlippageBps: 1`. Set it explicitly whenever
the default is not what you mean.

**Safety caps.** `SwapOptions.MinReceive` floors the quote's minimum receive (`KindSlippageExceeded`
below it, nothing signed); `MaxDebit` ceilings the total vault debit — strongly recommended for
unattended `exact_out` payouts; `IdempotencyKey` makes a retry after an ambiguous failure replay
the same movement instead of paying twice.

**Withdraw modes.** `"exact_out"` (default) — the recipient gets exactly `amount`, the debit is
server-computed. `"total_in"` — `amount` is the total debited; the recipient gets it minus fees.

**Waiting.** `Wait(id, timeout, interval)` polls to a terminal status — `completed | failed |
refunded | expired | cancelled`; zero values mean sensible defaults.

## Errors

Every fallible call returns `*paymos.Error` with `Kind`, `Message`, `Status` (0 for transport
failures) and `RetryAfter` (rate limits). Branch on the kind:

```go
var pe *paymos.Error
switch {
case errors.As(err, &pe) && pe.Kind == paymos.KindSlippageExceeded:
	// quoted minimum receive below your floor — nothing signed
case errors.As(err, &pe) && pe.Kind == paymos.KindInsufficientFunds:
	// not enough balance for amount + fees
case errors.As(err, &pe) && pe.Kind == paymos.KindRateLimited:
	time.Sleep(time.Duration(pe.RetryAfter) * time.Second)
}
```

| Kind | When |
|---|---|
| `KindAuth` | `401` — API key missing, malformed, or unrecognized |
| `KindForbidden` | `403` — the key is valid but lacks the scope this call needs |
| `KindInsufficientFunds` | `400` — the vault balance can't cover the amount (plus fees) |
| `KindQuoteExpired` | `400` — the referenced quote expired; fetch a fresh one |
| `KindSlippageExceeded` | `400` or local — delivered / quoted minimum amount fell below your floor |
| `KindCrossAssetWithdraw` | `400` — a withdraw changed the asset (that's a swap) |
| `KindRouteUnavailable` | `400` — no route could be quoted right now; retry shortly |
| `KindRateLimited` | `429` — carries `RetryAfter` (seconds, or 0) |
| `KindConflict` | `409` — idempotency key reused with a different request |
| `KindGeneral` | base — `404`, any other 4xx/5xx, local refusals, transport errors |

Calling `Swap` / `Withdraw` with a **read-only** key fails *before* any movement is created — a
read key can never sign.

## Security

- A leaked **API key alone cannot move funds** — no share, no signature (and the key can be
  revoked).
- A leaked **share alone cannot move funds** — no server co-sign.
- Both are required, on purpose. The SDK additionally checks every message it co-signs (your
  vault as signer, the asset's token, an amount no larger than the approved debit) and that the
  server's quote echoes what you approved. What it does not check: the **recipient** — the route's
  deposit address is chosen by the server — and, for `exact_out`, the debit itself, which the
  server computes. Set `MaxDebit` on unattended payouts so a wrong debit is refused.

Treat a full `vs_live_…` secret like a private key, and back up the share — losing it means
losing your ability to co-sign.

## License

MIT for this wrapper — see `LICENSE`. The co-signing core it downloads is proprietary; its
binary distribution grants no rights to its source.

---

## FAQ

### How do I send USDT (TRC20) from code?

Install the SDK, point it at your vault, and ask for a withdrawal with the asset written the way the
wallet writes it — `USDT@tron`. The same call sends USDT on BNB Chain (`USDT@bsc`), Ethereum
(`USDT@eth`), Polygon, Solana, Arbitrum, Avalanche or TON: the asset string is the only difference.

```
go get github.com/paymos-labs/go-wallet-sdk@latest
```

### Is this custodial? Who can move the money?

Nobody alone. The vault is **2-of-2**: your process holds one signing share, the server holds the
other, and a transfer needs both. A stolen API key cannot sign, and the server cannot sign without
you. Your share never leaves your process.

### What is the difference between a quote and a transfer?

A quote is a dry run. It prices the route, separates platform, network and route fees, and reserves
nothing — ask for as many as you like. A transfer is the same numbers, signed. Nothing moves until
your half of the signature exists.

### Does it blind-sign whatever the server asks for?

No, and this is the part worth reading twice. The server discloses the exact message it wants
signed; the SDK recomputes the digest itself and refuses unless that message is a single transfer
from your vault, of a positive amount, and the sources together move no more than the approved
debit. Two limits: the recipient is chosen by the server and is not checked, and for `exact_out` the
approved debit is itself server-computed — pass `MaxDebit` for unattended payouts.

Each disclosed transfer must also move the asset you are sending: its token id must hash to the
fingerprint `/assets` publishes for that asset. That fingerprint comes from the same server, so the
check catches a server bug or a compromised signing path, not a fully compromised server. For a
trust anchor independent of the server, pin fingerprints you obtained out of band —
`paymos.NewWallet(secret, "", 0, paymos.PinnedFingerprints(map[string][]string{"USDC@base": {"a42c…"}}))`.
A pinned asset is checked against your values only; `/assets` is ignored for it. A pin that pins
nothing — an empty list, an empty string, anything but 64 hex characters — makes `NewWallet` return
an error rather than quietly falling back to what `/assets` publishes.

### Which networks and assets are supported?

USDT moves on nine chains — Tron, Ethereum, BNB Chain, Polygon, Solana, Arbitrum, Optimism,
Avalanche and TON — and USDC on eight: that same list without Tron and TON, with Base instead. Add
the native coin of each of those chains, and BTC, LTC, DOGE, XRP, BCH, DASH, ZEC and ADA, and the
catalogue is 21 assets across 18 chains. It is also the authority: an asset it does not list cannot
be quoted or sent, in any SDK.

### How are fees reported?

Every quote breaks the cost into platform, network and route, and amounts come back as raw integer
strings rather than floats: money that has been through a float is money with a rounding error in
it. You pass human amounts in (`"100"`, `"0.5"`) and read exact integers back.

### Can I use it for automated payouts?

That is what it is for: headless, no browser, no wallet extension, no seed phrase in the environment.
A worker holding one share can pay out continuously, and losing that machine costs the ability to
sign — not the funds.

### What happens if a transfer is interrupted?

Every money-moving call is sent under an idempotency key, and repeating a call with the **same** key
returns the original operation instead of starting a second one. That holds only if your retry
carries the same key: set `IdempotencyKey` to a durable id (e.g. your payout id) and retry with it,
and a retry after a timeout replays the first payment rather than making another. Leave it empty —
the zero value, which Go cannot tell from an explicit `""` — and the SDK generates a fresh key per
call, so a retry is then a second payment. A key of only whitespace is refused rather than sent.

## The same wallet, in eight languages

Every SDK here speaks to the same vault API and enforces the same rules; pick the one your service is
written in. The signing core is shared, so a fix there reaches all of them.

| Language | Package | Repository |
|---|---|---|
| Python | `pip install paymos-wallet` | [python-wallet-sdk](https://github.com/paymos-labs/python-wallet-sdk) |
| TypeScript / Node.js | `npm install @paymos/wallet` | [typescript-wallet-sdk](https://github.com/paymos-labs/typescript-wallet-sdk) |
| Go *(this one)* | `go get github.com/paymos-labs/go-wallet-sdk` | [go-wallet-sdk](https://github.com/paymos-labs/go-wallet-sdk) |
| Rust | `cargo add paymos-wallet` | [rust-wallet-sdk](https://github.com/paymos-labs/rust-wallet-sdk) |
| C# / .NET | `dotnet add package Paymos.Wallet` | [csharp-wallet-sdk](https://github.com/paymos-labs/csharp-wallet-sdk) |
| Java | `io.paymos:wallet` | [java-wallet-sdk](https://github.com/paymos-labs/java-wallet-sdk) |
| Ruby | `gem install paymos-wallet` | [ruby-wallet-sdk](https://github.com/paymos-labs/ruby-wallet-sdk) |
| PHP | `composer require paymos/wallet` | [php-wallet-sdk](https://github.com/paymos-labs/php-wallet-sdk) |
| Signing core | `paymos-wallet-core` | [paymos-wallet-core](https://github.com/paymos-labs/paymos-wallet-core) |

## Documentation

- [wallet.paymos.io](https://wallet.paymos.io) — the product, the supported networks, and guides for
  the routes people ask about most: USDT BEP20 to TRC20, USDC between chains, and the rest.
- [Networks and assets](https://wallet.paymos.io/networks) — every chain and token the wallet
  carries, with the standard each one is named by.
- [USDT BEP20 → TRC20](https://wallet.paymos.io/guides/usdt-bep20-to-trc20) — a worked route, priced
  live; the other pairs are linked from it.
