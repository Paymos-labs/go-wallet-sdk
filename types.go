package paymos

// The read model, ported field-for-field from the Python SDK.
//
// Every amount IN THESE RESPONSE TYPES is a STRING of raw integer units, never a number. A token
// with 18 decimals runs past what an IEEE 754 double holds exactly, so a JSON parser that produced
// numbers here would round somebody's balance without saying so. FormatUnits shows one as a human
// decimal; ParseUnits turns a human figure into raw units to COMPARE with one.
//
// The amounts you PASS to Wallet are the other way round: human decimal strings ("100", "0.5"),
// which the server scales. Never pass the output of ParseUnits there — "10000" meant as 0.01 USDC
// is read as 10 000 USDC.

// Asset is one asset the vault can hold, as the server names it. Fingerprint is the lowercase hex
// SHA-256 of the asset's raw token id, as the server publishes it; the co-sign checks every
// disclosed transfer against it unless PinnedFingerprints pins the label. It is empty from a server
// that predates it — reads still work, a co-sign is refused. One label may appear more than once
// (two contracts of one coin), each with its own fingerprint.
type Asset struct {
	Asset       string `json:"asset"`
	Symbol      string `json:"symbol"`
	Chain       string `json:"chain"`
	Decimals    int    `json:"decimals"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Balance is what the vault holds of one asset. USD is a display estimate and may be empty.
type Balance struct {
	Asset     string `json:"asset"`
	Symbol    string `json:"symbol"`
	Chain     string `json:"chain"`
	Decimals  int    `json:"decimals"`
	AmountRaw string `json:"amount_raw"`
	USD       string `json:"usd"`
}

// RouteFee is the routing layer's own fee. Estimate marks a figure that can still move.
type RouteFee struct {
	Amount   string `json:"amount"`
	Estimate bool   `json:"estimate"`
}

// Fees is every charge on an operation, split so none of them can hide inside another.
type Fees struct {
	Asset    string            `json:"asset"`
	Platform string            `json:"platform"`
	Network  string            `json:"network"`
	Route    *RouteFee         `json:"route"`
	Total    string            `json:"total"`
	USD      map[string]string `json:"usd"`
}

// Amount is a raw integer amount string plus its asset.
type Amount struct {
	Amount string `json:"amount"`
	Asset  string `json:"asset"`
}

// Receive is what the quote says arrives. Min is the minimum the quote states; the SDK compares it
// with SwapOptions.MinReceive before signing, but does not observe what is delivered.
type Receive struct {
	Amount string `json:"amount"`
	Min    string `json:"min"`
	Asset  string `json:"asset"`
}

// Quote is a preview of an operation. MovementID is empty on a dry preview; Sources is the
// number of co-signing sessions a real quote will need.
type Quote struct {
	MovementID string `json:"movement_id"`
	Mode       string `json:"mode"`
	Send       Amount `json:"send"`
	// Debit is the MAXIMUM this quote may take from the vault, reserve against slippage
	// included — a ceiling, not a prediction. The co-sign refuses sources that move more than
	// it, but the server computes it: for exact_out cap it with MaxDebit, especially for
	// unattended payouts. An exact-output route routinely spends less and returns the
	// difference; compare the finished movement's Send to see what it actually cost.
	Debit     Amount  `json:"debit"`
	Receive   Receive `json:"receive"`
	Fees      *Fees   `json:"fees"`
	ExpiresAt string  `json:"expires_at"`
	Sources   *int    `json:"sources"`
}

// Movement is one operation's lifecycle, newest state included.
type Movement struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
	// Send is what the movement actually cost the vault: the approved maximum minus anything
	// the route handed back. This is the figure that matches the on-chain balance — reconcile
	// on it. It is NOT the quote's Debit, which is the ceiling that was approved before the
	// route ran.
	Send                 Amount  `json:"send"`
	Receive              Receive `json:"receive"`
	Fees                 *Fees   `json:"fees"`
	DestChainTxHash      string  `json:"dest_chain_tx_hash"`
	DestChainExplorerURL string  `json:"dest_chain_explorer_url"`
	CreatedAt            string  `json:"created_at"`
	CompletedAt          string  `json:"completed_at"`
}
