// Proves the Go SDK drives the same co-signing core the Python SDK and the server drive: a full
// 2-of-2 round — two parties, distributed key generation, commit, sign, aggregate — and the
// resulting ed25519 signature verifies. If this passes, the halves agree on what a signature is.
//
// The server-side operations are driven directly here rather than through the SDK, because the
// SDK deliberately cannot perform them: it holds one half and no more.
//
// The core binary comes from PAYMOS_NATIVE_LIB (set by the release preflight) or, in a source
// checkout, from the core's own release build under ../../mpc/wallet-mpc/target.

package paymos

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	ensureNativeLib()
	os.Exit(m.Run())
}

func ensureNativeLib() {
	if os.Getenv("PAYMOS_NATIVE_LIB") != "" {
		return
	}
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for {
		candidate := filepath.Join(dir, "mpc", "wallet-mpc")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			lib := "libwallet_mpc.so"
			if runtime.GOOS == "windows" {
				lib = "wallet_mpc.dll"
			} else if runtime.GOOS == "darwin" {
				lib = "libwallet_mpc.dylib"
			}
			path := filepath.Join(candidate, "target", "release", lib)
			if _, err := os.Stat(path); err == nil {
				os.Setenv("PAYMOS_NATIVE_LIB", path)
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

func callOp(t *testing.T, req string) map[string]any {
	t.Helper()
	r, err := mpcOp([]byte(req))
	if err != nil {
		t.Fatalf("op failed: %v", err)
	}
	return r
}

func rawOf(t *testing.T, m map[string]any, key string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(m[key])
	if err != nil {
		t.Fatalf("no %q in %v", key, m)
	}
	return raw
}

func packageFor(t *testing.T, packages any, id int) json.RawMessage {
	t.Helper()
	for _, pair := range packages.([]any) {
		p := pair.([]any)
		if int(p[0].(float64)) == id {
			raw, _ := json.Marshal(p[1])
			return raw
		}
	}
	t.Fatalf("no round2 package for %d", id)
	return nil
}

func TestCoSignsAReal2of2SignatureWithTheServerHalf(t *testing.T) {
	a1 := callOp(t, `{"op":"dkg_part1","id":1,"max":2,"min":2}`)
	b1 := callOp(t, `{"op":"dkg_part1","id":2,"max":2,"min":2}`)
	a2 := callOp(t, `{"op":"dkg_part2","secret":`+string(rawOf(t, a1, "secret"))+
		`,"round1_packages":[[2,`+string(rawOf(t, b1, "package"))+`]]}`)
	b2 := callOp(t, `{"op":"dkg_part2","secret":`+string(rawOf(t, b1, "secret"))+
		`,"round1_packages":[[1,`+string(rawOf(t, a1, "package"))+`]]}`)
	a3 := callOp(t, `{"op":"dkg_part3","secret":`+string(rawOf(t, a2, "secret"))+
		`,"round1_packages":[[2,`+string(rawOf(t, b1, "package"))+`]],"round2_packages":[[2,`+
		string(packageFor(t, b2["packages"], 1))+`]]}`)
	b3 := callOp(t, `{"op":"dkg_part3","secret":`+string(rawOf(t, b2, "secret"))+
		`,"round1_packages":[[1,`+string(rawOf(t, a1, "package"))+`]],"round2_packages":[[1,`+
		string(packageFor(t, a2["packages"], 2))+`]]}`)
	if a3["group_pubkey_hex"] != b3["group_pubkey_hex"] {
		t.Fatal("both halves must derive one group key")
	}

	kpA := rawOf(t, a3, "key_package")
	kpB := rawOf(t, b3, "key_package")

	// The client half goes through the SDK; the server half is driven directly, because the SDK
	// has no way to perform it and that is the point.
	clientCommitments, clientNonces, err := frostCommit(kpA)
	if err != nil {
		t.Fatal(err)
	}
	server := callOp(t, `{"op":"commit","key_package":`+string(kpB)+`}`)

	pkg := callOp(t, `{"op":"build_signing_package","commitments":[[1,`+string(clientCommitments)+
		`],[2,`+string(rawOf(t, server, "commitments"))+`]],"message_hex":"deadbeef"}`)

	clientShare, err := frostSign(rawOf(t, pkg, "signing_package"), clientNonces, kpA)
	if err != nil {
		t.Fatal(err)
	}
	serverShare := callOp(t, `{"op":"sign","signing_package":`+string(rawOf(t, pkg, "signing_package"))+
		`,"nonces":`+string(rawOf(t, server, "nonces"))+`,"key_package":`+string(kpB)+`}`)

	agg := callOp(t, `{"op":"aggregate","signing_package":`+string(rawOf(t, pkg, "signing_package"))+
		`,"signature_shares":[[1,`+string(clientShare)+`],[2,`+string(rawOf(t, serverShare, "signature_share"))+`]],"public_key_package":`+
		string(rawOf(t, a3, "public_key_package"))+`}`)
	if agg["verified"] != true {
		t.Fatalf("aggregate verifies: %v", agg)
	}
}

func TestReportsAFailedOpInsteadOfReturningNonsense(t *testing.T) {
	if _, err := frostSign([]byte(`{}`), []byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("signing with garbage must fail")
	}
}

func TestReportsThePinnedCoreVersion(t *testing.T) {
	r := callOp(t, `{"op":"version"}`)
	if r["version"] != coreVersion {
		t.Fatalf("core reports %v, this SDK is pinned to %s", r["version"], coreVersion)
	}
}
