package paymos

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The co-signing core — the same C ABI build the Python and .NET sides run — comes from three
// places, in this order:
//
//  1. PAYMOS_NATIVE_LIB — a full path to a local binary. The offline escape hatch, and the
//     operator's own choice: no hash below applies to it.
//  2. The per-user cache, where a previous run already left a verified binary.
//  3. The paymos-wallet-core GitHub release — downloaded, verified, then cached.
//
// How a download and a cached file are verified depends on pinnedCoreSHA256. With an entry for
// this version and platform, that compiled-in hash is the ONLY one accepted: the release's own
// .sha256 is not even fetched, the library extracted from the archive must hash to the pin before
// it is written, and the cached file is re-hashed against it on every load — a mismatch anywhere
// refuses, and nothing crosses the FFI boundary. Without an entry, the archive is checked against
// the .sha256 published beside it in the same release, which catches a corrupted download but not
// a replaced release (whoever can replace one asset can replace both), and a cached file is
// trusted as it was written.
//
// Whatever the source, the loaded binary must self-report the version this SDK is pinned to
// (fail-closed), and only then do its exports serve calls.

// coreVersion is the paymos-wallet-core release this SDK build is pinned to. Bump when the core
// releases; the release matrix already treats a core change as a change to every FFI SDK.
const coreVersion = "0.1.0"

// pinnedCoreSHA256 maps a core version to, per platform ("linux-x64", "linux-arm64", "win-x64",
// "win-arm64", "osx-x64", "osx-arm64"), the lowercase hex SHA-256 of the LIBRARY FILE inside
// paymos-wallet-native-v<version>-<platform>.tar.gz — libwallet_mpc.so, wallet_mpc.dll or
// libwallet_mpc.dylib as extracted, not the archive. It is empty in this build: until it is filled,
// a download is checked only against the release's own .sha256. Fill it from a build you trust;
// the same table, with the same values, lives in the C#, Java, PHP and Ruby SDKs.
var pinnedCoreSHA256 = map[string]map[string]string{
	// "0.1.0": {
	// 	"linux-x64":   "<sha256 of libwallet_mpc.so>",
	// 	"linux-arm64": "<sha256 of libwallet_mpc.so>",
	// 	"win-x64":     "<sha256 of wallet_mpc.dll>",
	// },
}

// pinnedCoreHash is the compiled-in hash for version on rid, lowercased, when there is one.
func pinnedCoreHash(version, rid string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(pinnedCoreSHA256[version][rid]))
	return h, h != ""
}

// coreReleaseBase is a variable only so the tests can serve a release from a local server.
var coreReleaseBase = "https://github.com/paymos-labs/paymos-wallet-core/releases/download"

// The archive holds one library of about a megabyte. These bounds stop a replaced release from
// spending the integrator's memory on a huge download or a decompression bomb.
var (
	maxCoreArchiveBytes int64 = 64 << 20
	maxCoreLibraryBytes int64 = 64 << 20
)

func coreRID() (string, *Error) {
	var osPart string
	switch runtime.GOOS {
	case "windows":
		osPart = "win"
	case "darwin":
		osPart = "osx"
	case "linux":
		osPart = "linux"
	default:
		return "", localError("unsupported OS: %s. Supported: linux/macos/windows on x64 and arm64", runtime.GOOS)
	}
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "arm64"
	default:
		return "", localError("unsupported CPU architecture: %s. Supported: x64, arm64", runtime.GOARCH)
	}
	return osPart + "-" + arch, nil
}

func coreLibName(rid string) string {
	switch {
	case strings.HasPrefix(rid, "win"):
		return "wallet_mpc.dll"
	case strings.HasPrefix(rid, "osx"):
		return "libwallet_mpc.dylib"
	default:
		return "libwallet_mpc.so"
	}
}

func coreCacheRoot() (string, *Error) {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "paymos", "native"), nil
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".cache", "paymos", "native"), nil
	}
	return "", localError("cannot locate a user cache directory")
}

// resolveCorePath returns the path of the binary to load, downloading and verifying it first
// when neither the override nor the cache can serve it.
func resolveCorePath() (string, *Error) {
	rid, err := coreRID()
	if err != nil {
		return "", err
	}
	if override := os.Getenv("PAYMOS_NATIVE_LIB"); override != "" {
		if _, statErr := os.Stat(override); statErr != nil {
			return "", localError("PAYMOS_NATIVE_LIB points at a missing file: %s", override)
		}
		return override, nil
	}

	cacheRoot, err := coreCacheRoot()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(cacheRoot, "v"+coreVersion, rid)
	cached := filepath.Join(cacheDir, coreLibName(rid))
	pinned, isPinned := pinnedCoreHash(coreVersion, rid)

	if _, statErr := os.Stat(cached); statErr != nil {
		archiveName := "paymos-wallet-native-v" + coreVersion + "-" + rid + ".tar.gz"
		archive, err := downloadBytes(coreReleaseBase+"/v"+coreVersion+"/"+archiveName, maxCoreArchiveBytes)
		if err != nil {
			return "", err
		}
		if !isPinned {
			// No compiled-in hash: the release's own checksum, which proves the download intact
			// and nothing more.
			checksum, err := downloadBytes(coreReleaseBase+"/v"+coreVersion+"/"+archiveName+".sha256", 4096)
			if err != nil {
				return "", err
			}
			if err := verifySHA256(archive, string(checksum), archiveName); err != nil {
				return "", err
			}
		}
		library, err := readSingleFileTarGz(archive, maxCoreLibraryBytes)
		if err != nil {
			return "", err
		}
		if isPinned {
			if err := checkPinnedSHA256(library, pinned, archiveName); err != nil {
				return "", err // refused before a byte of it is written
			}
		}
		if err := installCore(library, cached); err != nil {
			return "", err
		}
	}

	// A pinned core is re-hashed on every load, cached or just installed: the cache is only a
	// file on disk, and the pin is the only thing that says what may run.
	if isPinned {
		library, err := os.ReadFile(cached)
		if err != nil {
			return "", localError("cannot read the cached co-signing core %s: %v", cached, err)
		}
		if err := checkPinnedSHA256(library, pinned, cached); err != nil {
			return "", localError("%s. Nothing was loaded; delete %s to fetch the core again — the download is held to the same hash",
				err.Message, cached)
		}
	}
	return cached, nil
}

// checkPinnedSHA256 refuses payload unless it hashes to want, the compiled-in pin.
func checkPinnedSHA256(payload []byte, want, what string) *Error {
	sum := sha256.Sum256(payload)
	if got := hex.EncodeToString(sum[:]); got != want {
		return localError("SHA-256 mismatch for %s: this SDK pins %s, got %s", what, want, got)
	}
	return nil
}

func downloadBytes(url string, limit int64) ([]byte, *Error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, localError(
			"failed to download the co-signing core: %v. Set PAYMOS_NATIVE_LIB to a local libwallet_mpc build to run offline", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, localError(
			"failed to download the co-signing core: %s answered %d. Set PAYMOS_NATIVE_LIB to a local libwallet_mpc build to run offline",
			url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, localError("failed to download the co-signing core: %v", err)
	}
	if int64(len(body)) > limit {
		return nil, localError("failed to download the co-signing core: %s is over %d bytes — refusing it", url, limit)
	}
	return body, nil
}

func verifySHA256(payload []byte, checksumText, archiveName string) *Error {
	// Format produced by `sha256sum`: "<hex>  <name>".
	fields := strings.Fields(checksumText)
	if len(fields) == 0 {
		return localError("empty checksum file for the co-signing core download")
	}
	expected := strings.ToLower(fields[0])
	sum := sha256.Sum256(payload)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return localError(
			"SHA-256 mismatch for %s: expected %s, got %s. The download was refused and nothing was loaded",
			archiveName, expected, actual)
	}
	return nil
}

// readSingleFileTarGz returns the first regular file of one of our own single-file archives,
// refusing one larger than limit once decompressed.
func readSingleFileTarGz(archive []byte, limit int64) ([]byte, *Error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, localError("the downloaded core archive is not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, localError("the downloaded core archive is unreadable: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		library, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return nil, localError("the downloaded core archive is unreadable: %v", err)
		}
		if int64(len(library)) > limit {
			return nil, localError("the downloaded core archive holds a file over %d bytes — refusing to install it", limit)
		}
		return library, nil
	}
	return nil, localError("the downloaded core archive carried no file — refusing to install it")
}

// installCore writes the library to destination through a temporary file, so a reader never
// meets half of it.
func installCore(library []byte, destination string) *Error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return localError("cannot create the core cache directory: %v", err)
	}
	tmp := destination + ".tmp"
	if err := os.WriteFile(tmp, library, 0o755); err != nil {
		os.Remove(tmp)
		return localError("cannot write the co-signing core: %v", err)
	}
	os.Remove(destination)
	if err := os.Rename(tmp, destination); err != nil {
		return localError("cannot install the co-signing core: %v", err)
	}
	return nil
}

// loadCore opens the library, verifies its self-reported version against the pinned one, and
// only then publishes its exports for mpcCall. The C plumbing lives in mpc.go (cgo preambles
// are file-scoped); this file resolves WHERE the binary comes from, never HOW it is called.
func loadCore(path string) *Error {
	callSym, freeSym, err := openCoreLibrary(path)
	if err != nil {
		return err
	}

	// The version check goes through the handle's OWN exports, before those exports serve anyone.
	raw, verr := rawCoreCall(callSym, freeSym, []byte(`{"op":"version"}`))
	if verr != nil {
		return verr
	}
	resp, decErr := decodeObject(raw)
	version, _ := resp["version"].(string)
	if decErr != nil || version == "" {
		return localError("the loaded co-signing core does not report a version — too old for this SDK")
	}
	if version != coreVersion {
		return localError(
			"co-signing core version mismatch: %s reports v%s, this SDK is pinned to v%s. "+
				"Set PAYMOS_NATIVE_LIB to a matching build or clear the paymos native cache",
			path, version, coreVersion)
	}

	coreCall = callSym
	coreFree = freeSym
	return nil
}
