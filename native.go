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
//  1. PAYMOS_NATIVE_LIB — a full path to a local binary. The offline escape hatch.
//  2. The per-user cache, where a previous run already left a verified binary.
//  3. The paymos-wallet-core GitHub release — downloaded, SHA-256-checked against the release's
//     checksum file, then cached. A checksum mismatch deletes the download and refuses: a
//     substituted binary never crosses the FFI boundary.
//
// Whatever the source, the loaded binary must self-report the version this SDK is pinned to
// (fail-closed), and only then do its exports serve calls.

// coreVersion is the paymos-wallet-core release this SDK build is pinned to. Bump when the core
// releases; the release matrix already treats a core change as a change to every FFI SDK.
const coreVersion = "0.1.0"

const coreReleaseBase = "https://github.com/paymos-labs/paymos-wallet-core/releases/download"

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
	if _, statErr := os.Stat(cached); statErr == nil {
		return cached, nil
	}

	archiveName := "paymos-wallet-native-v" + coreVersion + "-" + rid + ".tar.gz"
	archive, err := downloadBytes(coreReleaseBase + "/v" + coreVersion + "/" + archiveName)
	if err != nil {
		return "", err
	}
	checksum, err := downloadBytes(coreReleaseBase + "/v" + coreVersion + "/" + archiveName + ".sha256")
	if err != nil {
		return "", err
	}
	if err := verifySHA256(archive, string(checksum), archiveName); err != nil {
		return "", err
	}
	if err := extractSingleFileTarGz(archive, cached); err != nil {
		return "", err
	}
	return cached, nil
}

func downloadBytes(url string) ([]byte, *Error) {
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, localError("failed to download the co-signing core: %v", err)
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

// extractSingleFileTarGz unpacks our own single-file archives.
func extractSingleFileTarGz(archive []byte, destination string) *Error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return localError("the downloaded core archive is not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return localError("the downloaded core archive is unreadable: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return localError("cannot create the core cache directory: %v", err)
		}
		tmp := destination + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return localError("cannot write the co-signing core: %v", err)
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			os.Remove(tmp)
			return localError("cannot write the co-signing core: %v", err)
		}
		f.Close()
		os.Remove(destination)
		if err := os.Rename(tmp, destination); err != nil {
			return localError("cannot install the co-signing core: %v", err)
		}
		return nil
	}
	return localError("the downloaded core archive carried no file — refusing to install it")
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
