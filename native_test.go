// Where the co-signing core comes from, and what it must hash to. A local server plays the
// GitHub release; nothing here downloads anything or loads a library.

package paymos

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// coreArchive is a release archive in the shape native-artifacts.sh packs: one file, no directory.
func coreArchive(t *testing.T, name string, library []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(library)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(library); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type fakeRelease struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []string
}

func (f *fakeRelease) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.Path)
	body, ok := f.files[r.URL.Path]
	if !ok {
		w.WriteHeader(404)
		return
	}
	_, _ = w.Write(body)
}

func (f *fakeRelease) asked(suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.requests {
		if strings.HasSuffix(p, suffix) {
			n++
		}
	}
	return n
}

// coreFixture points the resolver at a fresh cache and a local release serving library for this
// platform, with checksum as the release's .sha256 ("" for the archive's true one), and pins
// (nil: the table stays empty).
func coreFixture(t *testing.T, library []byte, checksum string, pins map[string]string) (*fakeRelease, string) {
	t.Helper()
	rid, rerr := coreRID()
	if rerr != nil {
		t.Skip(rerr.Message)
	}
	cache := t.TempDir()
	t.Setenv("PAYMOS_NATIVE_LIB", "")
	t.Setenv("XDG_CACHE_HOME", cache) // os.UserCacheDir on Linux
	t.Setenv("HOME", cache)           // … on macOS
	t.Setenv("LocalAppData", cache)   // … on Windows

	archiveName := "paymos-wallet-native-v" + coreVersion + "-" + rid + ".tar.gz"
	archive := coreArchive(t, coreLibName(rid), library)
	if checksum == "" {
		checksum = sha256Hex(archive)
	}
	release := &fakeRelease{files: map[string][]byte{
		"/v" + coreVersion + "/" + archiveName:             archive,
		"/v" + coreVersion + "/" + archiveName + ".sha256": []byte(checksum + "  " + archiveName + "\n"),
	}}
	srv := httptest.NewServer(release)
	t.Cleanup(srv.Close)

	savedBase, savedPins := coreReleaseBase, pinnedCoreSHA256
	coreReleaseBase = srv.URL
	pinnedCoreSHA256 = map[string]map[string]string{}
	if pins != nil {
		pinnedCoreSHA256[coreVersion] = pins
	}
	t.Cleanup(func() { coreReleaseBase, pinnedCoreSHA256 = savedBase, savedPins })
	return release, rid
}

// Empty until the owner fills it; a pasted entry with a typo fails here, not at a user's first
// payout.
func TestEveryShippedPinNamesAKnownPlatformAndIsASHA256(t *testing.T) {
	platforms := map[string]bool{"linux-x64": true, "linux-arm64": true, "win-x64": true,
		"win-arm64": true, "osx-x64": true, "osx-arm64": true}
	for version, byRID := range pinnedCoreSHA256 {
		for rid, hash := range byRID {
			if _, err := hex.DecodeString(hash); !platforms[rid] || len(hash) != 64 || err != nil {
				t.Errorf("%s/%s: %q is not a sha256 for a known platform", version, rid, hash)
			}
		}
	}
}

// With a compiled-in hash for the platform, that hash is the only one accepted: the release's
// .sha256 is never fetched (here it is wrong, and it does not matter), the extracted library
// must hash to the pin, and the cached file is re-hashed on every later load.
func TestPinnedCoreHashIsTheOnlyOneAccepted(t *testing.T) {
	library := []byte("the trusted co-signing core")
	release, rid := coreFixture(t, library, strings.Repeat("0", 64), nil)
	pinnedCoreSHA256[coreVersion] = map[string]string{rid: strings.ToUpper(sha256Hex(library))}

	path, err := resolveCorePath()
	if err != nil {
		t.Fatalf("a download matching the pin must install: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, library) {
		t.Fatalf("installed %q", got)
	}
	if n := release.asked(".sha256"); n != 0 {
		t.Fatalf("a pinned platform must not consult the release's own checksum (asked %d times)", n)
	}

	// Cached and intact: served from disk, re-hashed, no network.
	before := len(release.requests)
	if again, err := resolveCorePath(); err != nil || again != path || len(release.requests) != before {
		t.Fatalf("the cached core must load without a download: %v, %v", again, err)
	}

	// Cached and swapped: refused, and left where it is for whoever looks into it.
	if err := os.WriteFile(path, []byte("a substituted library"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = resolveCorePath()
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") || !strings.Contains(err.Error(), path) {
		t.Fatalf("a cached core that no longer matches the pin must be refused, got %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("the refused file is evidence, not to be deleted: %v", statErr)
	}
}

// A release whose library does not hash to the pin is refused before anything is written, even
// when its own .sha256 vouches for it.
func TestPinnedCoreRefusesADownloadThatDoesNotMatch(t *testing.T) {
	replaced := []byte("a replaced release")
	_, rid := coreFixture(t, replaced, "", nil) // its own .sha256 is right
	pinnedCoreSHA256[coreVersion] = map[string]string{rid: sha256Hex([]byte("the trusted co-signing core"))}

	path, err := resolveCorePath()
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("a library that misses the pin must be refused, got %q, %v", path, err)
	}
	cacheRoot, _ := coreCacheRoot()
	if entries, _ := os.ReadDir(cacheRoot); len(entries) != 0 {
		t.Fatalf("nothing may be written for a refused download: %v", entries)
	}
}

// With no entry for the platform, behaviour is what it always was: the archive is held to the
// release's .sha256, and a cached file is trusted as written.
func TestUnpinnedCoreKeepsTheReleaseChecksum(t *testing.T) {
	library := []byte("a core this SDK build carries no hash for")
	release, _ := coreFixture(t, library, "", nil)

	path, err := resolveCorePath()
	if err != nil {
		t.Fatalf("a download matching its release checksum must install: %v", err)
	}
	if release.asked(".sha256") != 1 {
		t.Fatalf("an unpinned platform must consult the release checksum: %v", release.requests)
	}
	if err := os.WriteFile(path, []byte("changed on disk"), 0o755); err != nil {
		t.Fatal(err)
	}
	if again, err := resolveCorePath(); err != nil || again != path {
		t.Fatalf("an unpinned cache is trusted as today: %v, %v", again, err)
	}

	// And a checksum that does not match is refused, as it always was.
	coreFixture(t, library, strings.Repeat("0", 64), nil)
	if _, err := resolveCorePath(); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("a release checksum mismatch must be refused, got %v", err)
	}
}

// A release cannot make the SDK buffer an unbounded download or decompress a bomb.
func TestCoreDownloadAndExtractionAreBounded(t *testing.T) {
	library := bytes.Repeat([]byte{0}, 4096)
	_, rid := coreFixture(t, library, "", nil)
	pinnedCoreSHA256[coreVersion] = map[string]string{rid: sha256Hex(library)}

	savedArchive, savedLibrary := maxCoreArchiveBytes, maxCoreLibraryBytes
	t.Cleanup(func() { maxCoreArchiveBytes, maxCoreLibraryBytes = savedArchive, savedLibrary })

	maxCoreLibraryBytes = 1024 // the zeros compress to almost nothing; decompressed they are 4096
	if _, err := resolveCorePath(); err == nil || !strings.Contains(err.Error(), "over 1024 bytes") {
		t.Fatalf("an oversized library must be refused, got %v", err)
	}
	maxCoreLibraryBytes, maxCoreArchiveBytes = savedLibrary, 16
	if _, err := resolveCorePath(); err == nil || !strings.Contains(err.Error(), "over 16 bytes") {
		t.Fatalf("an oversized download must be refused, got %v", err)
	}
}
