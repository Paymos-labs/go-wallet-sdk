package paymos

/*
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
static void* libOpen(const char* p) { return (void*)LoadLibraryA(p); }
static void* libSym(void* h, const char* n) { return (void*)GetProcAddress((HMODULE)h, n); }
#else
#include <dlfcn.h>
static void* libOpen(const char* p) { return dlopen(p, RTLD_NOW); }
static void* libSym(void* h, const char* n) { return dlsym(h, n); }
#endif

typedef unsigned char* (*mpcCallFn)(const unsigned char*, size_t, size_t*);
typedef void (*mpcFreeFn)(unsigned char*, size_t);

// cgo cannot call a function pointer from Go; these trampolines take the pointer as an argument.
static unsigned char* doMpcCall(void* fn, const unsigned char* req, size_t len, size_t* outLen) {
	return ((mpcCallFn)fn)(req, len, outLen);
}
static void doMpcFree(void* fn, unsigned char* p, size_t len) {
	((mpcFreeFn)fn)(p, len);
}
*/
import "C"

import (
	"encoding/json"
	"sync"
	"unsafe"
)

// The SDK's half of the 2-of-2 co-sign, over the same Rust core the Python SDK embeds and the
// .NET server calls. Nobody reimplements FROST: this is a JSON op in, a JSON op out, and the
// bytes signed here are the bytes those two would sign.
//
// Only two operations run client-side in production: commit (round one, per movement source) and
// sign (round two, one share per signing package). build_signing_package and aggregate are
// server-side operations and are deliberately not exported.
//
// Every blob — key package, commitments, nonces, signing package, signature share — is opaque
// JSON. It is passed through verbatim, never inspected and never rebuilt. The key package never
// reaches the wire: it only ever feeds the local core.

var (
	coreOnce    sync.Once
	coreCall    unsafe.Pointer
	coreFree    unsafe.Pointer
	coreLoadErr *Error
)

// openCoreLibrary dlopens the core at path and returns its two exports. The loader verifies the
// version through these pointers before they are published to mpcCall.
func openCoreLibrary(path string) (callFn, freeFn unsafe.Pointer, err *Error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	handle := C.libOpen(cPath)
	if handle == nil {
		return nil, nil, localError("failed to load the co-signing core from %s", path)
	}
	cCallName := C.CString("mpc_call")
	callSym := C.libSym(handle, cCallName)
	C.free(unsafe.Pointer(cCallName))
	cFreeName := C.CString("mpc_free")
	freeSym := C.libSym(handle, cFreeName)
	C.free(unsafe.Pointer(cFreeName))
	if callSym == nil || freeSym == nil {
		return nil, nil, localError("the file at %s is not a co-signing core build", path)
	}
	return callSym, freeSym, nil
}

// rawCoreCall invokes the core through an explicit function pointer — the version check uses
// this before the package-level exports are wired.
func rawCoreCall(callFn, freeFn unsafe.Pointer, requestJSON []byte) ([]byte, *Error) {
	cReq := C.CBytes(requestJSON)
	defer C.free(cReq)
	var outLen C.size_t
	outPtr := C.doMpcCall(callFn, (*C.uchar)(cReq), C.size_t(len(requestJSON)), &outLen)
	if outPtr == nil {
		return nil, localError("the loaded co-signing core does not answer — too old for this SDK")
	}
	defer C.doMpcFree(freeFn, outPtr, outLen)
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}

// decodeObject parses a JSON object body.
func decodeObject(raw []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mpcCall runs one JSON op against the core and returns its response body.
func mpcCall(requestJSON []byte) ([]byte, error) {
	coreOnce.Do(func() {
		path, err := resolveCorePath()
		if err != nil {
			coreLoadErr = err
			return
		}
		if err := loadCore(path); err != nil {
			coreLoadErr = err
		}
	})
	if coreLoadErr != nil {
		return nil, coreLoadErr
	}

	cReq := C.CBytes(requestJSON)
	defer C.free(cReq)
	var outLen C.size_t
	outPtr := C.doMpcCall(coreCall, (*C.uchar)(cReq), C.size_t(len(requestJSON)), &outLen)
	if outPtr == nil {
		return nil, localError("mpc call returned nothing")
	}
	defer C.doMpcFree(coreFree, outPtr, outLen)
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen)), nil
}

// mpcOp runs one op and unwraps the {ok, ...} envelope.
func mpcOp(requestJSON []byte) (map[string]any, error) {
	raw, err := mpcCall(requestJSON)
	if err != nil {
		return nil, err
	}
	r, err := decodeObject(raw)
	if err != nil {
		return nil, localError("mpc call returned non-JSON: %v", err)
	}
	if ok, _ := r["ok"].(bool); !ok {
		if msg, _ := r["error"].(string); msg != "" {
			return nil, localError("%s", msg)
		}
		return nil, localError("mpc call failed")
	}
	return r, nil
}

// frostCommit is round one for one signing session. The commitments go to sign/begin; the
// nonces stay private.
func frostCommit(keyPackage []byte) (commitments, nonces []byte, err error) {
	r, err := mpcOp([]byte(`{"op":"commit","key_package":` + string(keyPackage) + `}`))
	if err != nil {
		return nil, nil, err
	}
	commitments, err = json.Marshal(r["commitments"])
	if err != nil {
		return nil, nil, localError("mpc commit returned no commitments")
	}
	nonces, err = json.Marshal(r["nonces"])
	if err != nil {
		return nil, nil, localError("mpc commit returned no nonces")
	}
	return commitments, nonces, nil
}

// frostSign is round two: this side's signature share, which the server aggregates with its own.
func frostSign(signingPackage, nonces, keyPackage []byte) ([]byte, error) {
	r, err := mpcOp([]byte(
		`{"op":"sign","signing_package":` + string(signingPackage) +
			`,"nonces":` + string(nonces) +
			`,"key_package":` + string(keyPackage) + `}`))
	if err != nil {
		return nil, err
	}
	share, err := json.Marshal(r["signature_share"])
	if err != nil {
		return nil, localError("mpc sign returned no signature share")
	}
	return share, nil
}
