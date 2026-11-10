package paymos

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The blind-sign guard approves bytes that the on-chain verifier will parse again, so it has to
// read them the way that verifier does. encoding/json does not: it matches an object key to a
// struct field case-insensitively, and a later key overwrites an earlier one. A message carrying
// "intents": [a 5000 USDC transfer] and, after it, "Intents": [a 10 USDC transfer] decodes into
// the 10 USDC list, the digest binds the exact text, and the case-sensitive verifier executes the
// 5000. The same trick works on signer_id, intent and tokens.
//
// strictParse reads a document with every key exactly as written and refuses a key that already
// appeared in the same object. strictObject.field adds the other half: a key the guard reads is
// looked up by its exact spelling, and a second key that differs from it only by case is refused
// rather than ignored. No message the server builds carries either, so neither refusal can cost a
// legitimate payment.

// strictObject is a JSON object read by strictParse: keys exactly as written, each one once.
type strictObject map[string]any

// strictMaxDepth bounds how deeply strictParse nests. The reader recurses once per open bracket,
// and json.Decoder.Token — unlike Unmarshal, which stops at 10000 — enforces no depth of its own,
// so a server-written message of a few megabytes of "[" would otherwise grow this goroutine's
// stack until the runtime aborts the process, which no recover() catches. The deepest document
// the guard reads legitimately is a sign/begin answer — envelope, packages, package,
// commitments, commitment, header — six levels; a transfer message is four.
const strictMaxDepth = 64

// strictParse decodes exactly one JSON document. Objects become strictObject, arrays []any,
// numbers json.Number (never a float), and strings, booleans and null their Go values. A key
// repeated within one object — including one spelled with escapes, "intents" — is an error,
// and so is anything after the document or nesting deeper than strictMaxDepth.
func strictParse(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := strictValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON document")
	}
	return v, nil
}

// strictParseObject is strictParse for a document that must be an object.
func strictParseObject(raw []byte) (strictObject, error) {
	v, err := strictParse(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(strictObject)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	return obj, nil
}

// strictValue reads one value; depth is the number of containers already open around it.
func strictValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil // string, json.Number, bool or nil
	}
	if depth >= strictMaxDepth {
		return nil, fmt.Errorf("nested deeper than %d levels", strictMaxDepth)
	}
	switch delim {
	case '{':
		obj := strictObject{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, fmt.Errorf("object key %v is not a string", keyTok)
			}
			if _, seen := obj[key]; seen {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			val, err := strictValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		if _, err := dec.Token(); err != nil { // the closing brace
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			val, err := strictValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil { // the closing bracket
			return nil, err
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected %q", delim)
	}
}

// field returns the value under exactly name, and whether it is present. A different key that
// equals name under Unicode case folding — the equivalence encoding/json matches fields by — is
// refused: a document that spells one field two ways was written to be read two ways.
func (o strictObject) field(name string) (any, bool, error) {
	for key := range o {
		if key != name && strings.EqualFold(key, name) {
			return nil, false, fmt.Errorf("key %q differs from %q only by case", key, name)
		}
	}
	v, ok := o[name]
	return v, ok, nil
}

// stringField is field for a value that must be a JSON string; ok is false when it is absent or
// not a string.
func (o strictObject) stringField(name string) (s string, ok bool, err error) {
	v, present, err := o.field(name)
	if err != nil || !present {
		return "", false, err
	}
	s, ok = v.(string)
	return s, ok, nil
}

// requireStrictKeys refuses a document whose listed keys are ambiguous — repeated, or spelled a
// second way that differs only by case — at the top level. It is the check that lets a
// case-insensitive struct decode of the same bytes be trusted to read the exact-case keys.
func requireStrictKeys(raw []byte, names ...string) error {
	obj, err := strictParseObject(raw)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, _, err := obj.field(name); err != nil {
			return err
		}
	}
	return nil
}
