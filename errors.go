package tsp

import (
	"errors"
	"fmt"
)

// ErrorKind classifies why an operation failed. Every error returned by this
// package is an *Error carrying one, so a caller can branch on the kind with
// errors.Is against the sentinel values below, or with KindOf.
type ErrorKind uint8

// Error kinds.
const (
	KindInternal     ErrorKind = iota // anything else
	KindMalformed                     // CESR framing cannot be parsed
	KindVersion                       // unknown or unsupported TSP version
	KindSignature                     // signature verification failed
	KindDecrypt                       // decryption or authentication failed
	KindSender                        // envelope/ESSR sender mismatch, wrong sender key, unknown sender
	KindReceiver                      // message not addressed to the receiver
	KindDigest                        // a SAID does not verify
	KindRelationship                  // relationship state forbids the message
	KindUnsupported                   // scheme, payload type or option not supported
	KindInvalidInput                  // the caller's request is invalid
)

var kindNames = [...]string{
	KindInternal:     "internal",
	KindMalformed:    "malformed",
	KindVersion:      "version",
	KindSignature:    "signature",
	KindDecrypt:      "decrypt",
	KindSender:       "sender",
	KindReceiver:     "receiver",
	KindDigest:       "digest",
	KindRelationship: "relationship",
	KindUnsupported:  "unsupported",
	KindInvalidInput: "invalid-input",
}

// String returns the kind's short name ("malformed", "signature", ...).
func (k ErrorKind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("ErrorKind(%d)", uint8(k))
}

// Sentinel errors, one per kind, for use with errors.Is.
var (
	ErrInternal     = &Error{Kind: KindInternal}
	ErrMalformed    = &Error{Kind: KindMalformed}
	ErrVersion      = &Error{Kind: KindVersion}
	ErrSignature    = &Error{Kind: KindSignature}
	ErrDecrypt      = &Error{Kind: KindDecrypt}
	ErrSender       = &Error{Kind: KindSender}
	ErrReceiver     = &Error{Kind: KindReceiver}
	ErrDigest       = &Error{Kind: KindDigest}
	ErrRelationship = &Error{Kind: KindRelationship}
	ErrUnsupported  = &Error{Kind: KindUnsupported}
	ErrInvalidInput = &Error{Kind: KindInvalidInput}
)

// Error is the error type returned by this package.
type Error struct {
	Kind ErrorKind
	Msg  string
	Err  error // underlying cause, if any
}

func (e *Error) Error() string {
	s := "tsp: " + e.Kind.String()
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is a sentinel of the same kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Msg == "" && t.Err == nil && t.Kind == e.Kind
}

// KindOf returns the kind of err, or KindInternal if err is not an *Error.
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}

func newErr(kind ErrorKind, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

func wrapErr(kind ErrorKind, err error, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...), Err: err}
}
