// Package tsp implements the Trust Spanning Protocol (TSP), Rev 3
// (YTSP-AAC, version 0.2), as specified by the Trust over IP Foundation.
//
// A TSP message is an envelope (version, sender VID, receiver VID), a payload
// that is either encrypted or carried in the clear, and a signature over both,
// all framed in binary-domain CESR. This package encodes and decodes every
// Rev 3 payload type:
//
//   - SCS: upper-layer application data (XSCS)
//   - CTL: generic control data for the layer above TSP (XCTL)
//   - PAD: padding messages (XPAD)
//   - RFI, RFA, RFD: the relationship forming protocol (XRFI / XRFA / XRFD),
//     with self-addressing digests (SAIDs), reply paths and referrals
//   - HOP: nested and routed messages (XHOP)
//
// under four schemes: HPKE-Base (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// ChaCha20Poly1305), HPKE-Base with the MLKEM768-X25519 hybrid KEM and ML-DSA-65
// signatures, the libsodium sealed box, and signed-only.
//
// # Stateless API
//
// Pack builds a message, Open verifies and decrypts one, and Peek reads the
// envelope an intermediary sees:
//
//	packed, err := tsp.Pack(alice, bob.Public(), &tsp.SCS{Data: []byte("hi")}, nil)
//	msg, err := tsp.Open(bob, alice.Public(), packed.Message)
//
// Keys are carried by Identity (public) and PrivateIdentity. Nothing is
// resolved by Pack or Open; the caller supplies both parties.
//
// # Endpoint
//
// Endpoint adds VID resolution (VidResolver), relationship state (Store) and
// the relationship forming state machine: Invite, Accept, Cancel, Send and
// Receive. It performs no I/O, so any transport can be layered on top.
//
// # Parsing
//
// Parsing is strict and bounded: primitives must be canonically encoded, counts
// must agree with the bytes they frame, trailing bytes are rejected, and an
// unknown MAJOR version is refused. Every error is an *Error whose Kind says
// why (see ErrorKind).
package tsp
