package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

// SealedBoxOverhead is the size a libsodium sealed box adds to its plaintext:
// the 32-byte ephemeral public key and the 16-byte Poly1305 tag.
const SealedBoxOverhead = 32 + box.Overhead

func sealedBoxNonce(ephemeralPublic, recipientPublic []byte) (*[24]byte, error) {
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(ephemeralPublic)
	h.Write(recipientPublic)
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	return &nonce, nil
}

// SealedBoxSeal is libsodium's crypto_box_seal: X25519 + XSalsa20-Poly1305
// with nonce Blake2b-24(epk || pk). The output is epk || tag || ct.
//
// If skEm is non-nil it is the ephemeral X25519 secret, which makes the output
// deterministic; this exists for reproducing published test vectors and must
// not be used otherwise.
func SealedBoxSeal(pkR, plaintext, skEm []byte, rng io.Reader) ([]byte, error) {
	recipient, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, fmt.Errorf("%w: receiver X25519 key: %v", ErrKey, err)
	}
	if skEm == nil {
		if rng == nil {
			rng = rand.Reader
		}
		skEm = make([]byte, X25519KeySize)
		if _, err := io.ReadFull(rng, skEm); err != nil {
			return nil, fmt.Errorf("tsp/crypto: reading randomness: %w", err)
		}
	}
	eph, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral X25519 key: %v", ErrKey, err)
	}
	// Refuse a small-order recipient key (all-zero shared secret) explicitly;
	// nacl/box does not.
	if _, err := eph.ECDH(recipient); err != nil {
		return nil, fmt.Errorf("%w: X25519: %v", ErrKey, err)
	}
	epk := eph.PublicKey().Bytes()
	nonce, err := sealedBoxNonce(epk, pkR)
	if err != nil {
		return nil, err
	}
	var peer, priv [32]byte
	copy(peer[:], pkR)
	copy(priv[:], skEm)
	out := make([]byte, 0, SealedBoxOverhead+len(plaintext))
	out = append(out, epk...)
	return box.Seal(out, plaintext, nonce, &peer, &priv), nil
}

// SealedBoxOpen is libsodium's crypto_box_seal_open.
func SealedBoxOpen(skR, sealed []byte) ([]byte, error) {
	if len(sealed) < SealedBoxOverhead {
		return nil, fmt.Errorf("%w: sealed box too short", ErrDecrypt)
	}
	priv, err := ecdh.X25519().NewPrivateKey(skR)
	if err != nil {
		return nil, fmt.Errorf("%w: receiver X25519 key: %v", ErrKey, err)
	}
	epk := sealed[:32]
	ephPub, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrDecrypt, err)
	}
	if _, err := priv.ECDH(ephPub); err != nil {
		return nil, fmt.Errorf("%w: X25519: %v", ErrDecrypt, err)
	}
	pkR := priv.PublicKey().Bytes()
	nonce, err := sealedBoxNonce(epk, pkR)
	if err != nil {
		return nil, err
	}
	var peer, sk [32]byte
	copy(peer[:], epk)
	copy(sk[:], skR)
	pt, ok := box.Open(nil, sealed[32:], nonce, &peer, &sk)
	if !ok {
		return nil, ErrDecrypt
	}
	return pt, nil
}
