package crypto

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/blake2b"
)

// ErrSignature reports a signature that does not verify.
var ErrSignature = errors.New("tsp/crypto: signature verification failed")

// Signature and key sizes.
const (
	Ed25519PublicKeySize = ed25519.PublicKeySize
	Ed25519SeedSize      = ed25519.SeedSize
	Ed25519SignatureSize = ed25519.SignatureSize

	MLDSA65PublicKeySize   = 1952
	MLDSA65SeedSize        = mldsa.PrivateKeySize // 32
	MLDSA65ExpandedKeySize = mldsa65.PrivateKeySize
	MLDSA65SignatureSize   = 3309
)

func ed25519Key(sk []byte) (ed25519.PrivateKey, error) {
	switch len(sk) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(sk), nil
	case ed25519.PrivateKeySize:
		k := ed25519.NewKeyFromSeed(sk[:ed25519.SeedSize])
		if string(k[32:]) != string(sk[32:]) {
			return nil, fmt.Errorf("%w: Ed25519 private key does not match its public half", ErrKey)
		}
		return k, nil
	}
	return nil, fmt.Errorf("%w: Ed25519 private key of %d bytes", ErrKey, len(sk))
}

// Ed25519PublicKey returns the public key for an Ed25519 seed (32 bytes) or
// seed||public (64 bytes).
func Ed25519PublicKey(sk []byte) ([]byte, error) {
	k, err := ed25519Key(sk)
	if err != nil {
		return nil, err
	}
	return []byte(k.Public().(ed25519.PublicKey)), nil
}

// Ed25519Sign signs msg (RFC 8032 pure Ed25519).
func Ed25519Sign(sk, msg []byte) ([]byte, error) {
	k, err := ed25519Key(sk)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(k, msg), nil
}

// Ed25519Verify verifies an Ed25519 signature.
func Ed25519Verify(pk, msg, sig []byte) error {
	if len(pk) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: Ed25519 public key of %d bytes", ErrKey, len(pk))
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pk), msg, sig) {
		return ErrSignature
	}
	return nil
}

// MLDSA65PublicKey derives the public key from an ML-DSA-65 private key given
// either as the 32-byte seed or the 4032-byte expanded encoding (FIPS 204
// skEncode).
func MLDSA65PublicKey(sk []byte) ([]byte, error) {
	switch len(sk) {
	case MLDSA65SeedSize:
		k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), sk)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
		return k.PublicKey().Bytes(), nil
	case MLDSA65ExpandedKeySize:
		var k mldsa65.PrivateKey
		if err := k.UnmarshalBinary(sk); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
		pk, ok := k.Public().(*mldsa65.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: ML-DSA-65 public key", ErrKey)
		}
		return pk.MarshalBinary()
	}
	return nil, fmt.Errorf("%w: ML-DSA-65 private key of %d bytes", ErrKey, len(sk))
}

// MLDSA65Sign signs msg with ML-DSA-65 (FIPS 204 ML-DSA.Sign, empty context,
// hedged). sk is the 32-byte seed or the 4032-byte expanded key. The standard
// library signs from a seed; the expanded form, which is what published TSP
// vectors carry, is signed with CIRCL.
func MLDSA65Sign(sk, msg []byte, rng io.Reader) ([]byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	switch len(sk) {
	case MLDSA65SeedSize:
		k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), sk)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
		return k.Sign(rng, msg, nil)
	case MLDSA65ExpandedKeySize:
		var k mldsa65.PrivateKey
		if err := k.UnmarshalBinary(sk); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
		sig := make([]byte, MLDSA65SignatureSize)
		if err := mldsa65.SignTo(&k, msg, nil, true, sig); err != nil {
			return nil, err
		}
		return sig, nil
	}
	return nil, fmt.Errorf("%w: ML-DSA-65 private key of %d bytes", ErrKey, len(sk))
}

// MLDSA65Verify verifies an ML-DSA-65 signature (empty context).
func MLDSA65Verify(pk, msg, sig []byte) error {
	if len(pk) != MLDSA65PublicKeySize {
		return fmt.Errorf("%w: ML-DSA-65 public key of %d bytes", ErrKey, len(pk))
	}
	k, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pk)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKey, err)
	}
	if len(sig) != MLDSA65SignatureSize {
		return ErrSignature
	}
	if err := mldsa.Verify(k, msg, sig, nil); err != nil {
		return ErrSignature
	}
	return nil
}

// SHA256 returns SHA2-256(data).
func SHA256(data []byte) [32]byte { return sha256.Sum256(data) }

// Blake2b256 returns Blake2b-256(data).
func Blake2b256(data []byte) [32]byte { return blake2b.Sum256(data) }
