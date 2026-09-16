package tsp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"unicode/utf8"

	tspcrypto "github.com/affinidi/affinidi-tsp-go/crypto"
)

// SigKeyType is the signature scheme a VID's signing key belongs to.
type SigKeyType uint8

// Signature key types.
const (
	SigKeyUnknown SigKeyType = iota
	SigKeyEd25519
	SigKeyMLDSA65
)

func (t SigKeyType) String() string {
	switch t {
	case SigKeyEd25519:
		return "Ed25519"
	case SigKeyMLDSA65:
		return "MlDsa65"
	}
	return "unknown"
}

// EncKeyType is the KEM a VID's encryption key belongs to.
type EncKeyType uint8

// Encryption key types.
const (
	EncKeyUnknown EncKeyType = iota
	EncKeyX25519
	EncKeyMLKEM768X25519
)

func (t EncKeyType) String() string {
	switch t {
	case EncKeyX25519:
		return "X25519"
	case EncKeyMLKEM768X25519:
		return "MLKEM768-X25519"
	}
	return "unknown"
}

// MaxVIDSize bounds the length of any VID this package encodes or accepts.
// It is generous enough for long-form did:peer identifiers carrying
// post-quantum keys.
const MaxVIDSize = 64 * 1024

// Identity is the public view of a VID: the identifier and the keys bound to
// it. It is what a VidResolver produces.
type Identity struct {
	// VID is the verifiable identifier, e.g. a DID or URN.
	VID string
	// SigKeyType and SigningKey are the VID's public signature key: 32 bytes
	// for Ed25519, 1952 for ML-DSA-65.
	SigKeyType SigKeyType
	SigningKey []byte
	// EncKeyType and EncryptionKey are the VID's public encryption key: 32
	// bytes for X25519, 1216 for MLKEM768-X25519. May be empty for a VID that
	// only signs.
	EncKeyType    EncKeyType
	EncryptionKey []byte
}

// Validate checks that the identifier is usable and the keys are well formed.
func (id *Identity) Validate() error {
	if id == nil {
		return newErr(KindInvalidInput, "nil identity")
	}
	if err := validateVID(id.VID); err != nil {
		return err
	}
	switch id.SigKeyType {
	case SigKeyEd25519:
		if len(id.SigningKey) != ed25519.PublicKeySize {
			return newErr(KindInvalidInput, "%s: Ed25519 public key must be 32 bytes, got %d", id.VID, len(id.SigningKey))
		}
	case SigKeyMLDSA65:
		if len(id.SigningKey) != tspcrypto.MLDSA65PublicKeySize {
			return newErr(KindInvalidInput, "%s: ML-DSA-65 public key must be 1952 bytes, got %d", id.VID, len(id.SigningKey))
		}
	default:
		return newErr(KindUnsupported, "%s: signature key type %v", id.VID, id.SigKeyType)
	}
	switch id.EncKeyType {
	case EncKeyUnknown:
		if len(id.EncryptionKey) != 0 {
			return newErr(KindInvalidInput, "%s: encryption key without a key type", id.VID)
		}
	case EncKeyX25519:
		if len(id.EncryptionKey) != tspcrypto.X25519KeySize {
			return newErr(KindInvalidInput, "%s: X25519 public key must be 32 bytes, got %d", id.VID, len(id.EncryptionKey))
		}
	case EncKeyMLKEM768X25519:
		if len(id.EncryptionKey) != tspcrypto.HPKEPQPublicKeySize {
			return newErr(KindInvalidInput, "%s: MLKEM768-X25519 public key must be 1216 bytes, got %d", id.VID, len(id.EncryptionKey))
		}
	default:
		return newErr(KindUnsupported, "%s: encryption key type %v", id.VID, id.EncKeyType)
	}
	return nil
}

func validateVID(vid string) error {
	if vid == "" {
		return newErr(KindInvalidInput, "empty VID")
	}
	if len(vid) > MaxVIDSize {
		return newErr(KindInvalidInput, "VID of %d bytes exceeds %d", len(vid), MaxVIDSize)
	}
	if !utf8.ValidString(vid) {
		return newErr(KindInvalidInput, "VID is not valid UTF-8")
	}
	return nil
}

// PrivateIdentity is a VID this endpoint controls: its public Identity plus the
// private keys. Either private key may be absent when the identity is only used
// for the operations that need the other.
type PrivateIdentity struct {
	Identity
	// SigningPrivateKey is the Ed25519 seed (32 bytes, or 64 bytes seed||pk),
	// or the ML-DSA-65 private key as a 32-byte seed or the 4032-byte expanded
	// encoding.
	SigningPrivateKey []byte
	// DecryptionPrivateKey is the raw X25519 private key (32 bytes) or the
	// MLKEM768-X25519 private key seed (32 bytes).
	DecryptionPrivateKey []byte
}

// NewPrivateIdentity builds a PrivateIdentity from private keys, deriving the
// public keys. Either private key may be nil (with its type left unknown).
func NewPrivateIdentity(vid string, sigType SigKeyType, signingPrivateKey []byte, encType EncKeyType, decryptionPrivateKey []byte) (*PrivateIdentity, error) {
	p := &PrivateIdentity{
		Identity:             Identity{VID: vid, SigKeyType: sigType, EncKeyType: encType},
		SigningPrivateKey:    signingPrivateKey,
		DecryptionPrivateKey: decryptionPrivateKey,
	}
	var err error
	if p.SigningKey, err = publicSigningKey(sigType, signingPrivateKey); err != nil {
		return nil, err
	}
	if len(decryptionPrivateKey) > 0 {
		if p.EncryptionKey, err = publicEncryptionKey(encType, decryptionPrivateKey); err != nil {
			return nil, err
		}
	}
	return p, p.Validate()
}

// GenerateIdentity creates a fresh PrivateIdentity for vid with the given key
// types. rng defaults to crypto/rand.
func GenerateIdentity(vid string, sigType SigKeyType, encType EncKeyType, rng io.Reader) (*PrivateIdentity, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var sigSK, encSK []byte
	switch sigType {
	case SigKeyEd25519:
		sigSK = make([]byte, ed25519.SeedSize)
	case SigKeyMLDSA65:
		sigSK = make([]byte, mldsa.PrivateKeySize)
	default:
		return nil, newErr(KindUnsupported, "signature key type %v", sigType)
	}
	switch encType {
	case EncKeyX25519, EncKeyMLKEM768X25519:
		encSK = make([]byte, 32)
	default:
		return nil, newErr(KindUnsupported, "encryption key type %v", encType)
	}
	if _, err := io.ReadFull(rng, sigSK); err != nil {
		return nil, wrapErr(KindInternal, err, "reading randomness")
	}
	if _, err := io.ReadFull(rng, encSK); err != nil {
		return nil, wrapErr(KindInternal, err, "reading randomness")
	}
	return NewPrivateIdentity(vid, sigType, sigSK, encType, encSK)
}

// Public returns the public Identity (a copy).
func (p *PrivateIdentity) Public() *Identity {
	id := p.Identity
	id.SigningKey = append([]byte(nil), p.SigningKey...)
	id.EncryptionKey = append([]byte(nil), p.EncryptionKey...)
	return &id
}

// Validate checks the public identity and that each private key present
// corresponds to its public key.
func (p *PrivateIdentity) Validate() error {
	if p == nil {
		return newErr(KindInvalidInput, "nil identity")
	}
	if err := p.Identity.Validate(); err != nil {
		return err
	}
	if len(p.SigningPrivateKey) > 0 {
		pk, err := publicSigningKey(p.SigKeyType, p.SigningPrivateKey)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(pk, p.SigningKey) != 1 {
			return newErr(KindInvalidInput, "%s: signing private key does not match the public key", p.VID)
		}
	}
	if len(p.DecryptionPrivateKey) > 0 {
		pk, err := publicEncryptionKey(p.EncKeyType, p.DecryptionPrivateKey)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(pk, p.EncryptionKey) != 1 {
			return newErr(KindInvalidInput, "%s: decryption private key does not match the public key", p.VID)
		}
	}
	return nil
}

func publicSigningKey(t SigKeyType, sk []byte) ([]byte, error) {
	var (
		pk  []byte
		err error
	)
	switch t {
	case SigKeyEd25519:
		pk, err = tspcrypto.Ed25519PublicKey(sk)
	case SigKeyMLDSA65:
		pk, err = tspcrypto.MLDSA65PublicKey(sk)
	default:
		return nil, newErr(KindUnsupported, "signature key type %v", t)
	}
	if err != nil {
		return nil, wrapErr(KindInvalidInput, err, "signing private key")
	}
	return pk, nil
}

func publicEncryptionKey(t EncKeyType, sk []byte) ([]byte, error) {
	var (
		pk  []byte
		err error
	)
	switch t {
	case EncKeyX25519:
		var k *ecdh.PrivateKey
		if k, err = ecdh.X25519().NewPrivateKey(sk); err == nil {
			pk = k.PublicKey().Bytes()
		}
	case EncKeyMLKEM768X25519:
		pk, err = tspcrypto.HPKEPQPublicKey(sk)
	default:
		return nil, newErr(KindUnsupported, "encryption key type %v", t)
	}
	if err != nil {
		return nil, wrapErr(KindInvalidInput, err, "decryption private key")
	}
	return pk, nil
}
