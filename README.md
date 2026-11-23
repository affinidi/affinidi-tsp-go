# affinidi-tsp-go

A Go implementation of the **Trust Spanning Protocol (TSP) 1.0** — wire
version `YTSP-BAA` — from the Trust over IP Foundation
([tswg-tsp-specification@ccda6b3](https://github.com/trustoverip/tswg-tsp-specification/commit/ccda6b33159d860f05c328eb436dabe83548b705)).
It interoperates with `affinidi-tsp` 0.3+, `@openvtc/vti-tsp-js` 0.4+ and the
ToIP reference `tsp_sdk` 0.16+. Messages from the Rev 3 (`YTSP-AAC`) and Rev 2
drafts are refused; upgrade both ends together.

```
go get github.com/affinidi/affinidi-tsp-go
```

Requires Go 1.27 (`crypto/mldsa`, `crypto/hpke`).

> **Status: pre-release (0.2.0), not independently security-audited.** Checked
> against the specification's Appendix A vectors and, for interoperability, against
> the ToIP reference and other implementations by
> [tsp-conformance](https://github.com/OpenVTC/tsp-conformance).

## What it implements

| Area | Coverage |
|---|---|
| Framing | Binary-domain CESR: short and long count codes (`-X##` / `--X#####`), variable-length data with lead-byte variants (`4B`/`5B`/`6B`, `7AAB`/`8AAB`/`9AAB`), long VIDs, fixed data, indexed Ed25519 (`B#`) and ML-DSA-65 (`1AAQ`) signatures |
| Payloads | `XSCS`, `XCTL`, `XPAD`, `XRFI` (Reply_Path, Referral_Field), `XRFA`, `XRFD`, `XHOP` (nested and routed); Padding_Field; ESSR `VID_sndr`: always the sender's VID in a confidential payload (TSP 1.0 §3.7 step 7; a NULL VID there is refused), and optionally the NULL VID `4BAA` in a signed-only one |
| Digests | Self-addressing TSP digests: SHA2-256 (`I`) and Blake2b-256 (`F`), computed on pack and verified on open |
| Schemes | HPKE-Base (DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305); HPKE-Base with `MLKEM768-X25519` + ML-DSA-65; libsodium sealed box; signed-only |
| Relationships | `Endpoint`: invite / accept / cancel / send / receive, RFI race tie-break by lower digest, application messages refused without a relationship |

All eleven TSP 1.0 Appendix A vectors open, including the referral invite
(`Signature_new` verified); the ten that publish their ephemeral key material
are reproduced **byte for byte** by `Pack` (see `vectors_test.go`).
The post-quantum vector publishes none — the hybrid KEM draws its own
randomness — so it is opened and round-tripped instead.

## API

```go
// Stateless
func Pack(sender *PrivateIdentity, receiver *Identity, payload Payload, opts *PackOptions) (*Packed, error)
func Open(receiver *PrivateIdentity, sender *Identity, msg []byte) (*Message, error)
func Peek(msg []byte) (*Envelope, error)
func VerifyReferral(m *Message, introduced *Identity) error

// Payloads: *SCS, *CTL, *PAD, *RFI, *RFA, *RFD, *HOP

// Stateful
type VidResolver interface { Resolve(ctx context.Context, vid string) (*Identity, error) }
type Store interface { /* Relationship / SetRelationship / DeleteRelationship */ }
func NewEndpoint(resolver VidResolver, opts ...EndpointOption) *Endpoint
func (e *Endpoint) Invite / Accept / Cancel(ctx, from, to string) (*Packed, error)
func (e *Endpoint) Send(ctx, from, to string, data []byte) (*Packed, error)
func (e *Endpoint) Receive(ctx, msg []byte) (*Event, error)
func (e *Endpoint) State(ctx, local, remote string) (Relationship, error)
```

Every error is a `*tsp.Error` with a `Kind` (`malformed`, `version`,
`signature`, `decrypt`, `sender`, `receiver`, `digest`, `relationship`,
`unsupported`, `invalid-input`, `internal`); test with `errors.Is(err,
tsp.ErrSignature)` or `tsp.KindOf(err)`.

Sub-packages: `cesr` (the binary CESR primitives) and `crypto` (HPKE, sealed
box, signatures, digests).

## Design notes

- **HPKE-Base is implemented here** (RFC 9180 key schedule over the standard
  library's HKDF, X25519 and x/crypto's ChaCha20Poly1305) so that `PackOptions.Ephemeral`
  can drive `DeriveKeyPair(ikmE)`, which is how the specification publishes its
  vectors. It is checked against the RFC 9180 vectors shipped with Go and against
  `crypto/hpke` in both directions. The hybrid KEM uses `crypto/hpke` directly.
- **ML-DSA-65** verification uses `crypto/mldsa`. Signing accepts the 32-byte
  seed (`crypto/mldsa`) or the 4032-byte expanded key the specification's vectors
  publish, which the standard library cannot import; that path uses
  [CIRCL](https://github.com/cloudflare/circl).
- **Strict parsing.** Canonical encodings only (shortest count form, zero lead
  bytes and pad bits); every count must match the bytes it frames; one
  signature filling its attachment; no trailing bytes; unknown MAJOR version
  refused, MINOR carried. Size limits: `MaxMessageSize` (64 MiB), `MaxVIDSize`,
  `MaxHops`. `FuzzOpen` and `FuzzPeek` exercise the decoder.
- **SAIDs are verified from the received bytes**, not from re-encoded values, so
  verification is exactly the reverse of derivation.
- `PackOptions.Ephemeral` exists only to reproduce test vectors. Reusing
  ephemeral key material destroys confidentiality.

## Testing

```
go vet ./...
go test ./...
go test -run XXX -fuzz FuzzOpen -fuzztime 60s .
```

## License

Apache-2.0
