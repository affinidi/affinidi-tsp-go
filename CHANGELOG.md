# Changelog

## [0.2.0] — TSP 1.0

**Breaking on the wire and in behaviour.** Moves to the released TSP 1.0
specification
([tswg-tsp-specification@ccda6b3](https://github.com/trustoverip/tswg-tsp-specification/commit/ccda6b33159d860f05c328eb436dabe83548b705),
PR #86), in step with `affinidi-tsp` 0.3.0, `@openvtc/vti-tsp-js` 0.4.0 and the
ToIP reference `tsp_sdk` 0.16.0. A peer still on Rev 3 cannot exchange messages
with this release in either direction; upgrade both ends together.

### Changed

- Packs `YTSP-BAA` (1.0), was `YTSP-AAC` (0.2, Rev 3). `CurrentVersion` is
  `{Major: 1, Minor: 0}`.
- `Peek` and `Open` refuse every MAJOR but 1 with `KindVersion`, naming the
  draft found (Rev 3 `AAC`, its pre-merge draft `ABA`, Rev 2 `AAB`).
- `SenderFieldDefault` now writes the sender's VID under every scheme: 1.0
  requires it in every confidential payload (§3.2, §3.7 step 7), where Rev 3
  allowed the NULL VID under HPKE-Base. `SenderFieldNull` is accepted only for
  a signed-only payload.
- `Open` refuses a confidential payload (HPKE-Base, HPKE-PQ, sealed box) whose
  ESSR sender field is the NULL VID, with `KindSender`.
- Appendix A vectors replaced with 1.0's (`testdata/spec-vectors.json`,
  identical to `affinidi-tsp` and `vti-tsp-js`). The new
  `control-rfi-referral` vector is opened and its `Signature_new` verified.
- golang.org/x/crypto 0.59.0, golang.org/x/sys 0.50.0.

### Added

- Dependabot for Go modules and GitHub Actions.

## [0.1.0]

- TSP Rev 3 (`YTSP-AAC`).
