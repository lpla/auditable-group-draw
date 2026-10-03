# Changelog

## 0.2.0

- Enforce configuration commitment before the seed can be entered or generated.
- Invalidate seed, result and audit record after any configuration change.
- Reject stale individual restrictions when the participant list has changed, even if its length is unchanged.
- Normalize Unicode text to NFC and use deterministic lowercase matching for participant names.
- Reject empty or duplicate turn names, malformed capacities, reserved name separators and dangerous invisible control or bidirectional-formatting characters.
- Validate individual restriction values instead of silently accepting manipulated DOM values.
- Reject same-person group constraints instead of silently discarding them.
- Canonicalize and deduplicate equivalent group constraints using deterministic numeric ordering.
- Avoid misleading duplicate-person errors when a group constraint already contains an unknown name.
- Warn when restrictions leave exactly one valid assignment and the seed therefore cannot alter the result.
- Add explicit participant-order bit representation and source version to audit records.
- Use one timestamp source for local and UTC audit times.
- Add safer clipboard fallback and browser capability checks.
- Add restrictive Content Security Policy with no application network connections.
- Use SHA-256 CSP hashes instead of `unsafe-inline` in the standalone build.
- Add timestamped audit filenames containing the configuration hash prefix.
- Generalize the product from an escape-room-specific draw to a reusable two-turn group draw.
- Add independent Python verifier with strict schemas, bounded input size, duplicate-key detection and a 20-participant work limit.
- Add JavaScript core regression tests and a second deterministic vector covering restrictions and Unicode.
- Add responsive handling for very long names, accessible labels and live status regions, visible version/source information and reduced-motion behavior.
- Clarify the fairness model, privacy model, capacity semantics and hosting trust boundaries in the documentation.
- Pin GitHub Actions dependencies to immutable full commit SHAs and verify standalone reproducibility in CI.

## 0.1.0

Pre-hardening snapshot of the original escape-room drawing application. The exact original file is archived losslessly under `archive/v0.1.0`.
