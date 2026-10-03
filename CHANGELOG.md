# Changelog

## 0.2.0

- Enforce configuration commitment before the seed can be entered or generated.
- Invalidate seed, result and audit record after any configuration change.
- Reject stale individual restrictions when the participant list has changed, even if its length is unchanged.
- Normalize Unicode text to NFC and use locale-independent case folding for participant matching.
- Reject empty or duplicate turn names.
- Reject same-person group constraints instead of silently discarding them.
- Canonicalize and deduplicate equivalent group constraints.
- Use deterministic numeric ordering for constraint groups.
- Add explicit participant-order bit representation to the audit record.
- Use one timestamp source for local and UTC audit times.
- Add safer clipboard fallback and browser capability checks.
- Add restrictive Content Security Policy with no network connections.
- Add timestamped audit filenames containing the configuration hash prefix.
- Generalize the product from an escape-room-specific draw to a reusable two-turn group draw.
- Add independent Python verifier, deterministic test vector and CI tests.
- Add a reproducible single-file build script.

## 0.1.0

Pre-hardening snapshot of the original escape-room drawing application. The exact original file is archived losslessly under `archive/v0.1.0`.
