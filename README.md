# Auditable Group Draw

A small, dependency-free web application for drawing one valid split of a group into two turns while enforcing constraints and leaving enough evidence for anyone to reproduce the result independently.

The application is intentionally boring in the useful sense: it enumerates every valid assignment, then selects one uniformly from that finite set using SHA-256 and rejection sampling. There is no server, database, framework, analytics, remote font, network request, or hidden source of randomness.

## Why this is auditable

The ceremony is deliberately ordered:

1. Enter participants, capacities and constraints.
2. **Validate and commit the configuration.** The app canonicalizes it and displays its SHA-256 hash.
3. Record that hash before the seed is known.
4. Generate or reveal the public seed.
5. Run the draw.
6. Save the JSON audit record.
7. Verify it independently with `verifier.py`.

After the configuration has been committed, any edit to participants, turn names, capacities or constraints invalidates the hash, seed, result and audit record. This prevents an operator from learning the seed first and then quietly changing the configuration until a preferred result appears.

## Randomness model

For a fixed valid configuration, the application enumerates valid masks in ascending integer order. If there are `N` valid assignments, it repeatedly computes

```text
SHA-256(configHash | seed | counter)
```

and interprets the 256-bit digest as an integer. Values in the incomplete tail of the 256-bit range are rejected, so reducing the accepted value modulo `N` is unbiased.

This gives a uniform selection **conditional on the seed being unpredictable when the configuration is committed**. SHA-256 does not turn a guessable phrase into entropy. For a public ceremony, either use the built-in cryptographic seed generator after commitment or construct the seed from contributions that are only revealed after the configuration hash has been recorded.

## Constraints

The current version supports two turns and up to 20 participants. It supports:

- maximum capacity for each turn;
- participants forced into a particular turn;
- groups that must remain together;
- pairs that must be separated.

For the intended small-group use case, exhaustive enumeration is simpler to inspect than introducing a constraint solver.

## Run it

Open `index.html` from a static web server, or publish the repository with GitHub Pages.

For a single-file offline version:

```bash
python3 build_standalone.py
```

This creates `dist/auditable-group-draw.html`, containing the same HTML, CSS and JavaScript in one file.

## Independent verification

The verifier uses only the Python standard library and reimplements canonicalization, constraint checking, enumeration and selection independently of the browser code.

```bash
python3 verifier.py audit.json
```

A valid audit prints `PASS` together with the configuration hash, number of valid assignments, selected index, mask and selection digest. Any modification to the seed, configuration, assignment or intermediate cryptographic values causes verification to fail.

## Test vector

The repository includes `tests/fixtures/test-vector-v0.2.0.json`.

For the default twelve-person example with seed `test-seed`:

```text
configuration hash  e553af800b2740338adb1377659dbecf0e36744c78baa2f024a462a8e68fa347
valid assignments   924
selected index       414, base 0
selected mask        1818
selection digest     a3490803162e29be1b0ecf647a413c3cb4dc03cd95b977c558b8fdbcf480d592
```

Run the complete test suite with:

```bash
python3 -m unittest discover -s tests -v
```

## Security and trust boundaries

This is an auditable drawing tool, not a remote randomness beacon or a formally verified voting system. Participants still trust the browser and the particular source version being executed. Recording the repository revision, configuration hash, seed and audit JSON makes later verification practical; it does not prove that an unrecorded machine was uncompromised.

The page declares a restrictive Content Security Policy and makes no network connections. The standalone build also remains fully local.

## Version history

The exact pre-hardening application is preserved under `archive/v0.1.0` and on the `snapshot-v0.1.0` branch. Its original uncompressed SHA-256 is:

```text
76d2db81761a39d40450c968b754baf9189957d9f39ff4cd8a2006e5b50cd0f0
```

See `CHANGELOG.md` for the changes made after that snapshot.

## License

MIT. See `LICENSE`.
