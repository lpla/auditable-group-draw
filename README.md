# Auditable Group Draw

A small, dependency-free web application for drawing one valid split of a group into two turns while enforcing constraints and leaving enough evidence for anyone to reproduce the result independently.

The application is intentionally boring in the useful sense: it enumerates every valid assignment, then selects one uniformly from that finite set using SHA-256 and rejection sampling. There is no server, database, framework, analytics or remote font. The hosted version loads its own static HTML, CSS and JavaScript from GitHub Pages; participant data, constraints, seeds and results are processed locally in the browser and are not transmitted by the application.

Hosted application: https://lpla.github.io/auditable-group-draw/

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

Audit records identify the application version as `v0.2.0`. For a recorded public ceremony, also record the page version, configuration hash and public seed on camera.

## Randomness and fairness model

For a fixed valid configuration, the application enumerates valid masks in ascending integer order. If there are `N` valid assignments, it repeatedly computes

```text
SHA-256(configHash | seed | counter)
```

and interprets the 256-bit digest as an integer. Values in the incomplete tail of the 256-bit range are rejected, so reducing the accepted value modulo `N` is unbiased.

This gives a uniform selection **over complete valid assignments**, conditional on the seed being unpredictable when the configuration is committed. SHA-256 does not turn a guessable phrase into entropy. For a public ceremony, either use the built-in cryptographic seed generator after commitment or construct the seed from contributions that are only revealed after the configuration hash has been recorded. An externally generated seed can provide more observable evidence to people watching the ceremony than browser entropy alone.

Uniformity over complete valid assignments does **not** imply that every unconstrained participant has exactly a 50/50 marginal probability of each turn once restrictions are present. The restrictions define the sample space; the application samples uniformly from that space.

If the restrictions leave exactly one valid assignment, the interface explicitly warns that the result is determined and the seed cannot change it.

## Constraints

The current version supports two turns and between 2 and 20 participants. It supports:

- maximum capacity for each turn;
- participants forced into a particular turn;
- groups that must remain together;
- pairs that must be separated.

Capacities are upper bounds, not balancing targets. For example, with ten participants and capacities of six and six, valid assignments may have different group sizes unless other restrictions force a particular balance.

Participant names cannot contain `+`, comma, semicolon or `|`, because those characters are reserved as separators in group constraints. Dangerous invisible bidirectional formatting and control characters are also rejected to keep the visible audit record consistent with the hashed data.

For the intended small-group use case, exhaustive enumeration is simpler to inspect than introducing a constraint solver.

## Run it

Open `index.html` from a static web server, use the hosted GitHub Pages deployment, or build the single-file version:

```bash
python3 build_standalone.py
```

This creates `dist/auditable-group-draw.html`, containing the same HTML, CSS and JavaScript in one file. The standalone build uses CSP hashes for its inline CSS and JavaScript; it does not require `unsafe-inline`.

## Independent verification

The verifier uses only the Python standard library and reimplements canonicalization, constraint checking, enumeration and selection independently of the browser code.

```bash
python3 verifier.py audit.json
```

The verifier rejects unsupported schema versions, unexpected fields, malformed canonical data, more than 20 participants, duplicate JSON object keys and audit files larger than 1 MB before attempting exhaustive enumeration. These checks bound the work performed on untrusted audit files.

A valid audit prints `PASS` together with the configuration hash, number of valid assignments, selected index, mask and selection digest. Any modification to the seed, configuration, assignment or intermediate cryptographic values causes verification to fail.

## Test vectors

Two deterministic vectors are included. The unrestricted default example in `tests/fixtures/test-vector-v0.2.0.json`, using seed `test-seed`, produces:

```text
configuration hash  e553af800b2740338adb1377659dbecf0e36744c78baa2f024a462a8e68fa347
valid assignments   924
selected index       414, base 0
selected mask        1818
selection digest     a3490803162e29be1b0ecf647a413c3cb4dc03cd95b977c558b8fdbcf480d592
```

`tests/fixtures/test-vector-restricted-v0.2.0.json` additionally exercises Unicode names, unequal capacities, fixed turns, a together constraint and an apart constraint.

The CI suite checks both vectors against the JavaScript implementation and the independent Python verifier:

```bash
python3 -m unittest discover -s tests -v
node tests/test_core.js
```

It also verifies JavaScript syntax and builds the standalone application twice to ensure byte-for-byte reproducibility.

## Security and trust boundaries

This is an auditable drawing tool, not a remote randomness beacon, a formally verified voting system or a proof that the device running the draw is uncompromised. Participants still trust the browser, operating system and particular source version being executed. Recording the source version, configuration hash, seed and audit JSON makes later verification practical.

The hosted page declares a restrictive Content Security Policy: scripts and styles are loaded only from the same origin, and application code is forbidden from making network connections. The standalone build authorizes its embedded CSS and JavaScript by SHA-256 CSP hashes.

GitHub Pages does not let this repository set arbitrary HTTP response headers such as CSP `frame-ancestors`, so the hosted version does not claim clickjacking protection equivalent to a deployment where those headers can be configured. This is a limited risk here because the application has no account, cookies, backend state or privileged server-side action, but it remains part of the hosting trust boundary.

CI uses read-only repository permissions and pins third-party GitHub Actions to immutable full commit SHAs.

## Version history

The exact pre-hardening application is preserved under `archive/v0.1.0` and on the `snapshot-v0.1.0` branch. Its original uncompressed SHA-256 is:

```text
76d2db81761a39d40450c968b754baf9189957d9f39ff4cd8a2006e5b50cd0f0
```

See `CHANGELOG.md` for the changes made after that snapshot.

## License

MIT. See `LICENSE`.
