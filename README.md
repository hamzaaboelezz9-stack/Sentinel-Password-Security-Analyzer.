# Sentinel — Password Security Analyzer

A complete browser app, built with HTML, CSS and vanilla JavaScript. All password analysis runs in a disposable Web Worker. There is no password backend, telemetry, persistence, CDN or incremental breach query.

## Run locally

Use Node.js 20 or newer:

```sh
node serve.cjs
```

Open **http://127.0.0.1:8080**. The pinned zxcvbn 4.4.2 browser bundle is included, so running the app requires no package installation or internet access. Keep the breach switch off to analyze entirely offline. If port 8080 is occupied, set `SENTINEL_PORT` to another port from 1024–65535.

To run the test suite:

```sh
npm ci --ignore-scripts
npm run check
npm test
```

Only development uses npm. Production serves the checked-in files under `dist/`. Deploy with HTTPS, serve the security headers in `dist/_headers`, and do not inject analytics or third-party scripts. The local server binds only to `127.0.0.1`; it is intentionally not a public internet server. Header behavior on a hosted platform should be verified when configuring that platform. The HTML also carries a restrictive CSP; `frame-ancestors` requires the HTTP header.

## Files

- `dist/index.html` — accessible, responsive app and explanations.
- `dist/styles.css` — dark security workspace, strength gauge, mobile layout.
- `dist/app.js` — input lifecycle, aggregate report, cancellation and UI.
- `dist/analyzer.worker.js` — isolated analysis, secure breach lookup, cleanup.
- `dist/analysis-core.js` — Shannon calculation, safe model extraction, patterns and range parsing.
- `dist/vendor/zxcvbn.js` — bundled, pinned pattern/dictionary guessing engine.
- `serve.cjs` — local static server, safe routing and defensive headers.
- `tests/` — mathematical, privacy, worker, UI and failure-path tests using public synthetic examples only.

## Entropy and strength

For each distinct Unicode code point, estimate its empirical frequency as `p_i = count_i / n`. The app calculates:

```text
H = -sum(p_i * log2(p_i))       bits per character
empirical total = n * H         displayed Shannon bits
guesswork bits = log2(G)        G = zxcvbn estimated guesses
```

Empirical Shannon entropy describes character-frequency diversity. It cannot establish how randomly a single password was chosen. A keyboard walk may have high empirical entropy and still be guessed immediately. Accordingly, the score does **not** use `n × H` as security strength.

zxcvbn estimates guess rank from common-password and dictionary ranks, names, keyboard adjacency, repeated chunks, sequences, years, dates and leetspeak. The app extracts only booleans and aggregate numbers; it never displays or returns matched words, tokens, the password, or user-derived feedback. It also checks a small embedded common-password blocklist. Scores follow zxcvbn's log10 guess thresholds: below 3 / 6 / 8 / 10, then at least 10, mapped to 0 / 25 / 50 / 75 / 100. Local blocklist matches and confirmed HIBP matches force a score of 0.

Dictionary coverage is mainly English. Detection is heuristic and may miss language-specific or personal patterns. “Not detected” is not proof of absence; a score of 100 is not a security guarantee. Public examples are demonstrations and must never be reused as actual credentials.

## Crack-time assumptions

Calculations use logarithms to avoid overflow:

```text
uniform exhaustive search: T = N^n / (2 * R)
pattern/dictionary attack: T = G / R
log10(T_pattern) = log10(G) - log10(R)
```

The exhaustive model assumes uniform random ASCII selection from observed character classes, a known length, and half the search space on average. This is a conditional theoretical estimate; it does not model human choice. ASCII pools are 26 lowercase, 26 uppercase, 10 digits and 33 other printable symbols, including space. For Unicode input the app does not invent an alphabet or a uniform-search estimate.

The dictionary model uses an approximate guess rank, so no additional half-space factor is applied. Default illustrative rates are 10 billion guesses/s for a fast hash and 10,000 guesses/s for a slower hash. The fast-hash scenario is selectable at 1 / 10 / 100 billion guesses/s. These are assumptions, not current hardware benchmarks or measured Argon2/bcrypt parameters. An actual leak permits an attacker to try a known password immediately, regardless of the modeled time. Very large times are capped in the display.

## HIBP privacy protocol

The breach switch defaults to off. A request occurs only after an explicit opt-in and submission; public demonstrations disable the switch. The worker calculates SHA-1 over the exact UTF-8 input and sends only the first five hexadecimal characters to:

```text
https://api.pwnedpasswords.com/range/{5-character-prefix}
```

It requests `Add-Padding: true`, uses `cache: no-store`, omits cookies/credentials and referrers, rejects redirects, limits response bytes, and times out. The remaining 35 hash characters are compared locally against strictly validated range records. Zero-count padding is discarded. Full hashes and suffixes never reach the UI. Network errors, invalid records and timeouts produce **Unavailable**, never a false “No match.” Lookup failures preserve the local result; reset or leaving the page terminates the worker and cancels its activity.

SHA-1 is the lookup identifier required by this protocol; it is **not** an acceptable password-storage scheme. HIBP can see the requesting IP and 20-bit prefix. K-anonymity reduces exposure, but is not complete anonymity. The embedded blocklist is not a full breach dataset, and a live miss does not prove the password has never been leaked.

## In-memory processing and its limits

The input is cleared at submission, including validation failure. The exact password is preserved: no trimming, case folding or Unicode normalization before hashing. Case/leet transformations are transient local pattern checks only. Empty input, control characters, malformed UTF-16 and more than 128 Unicode code points are rejected without echoing them. Input bounds and a disposable-worker deadline mitigate pathological estimator inputs.

UTF-8 bytes transfer to the worker, detaching the UI buffer. Mutable input and digest buffers are overwritten promptly. Only predefined advice, numeric metrics, booleans and the breach count leave the worker. Its lifetime ends on completion, failure, timeout, reset or leaving the visible page. Reports are cleared on page hiding and are never stored. Input is rendered only by the native password field; results use `textContent`, never interpolated HTML.

**JavaScript cannot guarantee physical zeroization of immutable strings, garbage-collected copies, browser internals or extensions.** References are discarded and worker isolation limits their lifetime, but this is zero application retention, not a claim of guaranteed RAM wiping. A compromised browser/device is outside the threat model. Password managers may ignore the app's autocomplete suppression. Prefer a trusted device and local mode when checking a sensitive password.

The app writes no password or report to cookies, localStorage, sessionStorage, IndexedDB, URLs, files, logs, analytics, service workers or a backend. Static asset hosting and private-site sign-in necessarily use platform infrastructure but do not receive app password input. Optional HIBP is the only app-level external request. No cryptographic keys or API secrets are required.

Optional WebMCP tools accept only included public example names or a clear action; they deliberately accept no user secret because agent parameters may be retained in a transcript. They use the same UI actions and validate their inputs.

## References and license

- [zxcvbn primary documentation](https://github.com/dropbox/zxcvbn)
- [HIBP range API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)
- [HIBP padded responses](https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding)

Application code: MIT, see `LICENSE`. zxcvbn retains its own MIT attribution in `dist/vendor/ZXCVBN-LICENSE.txt`. No independent penetration test or external security certification is implied.
