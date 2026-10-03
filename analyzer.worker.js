/* One-use isolated worker: only safe, aggregate results leave this context.
 * All dependencies are first-party served; no CDN, analytics or telemetry.
 */
'use strict';
importScripts('./vendor/zxcvbn.js', './analysis-core.js');
let used = false;
self.onmessage = async event => {
  if (used) return;
  used = true;
  let bytes, secret = '', digestBytes, hash = '', suffix = '', prefix = '';
  let timer, responseText = '';
  try {
    const input = event.data;
    if (!input || !(input.bytes instanceof ArrayBuffer) || input.bytes.byteLength > 512 || typeof input.breach !== 'boolean') throw new Error('INVALID_INPUT');
    bytes = new Uint8Array(input.bytes);
    secret = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    SentinelCore.validate(secret);
    const report = SentinelCore.analyze(secret, self.zxcvbn);
    secret = '';
    const useBreach = input.breach;
    if (useBreach) {
      if (!self.crypto?.subtle) throw new Error('CRYPTO_UNAVAILABLE');
      // SHA-1 is ONLY an HIBP lookup identifier, never password storage.
      const digestPromise = self.crypto.subtle.digest('SHA-1', bytes);
      // WebCrypto snapshots the supplied bytes synchronously. Wipe our buffer
      // immediately rather than retaining the secret while hashing resolves.
      bytes.fill(0); bytes = null;
      digestBytes = new Uint8Array(await digestPromise);
      hash = Array.from(digestBytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      prefix = hash.slice(0, 5); suffix = hash.slice(5);
    }
    // Clear mutable data before results or the optional network operation.
    if (bytes) { bytes.fill(0); bytes = null; }
    if (digestBytes) { digestBytes.fill(0); digestBytes = null; }
    secret = ''; hash = '';
    self.postMessage({ type: 'local', report });
    if (!useBreach) { self.postMessage({ type: 'done' }); self.close(); return; }
    self.postMessage({ type: 'breach-loading' });
    try {
      const abort = new AbortController();
      timer = setTimeout(() => abort.abort(), 8000);
      // Only a 20-bit SHA-1 prefix is transmitted over HTTPS. No cookies,
      // referrer, plaintext, suffix, full hash, retry, incremental queries,
      // background request, caching, or credentials are sent.
      const response = await fetch('https://api.pwnedpasswords.com/range/' + prefix, {
        method: 'GET', headers: { 'Add-Padding': 'true' },
        cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
        redirect: 'error', mode: 'cors', signal: abort.signal
      });
      prefix = '';
      if (!response.ok) throw new Error('BREACH_UNAVAILABLE');
      const size = Number(response.headers.get('Content-Length') || 0);
      if (size > 2_000_000) throw new Error('INVALID_RANGE');
      // Bound streamed responses as well as declared Content-Length.
      const reader = response.body?.getReader();
      if (!reader) throw new Error('BREACH_UNAVAILABLE');
      const decoder = new TextDecoder('utf-8', { fatal: true });
      let received = 0;
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        received += chunk.value.byteLength;
        if (received > 2_000_000) { await reader.cancel(); throw new Error('INVALID_RANGE'); }
        responseText += decoder.decode(chunk.value, { stream: true });
      }
      responseText += decoder.decode();
      const count = SentinelCore.parseRange(responseText, suffix);
      responseText = ''; suffix = '';
      self.postMessage({ type: 'breach', count });
    } catch {
      // A lookup error must never look like a clean breach result.
      self.postMessage({ type: 'breach-error' });
    } finally {
      clearTimeout(timer); responseText = ''; suffix = ''; prefix = '';
    }
    self.postMessage({ type: 'done' });
  } catch (error) {
    const allowed = ['EMPTY_INPUT','TOO_LONG','CONTROL_CHARACTER','INVALID_UNICODE','ENGINE_UNAVAILABLE','CRYPTO_UNAVAILABLE'];
    self.postMessage({ type: 'error', code: allowed.includes(error.message) ? error.message : 'ANALYSIS_ERROR' });
  } finally {
    if (bytes) bytes.fill(0);
    if (digestBytes) digestBytes.fill(0);
    secret = ''; hash = ''; suffix = ''; prefix = ''; responseText = '';
    self.close();
  }
};
