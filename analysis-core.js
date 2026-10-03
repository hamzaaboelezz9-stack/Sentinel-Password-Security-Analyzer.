/* Sentinel analysis core. No logging, DOM, persistence, or network operations.
 * Empirical Shannon entropy describes symbol diversity; it is NOT a measure
 * of password-generation uncertainty. Strength uses zxcvbn's guessing model.
 */
(function (root) {
  'use strict';
  const MAX_CODE_POINTS = 128;
  const COMMON = new Set([
    'password','password1','password123','123456','12345678','123456789',
    '1234567890','qwerty','qwerty123','abc123','letmein','welcome','welcome1',
    'admin','admin123','iloveyou','monkey','dragon','football','sunshine',
    '000000','111111','123123','princess','login','passw0rd','p@ssw0rd',
    'p@ssword','password!','password123!','password1!','changeme','secret'
  ]);
  const PATTERNS = ['keyboard','dictionary','repeat','leet','sequence','date'];
  const ROWS = ['1234567890','qwertyuiop','asdfghjkl','zxcvbnm'];
  const LEET = { '@':'a', '4':'a', '8':'b', '3':'e', '1':'i', '!':'i', '0':'o', '$':'s', '5':'s', '7':'t' };

  function validate(secret) {
    if (typeof secret !== 'string' || secret.length === 0) throw new Error('EMPTY_INPUT');
    // Preserve spaces, Unicode and punctuation exactly. Never trim or normalize
    // passwords: that would analyze a different credential.
    if (secret.length > MAX_CODE_POINTS * 2 || Array.from(secret).length > MAX_CODE_POINTS) throw new Error('TOO_LONG');
    if (/[\u0000-\u001f\u007f]/u.test(secret)) throw new Error('CONTROL_CHARACTER');
    // Reject malformed UTF-16; TextEncoder otherwise silently replaces it.
    for (let i = 0; i < secret.length; i++) {
      const c = secret.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const next = secret.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('INVALID_UNICODE');
      } else if (c >= 0xdc00 && c <= 0xdfff) throw new Error('INVALID_UNICODE');
    }
  }

  function shannon(secret) {
    const frequencies = new Map();
    let length = 0;
    for (const symbol of secret) { frequencies.set(symbol, (frequencies.get(symbol) || 0) + 1); length++; }
    let perSymbol = 0;
    for (const count of frequencies.values()) {
      const p = count / length;
      perSymbol -= p * Math.log2(p);
    }
    const out = { length, distinct: frequencies.size, perSymbol, total: length * perSymbol };
    frequencies.clear();
    return out;
  }

  function keyboardWalk(secret) {
    const lower = secret.toLowerCase();
    for (const row of ROWS) {
      const reverse = Array.from(row).reverse().join('');
      for (let i = 0; i <= row.length - 4; i++) {
        if (lower.includes(row.slice(i, i + 4)) || lower.includes(reverse.slice(i, i + 4))) return true;
      }
    }
    return false;
  }

  function analyze(secret, estimate) {
    validate(secret);
    if (typeof estimate !== 'function') throw new Error('ENGINE_UNAVAILABLE');
    let model;
    let lower = '', deLeet = '';
    try {
      const entropy = shannon(secret);
      lower = secret.toLowerCase();
      deLeet = lower.replace(/[@4831!0$57]/g, symbol => LEET[symbol]);
      const blocklisted = COMMON.has(lower) || COMMON.has(deLeet);
      model = estimate(secret);
      if (!Number.isFinite(model.guesses_log10) || model.guesses_log10 < 0) throw new Error('ENGINE_ERROR');
      const findings = Object.fromEntries(PATTERNS.map(key => [key, false]));
      // Only reduce to booleans. Never return model.password, match.token,
      // matched_word, user-derived feedback, or any other secret fragment.
      for (const part of model.sequence || []) {
        if (part.pattern === 'spatial') findings.keyboard = true;
        if (part.pattern === 'dictionary') findings.dictionary = true;
        if (part.pattern === 'repeat') findings.repeat = true;
        if (part.pattern === 'sequence') findings.sequence = true;
        if (part.pattern === 'date' || part.pattern === 'regex') findings.date = true;
        if (part.l33t) findings.leet = true;
      }
      findings.keyboard ||= keyboardWalk(secret);
      findings.repeat ||= /(.)\1{2,}/u.test(secret);
      // A replacement is only a finding if it helps produce a known word.
      findings.leet ||= lower !== deLeet && COMMON.has(deLeet);
      findings.dictionary ||= blocklisted;
      const ascii = /^[\x20-\x7e]+$/.test(secret);
      let alphabet = 0;
      if (/[a-z]/.test(secret)) alphabet += 26;
      if (/[A-Z]/.test(secret)) alphabet += 26;
      if (/[0-9]/.test(secret)) alphabet += 10;
      if (/[\x20-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]/.test(secret)) alphabet += 33;
      const logGuesses = model.guesses_log10;
      // Score thresholds follow zxcvbn. A local blocklist match always fails.
      const bucket = blocklisted ? 0 : logGuesses < 3 ? 0 : logGuesses < 6 ? 1 : logGuesses < 8 ? 2 : logGuesses < 10 ? 3 : 4;
      const suggestions = [];
      if (blocklisted) suggestions.push('Replace this password completely. It matches the local common-password blocklist.');
      if (entropy.length < 15) suggestions.push('Use at least 15 characters; longer unique passwords are harder to guess.');
      if (findings.dictionary || findings.leet) suggestions.push('Avoid familiar words with predictable numbers or symbol substitutions. Use several independently random words instead.');
      if (findings.keyboard || findings.sequence || findings.repeat) suggestions.push('Remove keyboard walks, sequences, and repeated chunks; they are guessed early.');
      if (findings.date) suggestions.push('Avoid years, dates, and other personally meaningful numbers.');
      if (!suggestions.length) suggestions.push('This model found no major weakness. Keep this password unique to one account.');
      suggestions.push('Use a password manager for a unique random password, and enable a passkey or multi-factor authentication.');
      return {
        entropy, logGuesses, guessworkBits: logGuesses / Math.log10(2), score: bucket * 25,
        bucket, blocklisted, findings, suggestions, unicode: !ascii,
        // Uniform exhaustive search: expected position is half the search space.
        // This is explicitly a conditional theoretical model, not entropy.
        bruteLogGuesses: ascii ? entropy.length * Math.log10(alphabet) - Math.log10(2) : null,
        alphabet: ascii ? alphabet : null
      };
    } finally {
      lower = ''; deLeet = ''; secret = '';
      // JS strings are immutable. Clear references and destroy the one-shot
      // worker in the caller; guaranteed physical RAM erasure is impossible.
      if (model) { model.password = ''; model.sequence = []; model.feedback = {}; }
      model = null;
    }
  }

  // Strictly parse padded HIBP range data; ignore zero-count padding entries.
  function parseRange(body, suffix) {
    if (typeof body !== 'string' || body.length > 2_000_000 || !/^[A-F0-9]{35}$/.test(suffix)) throw new Error('INVALID_RANGE');
    let count = 0, validLines = 0;
    for (const line of body.split(/\r?\n/)) {
      if (!line) continue;
      const match = /^([A-F0-9]{35}):([0-9]{1,15})$/.exec(line);
      if (!match) throw new Error('INVALID_RANGE');
      const value = Number(match[2]);
      if (!Number.isSafeInteger(value)) throw new Error('INVALID_RANGE');
      validLines++;
      if (match[1] === suffix && value > 0) count = Math.max(count, value);
    }
    if (!validLines) throw new Error('INVALID_RANGE');
    return count;
  }

  function formatTime(logSeconds) {
    if (!Number.isFinite(logSeconds)) return 'Unavailable';
    if (logSeconds < 0) return 'Less than 1 second';
    const units = [[31557600, 'year'], [86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
    const logYears = logSeconds - Math.log10(31557600);
    if (logYears >= 6) {
      if (logYears >= 12) return 'More than 1 trillion years';
      if (logYears >= 9) return (10 ** (logYears - 9)).toFixed(1) + ' billion years';
      return (10 ** (logYears - 6)).toFixed(1) + ' million years';
    }
    for (const [seconds, name] of units) {
      if (logSeconds >= Math.log10(seconds)) {
        const amount = Math.max(1, Math.floor(10 ** (logSeconds - Math.log10(seconds))));
        return amount.toLocaleString('en-US') + ' ' + name + (amount === 1 ? '' : 's');
      }
    }
    return 'Less than 1 second';
  }

  const api = Object.freeze({ analyze, validate, shannon, parseRange, formatTime, MAX_CODE_POINTS });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SentinelCore = api;
})(typeof self !== 'undefined' ? self : globalThis);
