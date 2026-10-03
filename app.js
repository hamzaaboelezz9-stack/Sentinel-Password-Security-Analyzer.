/* UI handles only transient input and aggregate reports. Never use innerHTML
 * with input, console logs, telemetry, storage APIs, or URL serialization.
 */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const password = $('password');
  const breachToggle = $('breach-toggle');
  const LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
  const COLORS = ['#fda298','#f4b783','#f4ca7b','#b9d889','#c5ef73'];
  const DESCRIPTIONS = [
    'Easy to guess. Replace this password completely.',
    'Predictable enough to be guessed early. Add independent randomness.',
    'Some resistance, but still vulnerable to offline guessing.',
    'Good modeled resistance. More length and randomness can improve it.',
    'High modeled resistance. Keep it unique; estimates are not guarantees.'
  ];
  const ERRORS = {
    EMPTY_INPUT: 'Enter a password to analyze.',
    TOO_LONG: 'Use at most 128 Unicode characters for this bounded analysis.',
    CONTROL_CHARACTER: 'Control characters are not supported. Spaces and other printable characters are preserved.',
    INVALID_UNICODE: 'This input contains an invalid Unicode sequence.',
    ENGINE_UNAVAILABLE: 'The local analysis engine did not load. Refresh the page and try again.',
    CRYPTO_UNAVAILABLE: 'Secure browser cryptography is unavailable. Disable the breach check or use HTTPS / localhost.',
    ANALYSIS_ERROR: 'Analysis could not complete. Your input was cleared. Try again.'
  };
  let worker = null, watchdog = null, report = null, breachCount = null;
  let attempt = 0, busy = false;

  function countCharacters() { let count = 0; for (const ignored of password.value) count++; return count; }
  function clearSecret() {
    password.value = '';
    password.type = 'password';
    $('visibility').setAttribute('aria-pressed', 'false');
    $('visibility').setAttribute('aria-label', 'Show password');
    $('character-count').textContent = '0 / 128';
  }
  function showError(code) {
    $('input-error').textContent = ERRORS[code] || ERRORS.ANALYSIS_ERROR;
    $('input-error').hidden = false;
    password.setAttribute('aria-invalid', 'true');
  }
  function setBusy(value) {
    busy = value;
    $('analyze-button').disabled = value;
    password.disabled = value;
    breachToggle.disabled = value;
    $('weak-sample').disabled = value;
    $('strong-sample').disabled = value;
    $('visibility').disabled = value;
    // Keep Clear enabled so users can immediately cancel any operation.
    $('analyze-button').lastChild.textContent = value ? ' Analyzing…' : 'Analyze password';
    $('analyzer-form').setAttribute('aria-busy', String(value));
  }
  function dispose() {
    if (worker) worker.terminate();
    worker = null;
    clearTimeout(watchdog); watchdog = null;
    setBusy(false);
  }
  function pill(id, text, state) { const element = $(id); element.textContent = text; element.className = 'finding-state ' + state; }
  function setSuggestions(items) {
    const fragment = document.createDocumentFragment();
    items.forEach((text, i) => {
      const li = document.createElement('li'), number = document.createElement('span'), p = document.createElement('p');
      number.textContent = String(i + 1).padStart(2, '0'); p.textContent = text;
      li.append(number, p); fragment.append(li);
    });
    $('suggestions').replaceChildren(fragment);
  }
  function renderStrength() {
    if (!report) return;
    const breached = typeof breachCount === 'number' && breachCount > 0;
    const score = breached ? 0 : report.score, bucket = breached ? 0 : report.bucket;
    $('score-number').textContent = String(score);
    $('strength-label').textContent = breached ? 'Compromised' : LABELS[bucket];
    $('strength-label').style.color = COLORS[bucket];
    $('strength-description').textContent = breached ? 'Found in breach data. Replace it everywhere it was used.' : DESCRIPTIONS[bucket];
    $('dial-progress').setAttribute('stroke-dasharray', score + ' 100');
    $('dial-progress').style.stroke = COLORS[bucket];
    const bars = $('strength-bars');
    bars.setAttribute('aria-valuenow', String(score)); bars.setAttribute('aria-valuetext', breached ? 'Compromised' : LABELS[bucket]);
    [...bars.children].forEach((bar, i) => { bar.style.background = i <= bucket ? COLORS[bucket] : '#343d46'; });
    const suggestions = report.suggestions.slice();
    if (breached) suggestions.unshift('This exact password appears in breach data. Replace it on every account where it was used.');
    if (report.unicode) suggestions.push('Non-English words and Unicode patterns have limited model coverage. Treat this estimate with extra caution.');
    setSuggestions(suggestions);
  }
  function renderTimes() {
    if (!report) return;
    const rate = Number($('gpu-rate').value);
    if (![1e9, 1e10, 1e11].includes(rate)) return;
    $('time-brute').textContent = report.bruteLogGuesses === null ? 'Not modeled for Unicode' : SentinelCore.formatTime(report.bruteLogGuesses - Math.log10(rate));
    $('time-dictionary').textContent = SentinelCore.formatTime(report.logGuesses - Math.log10(rate));
    $('time-slow').textContent = SentinelCore.formatTime(report.logGuesses - 4);
    $('brute-assumption').textContent = report.alphabet ? 'Uniform random · ' + report.alphabet + '-symbol ASCII alphabet' : 'Unicode alphabet is not assumed';
    $('dictionary-assumption').textContent = 'Pattern-aware rank · ' + (rate / 1e9) + ' billion guesses/s';
    if (report.blocklisted || (typeof breachCount === 'number' && breachCount > 0)) {
      $('time-dictionary').textContent = 'Known · try immediately';
      $('time-slow').textContent = 'Known · try immediately';
      $('dictionary-assumption').textContent = 'Known password · rank model superseded';
    }
  }
  function renderLocal(value) {
    report = value;
    $('entropy-total').textContent = value.entropy.total.toFixed(1);
    $('entropy-detail').textContent = value.entropy.perSymbol.toFixed(2) + ' bits/character · empirical distribution';
    $('guesswork').textContent = value.guessworkBits.toFixed(1);
    $('length').textContent = String(value.entropy.length);
    $('length-detail').textContent = value.entropy.distinct + ' distinct characters · spaces preserved';
    const flags = { keyboard:value.findings.keyboard, dictionary:value.findings.dictionary, repeat:value.findings.repeat, leet:value.findings.leet, sequence:value.findings.sequence || value.findings.date };
    for (const [key, found] of Object.entries(flags)) pill('finding-' + key, found ? 'Detected' : 'Not detected', found ? 'detected' : 'clear');
    $('blocklist-status').textContent = value.blocklisted ? 'Matched · replace it' : 'No match';
    $('blocklist-status').style.color = value.blocklisted ? COLORS[0] : COLORS[4];
    $('report-state').textContent = 'Input cleared · local analysis complete';
    renderStrength(); renderTimes();
  }
  function resetReport() {
    report = null; breachCount = null;
    for (const id of ['score-number','entropy-total','guesswork','length']) $(id).textContent = '—';
    $('strength-label').textContent = 'Ready when you are'; $('strength-label').style.color = '';
    $('strength-description').textContent = 'Analyze a password to see its resistance to guessing.';
    $('dial-progress').setAttribute('stroke-dasharray','0 100');
    [...$('strength-bars').children].forEach(bar => { bar.style.background = ''; });
    $('strength-bars').setAttribute('aria-valuenow','0'); $('strength-bars').setAttribute('aria-valuetext','Not analyzed');
    $('report-state').textContent = 'No password analyzed';
    $('entropy-detail').textContent = 'Character distribution, not unpredictability';
    $('length-detail').textContent = 'Unicode code points · spaces preserved';
    for (const key of ['keyboard','dictionary','repeat','leet','sequence']) pill('finding-' + key, 'Not checked', 'neutral');
    pill('breach-status','Not checked','neutral');
    $('breach-description').textContent = 'The local common-password blocklist runs with every analysis. Live breach lookup is optional.';
    $('blocklist-status').textContent = '—'; $('blocklist-status').style.color = '';
    for (const id of ['time-brute','time-dictionary','time-slow']) $(id).textContent = '—';
    $('brute-assumption').textContent = 'Uniform random ASCII · half the search space';
    $('dictionary-assumption').textContent = 'Pattern-aware guesses · fast hash';
    setSuggestions(['Use a long, unique password for every account.','Prefer a password manager or several independently random words.','Enable multi-factor authentication or use a passkey.']);
  }
  function resetAll() {
    attempt++; dispose(); clearSecret(); resetReport();
    $('input-error').hidden = true; password.removeAttribute('aria-invalid');
  }
  function analyze() {
    if (busy) return;
    resetReport();
    $('input-error').hidden = true; password.removeAttribute('aria-invalid');
    let secret = password.value, bytes;
    const checkBreach = breachToggle.checked;
    try { SentinelCore.validate(secret); bytes = new TextEncoder().encode(secret); }
    catch (error) { clearSecret(); secret = ''; showError(error.message); password.focus(); return; }
    // No persistent app state ever receives the password. Detach mutable bytes
    // by transfer; clear the DOM and local string before running the worker.
    clearSecret(); secret = '';
    const id = ++attempt;
    setBusy(true); $('report-state').textContent = 'Analyzing locally…';
    try {
      worker = new Worker('./analyzer.worker.js');
      watchdog = setTimeout(() => {
        if (id !== attempt) return;
        dispose(); showError('ANALYSIS_ERROR'); $('report-state').textContent = 'Analysis timed out · input cleared';
      }, 12000);
      worker.onmessage = event => {
        if (id !== attempt) return;
        const message = event.data;
        switch (message.type) {
          case 'local':
            renderLocal(message.report);
            if (!checkBreach) {
              pill('breach-status','Not requested','neutral');
              $('breach-description').textContent = message.report.blocklisted ? 'This password matches the small local weak-password blocklist. Live breach data was not requested.' : 'No match in the small local blocklist. Live breach data was not requested; breach status is unknown.';
            }
            break;
          case 'breach-loading':
            clearTimeout(watchdog);
            watchdog = setTimeout(() => {
              if (id !== attempt) return;
              dispose(); pill('breach-status','Unavailable','pending');
              $('breach-description').textContent = 'The lookup timed out. Breach status is unknown. Local results remain available.';
            }, 10000);
            pill('breach-status','Checking…','pending');
            $('breach-description').textContent = 'Checking a padded hash range over HTTPS. Your password and full hash remain local.';
            break;
          case 'breach':
            breachCount = message.count;
            pill('breach-status', message.count > 0 ? 'Compromised' : 'No match', message.count > 0 ? 'detected' : 'clear');
            $('breach-description').textContent = message.count > 0 ? 'This exact password appeared ' + message.count.toLocaleString('en-US') + ' times in the HIBP corpus. Replace it everywhere it was used.' : 'No match in the HIBP corpus. This does not prove the password is safe, unique, or never leaked.';
            renderStrength(); renderTimes(); break;
          case 'breach-error':
            pill('breach-status','Unavailable','pending');
            $('breach-description').textContent = 'The service could not be reached or returned invalid data. Breach status is unknown; your local analysis is still available.';
            break;
          case 'error':
            dispose(); showError(message.code); $('report-state').textContent = 'Analysis failed · input cleared'; break;
          case 'done': dispose(); break;
        }
      };
      worker.onerror = event => {
        event.preventDefault();
        if (id !== attempt) return;
        dispose(); showError('ENGINE_UNAVAILABLE'); $('report-state').textContent = 'Analysis failed · input cleared';
      };
      worker.postMessage({ bytes: bytes.buffer, breach: checkBreach }, [bytes.buffer]);
      bytes = null;
    } catch {
      if (bytes?.byteLength) bytes.fill(0);
      bytes = null; dispose(); showError('ANALYSIS_ERROR');
    }
  }

  $('analyzer-form').addEventListener('submit', event => { event.preventDefault(); analyze(); });
  $('clear-button').addEventListener('click', () => { resetAll(); password.focus(); });
  password.addEventListener('input', () => {
    const count = countCharacters(); $('character-count').textContent = count + ' / 128';
    $('input-error').hidden = true; password.removeAttribute('aria-invalid');
    // Prevent a previous result from being mistaken for the new credential.
    if (report) resetReport();
  });
  $('visibility').addEventListener('click', () => {
    const show = password.type === 'password'; password.type = show ? 'text' : 'password';
    $('visibility').setAttribute('aria-pressed', String(show));
    $('visibility').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
  $('gpu-rate').addEventListener('change', renderTimes);
  function sample(kind) {
    if (busy) return;
    resetAll();
    // Public illustrative samples, never offered as generated credentials.
    password.value = kind === 'weak' ? 'P@ssw0rd123!' : 'vG7!cQ2#zM9@bL4$kT8%';
    $('character-count').textContent = countCharacters() + ' / 128';
    // Demo never enables or performs a network request.
    breachToggle.checked = false;
    analyze();
    $('report-state').textContent = 'Analyzing public example…';
  }
  $('weak-sample').addEventListener('click', () => sample('weak'));
  $('strong-sample').addEventListener('click', () => sample('strong'));
  window.addEventListener('pagehide', resetAll);
  document.addEventListener('visibilitychange', () => { if (document.hidden) resetAll(); });

  // WebMCP deliberately accepts NO password argument: an agent tool parameter
  // could enter a transcript. Agents may clear state or evaluate public demos.
  const context = document.modelContext;
  if (context?.registerTool) {
    const lifecycle = new AbortController();
    window.addEventListener('pagehide', () => lifecycle.abort(), { once: true });
    for (const tool of [
      { name:'clear_password_analysis', title:'Clear password analysis', description:'Clear password input and report, and cancel any active evaluation.', inputSchema:{type:'object',properties:{},additionalProperties:false}, execute: input => { if (!input || typeof input !== 'object' || Object.keys(input).length) throw new Error('Invalid input'); resetAll(); return { cleared:true }; } },
      { name:'analyze_public_password_example', title:'Analyze a public example', description:'Analyze an included weak or strong public example locally. Never accepts a user password or makes a breach request.', inputSchema:{type:'object',properties:{example:{type:'string',enum:['weak','strong']}},required:['example'],additionalProperties:false}, execute: async input => {
        if (!input || typeof input !== 'object' || !['weak','strong'].includes(input.example) || Object.keys(input).length !== 1 || busy) throw new Error('Invalid input or analysis busy');
        sample(input.example);
        await new Promise((resolve, reject) => { const start = Date.now(); const poll = () => { if (!busy) return report ? resolve() : reject(new Error('Analysis failed')); if (Date.now() - start > 13000) return reject(new Error('Analysis timed out')); setTimeout(poll, 50); }; poll(); });
        return { score:report.score, shannonBits:report.entropy.total, findings:report.findings, breachRequested:false };
      } }
    ]) {
      try { Promise.resolve(context.registerTool({...tool,annotations:{readOnlyHint:false,untrustedContentHint:false}}, {signal:lifecycle.signal})).catch(() => {}); } catch { /* Optional capability must not break the private local UI. */ }
    }
  }
})();
