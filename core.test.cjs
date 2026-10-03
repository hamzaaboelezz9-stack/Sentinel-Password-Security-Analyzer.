'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const core = require('../dist/analysis-core.js');
const zxcvbn = require('zxcvbn');

test('Shannon calculation follows actual frequencies, including repeated symbols', () => {
  assert.deepEqual(core.shannon('aaaa'), {length:4,distinct:1,perSymbol:0,total:0});
  assert.equal(core.shannon('abab').perSymbol, 1);
  assert.equal(core.shannon('abcd').total, 8);
  const expected = -.75*Math.log2(.75) - .25*Math.log2(.25);
  assert.equal(core.shannon('aaab').perSymbol, expected);
});
test('Unicode code points and spaces are preserved; malformed input is rejected', () => {
  assert.equal(core.shannon('🔐🔐a ').length, 4);
  assert.equal(core.shannon('🔐🔐a ').total, 6);
  assert.doesNotThrow(() => core.validate('  a  '));
  assert.doesNotThrow(() => core.validate('🔐'.repeat(128)));
  for (const value of ['', 'a'.repeat(129), 'abc\n', '\ud800', '\udc00']) assert.throws(() => core.validate(value));
  assert.notEqual(core.analyze('secret',zxcvbn).entropy.length,core.analyze(' secret ',zxcvbn).entropy.length);
});
test('Common, keyboard, repeated, leet and dictionary passwords are penalized', () => {
  const cases = [ ['qwerty', 'keyboard'], ['12345678', 'keyboard'], ['aaaaaa', 'repeat'], ['abcabcabc', 'repeat'], ['P@ssw0rd', 'leet'], ['dragon', 'dictionary'] ];
  for (const [sample, pattern] of cases) {
    const result = core.analyze(sample, zxcvbn);
    assert.equal(result.findings[pattern], true, pattern);
    assert.ok(result.score <= 50);
  }
  assert.equal(core.analyze('password123',zxcvbn).score,0);
  const strong = core.analyze('vG7!cQ2#zM9@bL4$kT8%',zxcvbn);
  assert.equal(strong.score,100);
  assert.equal(strong.alphabet,95);
  assert.ok(strong.bruteLogGuesses > strong.logGuesses);
});
test('A high empirical entropy does not override predictable dictionary structure', () => {
  const result = core.analyze('qwertyuiopasdfghjkl',zxcvbn);
  assert.ok(result.entropy.total > 60);
  assert.ok(result.score < 100);
});
test('Report contains only aggregate values and predefined advice, never secret fragments', () => {
  const secret = 'sunshine1234!!';
  const result = core.analyze(secret,zxcvbn), serialized = JSON.stringify(result);
  assert.ok(!serialized.includes(secret));
  assert.ok(!serialized.includes('sunshine'));
  assert.ok(!serialized.includes('token'));
  assert.equal(core.analyze('عبارة سرية مختلفة 🔐',zxcvbn).bruteLogGuesses,null);
});
test('HIBP parser ignores zero padding, validates records, and distinguishes failure from a miss', () => {
  const suffix = 'A'.repeat(35), other = 'B'.repeat(35);
  assert.equal(core.parseRange(suffix+':42\r\n'+other+':0\r\n',suffix),42);
  assert.equal(core.parseRange(suffix+':0\n'+other+':5',suffix),0);
  assert.equal(core.parseRange(other+':5',suffix),0);
  for (const body of ['', 'garbage', suffix+':NaN', suffix+':-1', suffix+':9\nmalformed']) assert.throws(() => core.parseRange(body,suffix));
  assert.throws(() => core.parseRange(other+':5','bad'));
  assert.throws(() => core.parseRange('a'.repeat(2000001),suffix));
});
test('Log-domain crack-time arithmetic avoids overflow and responds to attack rate', () => {
  assert.equal(core.formatTime(-4),'Less than 1 second');
  assert.equal(core.formatTime(Math.log10(3600)), '1 hour');
  assert.equal(core.formatTime(1000),'More than 1 trillion years');
  const result = core.analyze('vG7!cQ2#zM9@bL4$kT8%',zxcvbn);
  assert.notEqual(core.formatTime(result.logGuesses-9),core.formatTime(result.logGuesses-11));
});
