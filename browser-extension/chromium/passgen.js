// Password generator shared by the content script and the popup.
//
// Rules follow the "passwordrules" syntax sites publish on password fields
// (https://developer.apple.com/password-rules/). desktop-agent/internal/passgen
// implements the same rules for vaultctl.
(function (root) {
  const LOWER = 'abcdefghijklmnopqrstuvwxyz';
  const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const DIGIT = '0123456789';
  const SPECIAL = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  const DEFAULT_SYMBOLS = '!@#$%^&*-_=+.?';
  const DEFAULT_LENGTH = 20;

  function union(a, b) {
    let out = '';
    for (const ch of a + b) {
      const c = ch.charCodeAt(0);
      if (c >= 0x21 && c <= 0x7e && !out.includes(ch)) out += ch;
    }
    return out;
  }

  function defaultPolicy() {
    return {
      length: DEFAULT_LENGTH,
      minLength: 0,
      maxLength: 0,
      required: [LOWER, UPPER, DIGIT, DEFAULT_SYMBOLS],
      allowed: LOWER + UPPER + DIGIT + DEFAULT_SYMBOLS,
      maxConsecutive: 0,
      pattern: null,
      source: 'default',
    };
  }

  function parseClasses(value) {
    let set = '';
    let rest = value.trim();
    while (rest.length) {
      rest = rest.replace(/^[,\s]+/, '');
      if (!rest.length) break;
      if (rest[0] === '[') {
        const end = rest.lastIndexOf(']');
        if (end < 1) throw new Error('unterminated character class');
        set = union(set, rest.slice(1, end));
        rest = rest.slice(end + 1);
        continue;
      }
      const comma = rest.indexOf(',');
      const word = (comma < 0 ? rest : rest.slice(0, comma)).trim().toLowerCase();
      rest = comma < 0 ? '' : rest.slice(comma + 1);
      if (word === 'lower') set = union(set, LOWER);
      else if (word === 'upper') set = union(set, UPPER);
      else if (word === 'digit') set = union(set, DIGIT);
      else if (word === 'special') set = union(set, SPECIAL);
      else if (word === 'ascii-printable' || word === 'unicode') set = union(set, LOWER + UPPER + DIGIT + SPECIAL);
    }
    return set;
  }

  function parseRules(rules) {
    const p = defaultPolicy();
    p.required = [];
    p.allowed = '';
    p.source = 'site rules';
    let sawClass = false;
    for (const part of String(rules || '').split(';')) {
      const i = part.indexOf(':');
      if (i < 0) continue;
      const name = part.slice(0, i).trim().toLowerCase();
      const value = part.slice(i + 1).trim();
      if (name === 'minlength' || name === 'maxlength' || name === 'max-consecutive') {
        const n = parseInt(value, 10);
        if (!Number.isFinite(n) || n < 0) continue;
        if (name === 'minlength') p.minLength = n;
        else if (name === 'maxlength') p.maxLength = n;
        else p.maxConsecutive = n;
      } else if (name === 'required' || name === 'allowed') {
        const set = parseClasses(value);
        sawClass = true;
        if (name === 'required') p.required.push(set);
        p.allowed = union(p.allowed, set);
      }
    }
    if (!sawClass) {
      const d = defaultPolicy();
      p.required = d.required;
      p.allowed = d.allowed;
    }
    return p;
  }

  // policyForField reads the rules a page declares on an input element.
  function policyForField(input) {
    let p = defaultPolicy();
    if (!input) return p;
    const rules = input.getAttribute('passwordrules');
    if (rules) p = parseRules(rules);
    const min = parseInt(input.getAttribute('minlength'), 10);
    const max = parseInt(input.getAttribute('maxlength'), 10);
    if (Number.isFinite(min) && min > 0) {
      p.minLength = Math.max(p.minLength, min);
      p.source = p.source === 'default' ? 'field limits' : p.source;
    }
    if (Number.isFinite(max) && max > 0) {
      p.maxLength = p.maxLength ? Math.min(p.maxLength, max) : max;
      p.source = p.source === 'default' ? 'field limits' : p.source;
    }
    const pattern = input.getAttribute('pattern');
    if (pattern) {
      try {
        p.pattern = new RegExp('^(?:' + pattern + ')$', 'u');
        p.source = p.source === 'default' ? 'field pattern' : p.source;
      } catch (_) {
        p.pattern = null;
      }
    }
    return p;
  }

  // applyOverrides layers the user's saved per-site choices on a policy.
  // overrides: {length?: number, symbols?: boolean, symbolSet?: string}
  function applyOverrides(p, overrides) {
    if (!overrides) return p;
    const q = Object.assign({}, p, { required: p.required.slice() });
    if (overrides.symbols === false || typeof overrides.symbolSet === 'string') {
      const sym = overrides.symbols === false ? '' : overrides.symbolSet;
      q.required = q.required.filter((r) => r !== DEFAULT_SYMBOLS && r !== SPECIAL && !/^[^A-Za-z0-9]+$/.test(r));
      if (sym) q.required.push(sym);
      q.allowed = LOWER + UPPER + DIGIT + (sym || '');
    }
    if (Number.isFinite(overrides.length) && overrides.length > 0) q.length = overrides.length;
    q.source = 'your settings';
    return q;
  }

  function randomIndex(n) {
    // Rejection sampling for an unbiased index.
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    for (;;) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return buf[0] % n;
    }
  }

  function effectiveLength(p) {
    let len = p.length > 0 ? p.length : DEFAULT_LENGTH;
    if (p.maxLength > 0 && len > p.maxLength) len = p.maxLength;
    if (len < p.minLength) len = p.minLength;
    return len;
  }

  function satisfies(pw, p, required) {
    for (const set of required) {
      if (![...pw].some((c) => set.includes(c))) return false;
    }
    if (p.maxConsecutive > 0) {
      let run = 1;
      for (let i = 1; i < pw.length; i++) {
        run = pw[i] === pw[i - 1] ? run + 1 : 1;
        if (run > p.maxConsecutive) return false;
      }
    }
    if (p.pattern && !p.pattern.test(pw)) return false;
    return true;
  }

  function generate(p) {
    p = p || defaultPolicy();
    const len = effectiveLength(p);
    let allowed = p.allowed;
    const required = p.required.filter((r) => r);
    for (const r of required) allowed = union(allowed, r);
    if (!allowed) throw new Error('These rules allow no characters.');
    if (required.length > len) throw new Error('Length ' + len + ' is too short for the required character types.');
    for (let attempt = 0; attempt < 5000; attempt++) {
      let pw = '';
      for (let i = 0; i < len; i++) pw += allowed[randomIndex(allowed.length)];
      if (satisfies(pw, p, required)) return pw;
    }
    throw new Error("Couldn't meet this site's password rules. Adjust the options and try again.");
  }

  function describe(p) {
    const len = effectiveLength(p);
    const parts = [len + ' characters'];
    const hasSym = p.required.some((r) => /^[^A-Za-z0-9]+$/.test(r)) || /[^A-Za-z0-9]/.test(p.allowed);
    parts.push(hasSym ? 'with symbols' : 'letters and digits');
    return parts.join(', ') + ' (' + p.source + ')';
  }

  const api = { LOWER, UPPER, DIGIT, SPECIAL, DEFAULT_SYMBOLS, DEFAULT_LENGTH, defaultPolicy, parseRules, policyForField, applyOverrides, generate, describe, effectiveLength };
  root.UAPassgen = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
