// Cross-handler auth-boundary tests covering both doPost and the
// `/exec/quota` doGet branch in Code.gs, CodeFull.gs, and Code.cfw.gs.
//
// Run from repo root:  node assets/apps_script/tests/auth_guard_test.js
//
// Why this exists, separate from quota_endpoint_test.js: the original
// quota test stubbed AUTH_KEY / DEFAULT_AUTH_KEY as distinct values, so
// it pinned the path/key gate but couldn't catch the more dangerous
// "AUTH_KEY still equals the shipped placeholder" or "AUTH_KEY is
// blank" cases — both of which let anyone use the deployment as a relay
// via doPost (or fingerprint it via /exec/quota).
//
// We extract the function bodies from each .gs source and run them in
// a sandboxed scope with stubbed Apps Script services. Helper functions
// used by doPost / doGet (_isConfiguredAuthKey, _decoyOrError, _json)
// are extracted and bound into the scope so the test exercises the
// real auth-boundary logic, not a mock.

'use strict';

const fs = require('fs');
const path = require('path');

let passed = 0;
function ok(label) { console.log('  ok — ' + label); passed++; }
function fail(label, detail) {
  console.error('FAIL: ' + label + (detail ? ' — ' + detail : ''));
  process.exit(1);
}

/** Extract a top-level `function NAME(...) { ... }` body by brace-matching.
 *
 *  Skips `{` / `}` that appear inside:
 *    - "..." and '...' string literals (with `\` escapes),
 *    - `...` template literals (escapes only — template substitutions
 *      `${expr}` are NOT parsed; if a future extracted body uses one
 *      with `{` inside, we'd miscount. None of the current sources do,
 *      and the doc comment below makes that assumption explicit).
 *    - // line comments,
 *    - / * block comments * /
 *
 *  This is enough for the .gs handlers this test runs against and
 *  catches the real cases the previous naive version would have
 *  silently mis-extracted (e.g. ``Quota probe: `{ k, op: "quota" }` ``
 *  inside a // comment in doPost — the braces there are balanced so
 *  the depth would still net to zero, but an unbalanced one would
 *  truncate the body without warning).
 *
 *  Not handled: regex literals (none in the .gs sources we extract),
 *  template-literal substitutions (`${expr}`), Unicode escape
 *  sequences inside identifiers. If any extracted function grows one
 *  of those, upgrade this to a real tokenizer.
 */
function extractFnBody(src, name) {
  const sig = 'function ' + name + '(';
  const start = src.indexOf(sig);
  if (start < 0) throw new Error('function not found: ' + name);
  const bodyStart = src.indexOf('{', start);
  if (bodyStart < 0) throw new Error('no body for: ' + name);

  let depth = 1;
  let i = bodyStart + 1;
  while (i < src.length && depth > 0) {
    const ch = src[i];

    // String / template literal — skip to the matching closing quote.
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') {
          // Skip the escape and the escaped char.
          i += 2;
        } else {
          i++;
        }
      }
      i++; // past the closing quote (or past EOF — loop terminates)
      continue;
    }

    // Line comment: skip to end of line.
    if (ch === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      i = nl < 0 ? src.length : nl;
      continue;
    }

    // Block comment: skip to `*/`.
    if (ch === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end < 0 ? src.length : end + 2;
      continue;
    }

    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    i++;
  }
  if (depth !== 0) {
    throw new Error(
      'extractFnBody(' + name + '): unbalanced braces, depth ended at ' + depth,
    );
  }
  // `i` points one past the closing `}` of the function body.
  const argStart = src.indexOf('(', start) + 1;
  const argEnd = src.indexOf(')', argStart);
  const args = src.slice(argStart, argEnd);
  return { args: args, body: src.slice(bodyStart + 1, i - 1) };
}

/** Extract `const NAME = <expr>;` from `src` and evaluate the RHS so the
 *  test reflects the production value of the constant (post-
 *  concatenation, post-substring substitution, whatever the source
 *  actually computes). Returns the resolved value (string for our
 *  current use). Throws if the constant is missing — that would mean
 *  someone renamed or deleted the sentinel, which the test SHOULD
 *  surface loudly. */
function extractConst(src, name) {
  const re = new RegExp(
    'const\\s+' + name + '\\s*=\\s*([^;]+);',
  );
  const m = src.match(re);
  if (!m) throw new Error('const not found: ' + name);
  // The RHS may contain string concatenation (`"a" + "b"`) and nothing
  // else (no function calls, no service references). Eval it in an
  // empty scope.
  // eslint-disable-next-line no-new-func
  return new Function('return (' + m[1].trim() + ');')();
}

/** Build a sandbox for one .gs file with stubbed Apps Script services
 *  and the AUTH_KEY / DEFAULT_AUTH_KEY / WORKER_URL constants we want
 *  to test against. Returns { doPost, doGet, lastJson }. */
function buildSandbox(file, opts) {
  const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

  const ContentService = {
    MimeType: { JSON: 'json', HTML: 'html' },
    createTextOutput(text) {
      return {
        text: text,
        mime: null,
        setMimeType(m) { this.mime = m; return this; },
      };
    },
  };
  const UrlFetchApp = {
    getRemainingDailyQuota() { return 12345; },
    // Used by _doSingle / _doBatch in the relay path. Must never be
    // called by the auth-rejection paths we're testing; if it is,
    // the failing test prints `unexpected UrlFetchApp.fetch`.
    fetch() { throw new Error('unexpected UrlFetchApp.fetch call'); },
    fetchAll() { throw new Error('unexpected UrlFetchApp.fetchAll call'); },
  };

  // Helpers used by doPost / doGet — extracted from the same source
  // so the test exercises the real code, not a mock of it. _decoyOrError
  // is wrapped with DIAGNOSTIC_MODE = false so the production HTML path
  // fires; flipping DIAGNOSTIC_MODE for one test would change the
  // signal we're asserting on (mime html vs mime json).
  const DECOY_HTML = '<html></html>';
  const DIAGNOSTIC_MODE = false;

  // _decoyOrError returns either the JSON body (DIAGNOSTIC_MODE) or
  // the decoy HTML. We use the production path.
  function _json(obj) {
    return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
      ContentService.MimeType.JSON,
    );
  }
  function _decoyOrError(jsonBody) {
    if (DIAGNOSTIC_MODE) return _json(jsonBody);
    return ContentService
      .createTextOutput(DECOY_HTML)
      .setMimeType(ContentService.MimeType.HTML);
  }

  // Extract the production _isConfiguredAuthKey so the test exercises
  // the real string-trimming/placeholder check, not a re-implementation.
  const helperSrc = extractFnBody(src, '_isConfiguredAuthKey');
  const _isConfiguredAuthKey = new Function(
    'AUTH_KEY', 'DEFAULT_AUTH_KEY',
    helperSrc.body,
  ).bind(null, opts.AUTH_KEY, opts.DEFAULT_AUTH_KEY);

  // doPost and doGet — same trick. We don't run the relay path so
  // _doSingle / _doBatch / _doTunnel never get called.
  const postSrc = extractFnBody(src, 'doPost');
  const getSrc = extractFnBody(src, 'doGet');

  // The closure parameters need to cover every name doPost/doGet
  // reference. CodeFull.gs also touches _doTunnel; Code.cfw.gs touches
  // WORKER_URL / DEFAULT_WORKER_URL. Provide stubs for all of them so
  // the auth-fail early-return branches run cleanly.
  const closureArgs = [
    'e', 'AUTH_KEY', 'DEFAULT_AUTH_KEY', 'WORKER_URL', 'DEFAULT_WORKER_URL',
    'DECOY_HTML', 'ContentService', 'UrlFetchApp',
    '_isConfiguredAuthKey', '_decoyOrError', '_json',
    '_doSingle', '_doBatch', '_doTunnel',
    // CodeFull.gs's doPost calls these around the dispatch. Inert
    // when `ENABLE_PERF_LOGGING` is false (the shipped default), but
    // we still need to define the symbols so the extracted function
    // body doesn't ReferenceError. No-op stubs are sufficient — this
    // test exercises the auth-fail / dispatch branches, not the
    // timing instrumentation itself.
    '_perfStart', '_perfReport',
    // Tunnel-op allowlist used to normalise `perfKind`. Empty object
    // forces the `tunnel_unknown` fallback, which is fine for the
    // auth-guard tests — they never assert on the perf log line.
    '_PERF_TUNNEL_KIND',
  ];
  function _unexpectedRelay(name) {
    return function () {
      throw new Error('unexpected ' + name + ' call: auth-rejected path leaked into relay');
    };
  }
  function _perfNoop() { /* intentionally inert */ }
  function callFn(body, e) {
    return new Function(...closureArgs, body)(
      e,
      opts.AUTH_KEY,
      opts.DEFAULT_AUTH_KEY,
      opts.WORKER_URL || 'https://configured.example',
      opts.DEFAULT_WORKER_URL || 'https://CHANGE_ME.example',
      DECOY_HTML,
      ContentService,
      UrlFetchApp,
      _isConfiguredAuthKey,
      _decoyOrError,
      _json,
      _unexpectedRelay('_doSingle'),
      _unexpectedRelay('_doBatch'),
      _unexpectedRelay('_doTunnel'),
      _perfNoop,
      _perfNoop,
      {},
    );
  }
  return {
    doPost: function (e) { return callFn(postSrc.body, e); },
    doGet: function (e) { return callFn(getSrc.body, e); },
    _isConfiguredAuthKey: _isConfiguredAuthKey,
  };
}

// Each file tested with the same set of AUTH_KEY values:
//   - placeholder: the shipped template default → must reject
//   - blank / whitespace → must reject
//   - real configured key → must accept (and route the request)
const REAL_KEY = 'my-real-secret-42';

const HANDLER_FILES = ['Code.gs', 'CodeFull.gs', 'Code.cfw.gs'];

// ─── extractFnBody self-tests ─────────────────────────────────────────
// Synthetic sources whose function bodies contain `{` / `}` inside
// strings, template literals, and comments. The naive brace-counter
// would mis-extract every one of these. Each case picks a body whose
// raw brace count is intentionally unbalanced (one extra `{` or `}`
// inside a string/comment) so a regression would change the extracted
// text, not just silently re-balance.
console.log('extractFnBody self-tests');
{
  const cases = [
    {
      label: 'brace in double-quoted string',
      src: 'function f() { var x = "}"; return x; }',
      expectBody: ' var x = "}"; return x; ',
    },
    {
      label: 'brace in single-quoted string',
      src: "function f() { var x = '{{{'; return x; }",
      expectBody: " var x = '{{{'; return x; ",
    },
    {
      label: 'brace in template literal',
      src: 'function f() { var x = `}`; return x; }',
      expectBody: ' var x = `}`; return x; ',
    },
    {
      label: 'brace in line comment',
      src: 'function f() { // }}}\n return 1; }',
      expectBody: ' // }}}\n return 1; ',
    },
    {
      label: 'brace in block comment',
      src: 'function f() { /* }}} */ return 1; }',
      expectBody: ' /* }}} */ return 1; ',
    },
    {
      label: 'escaped quote inside string',
      src: 'function f() { var x = "say \\"}\\""; return x; }',
      expectBody: ' var x = "say \\"}\\""; return x; ',
    },
    {
      label: 'nested real braces still count',
      src: 'function f() { if (x) { return { a: 1 }; } return null; }',
      expectBody: ' if (x) { return { a: 1 }; } return null; ',
    },
  ];
  for (const c of cases) {
    const out = extractFnBody(c.src, 'f');
    if (out.body !== c.expectBody) {
      fail(
        'extractFnBody (' + c.label + ') mis-extracted',
        'expected ' + JSON.stringify(c.expectBody)
          + ', got ' + JSON.stringify(out.body),
      );
    }
    ok('extractFnBody handles ' + c.label);
  }
}

// ─── 0. Source-truth check: the shipped AUTH_KEY placeholder must
//     equal the value `_isConfiguredAuthKey` compares against. If a
//     future edit changes the AUTH_KEY default but not the sentinel
//     (or vice versa), `_isConfiguredAuthKey()` would silently
//     start returning true for the placeholder and reopen the
//     fingerprinting / public-relay hole this test is meant to guard.
//
//     We read both constants from the actual source so the assertion
//     reflects whatever the file currently ships, not a hardcoded
//     literal in this test. The split-string concatenation in the
//     sentinel (see Code.gs "SENTINELS — DO NOT EDIT") is evaluated
//     by `extractConst` so the resolved value, not the source
//     expression, is what we compare.
console.log('source-truth check');
for (const file of HANDLER_FILES) {
  const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const shippedAuthKey = extractConst(src, 'AUTH_KEY');
  const sentinel = extractConst(src, 'DEFAULT_AUTH_KEY');
  if (shippedAuthKey !== sentinel) {
    fail(
      file + ': shipped AUTH_KEY (' + JSON.stringify(shippedAuthKey)
        + ') does not equal DEFAULT_AUTH_KEY sentinel ('
        + JSON.stringify(sentinel)
        + '). _isConfiguredAuthKey() would now return true for the '
        + 'shipped placeholder, defeating the fail-closed guard.',
    );
  }
  ok(file + ': shipped AUTH_KEY matches DEFAULT_AUTH_KEY sentinel ('
    + JSON.stringify(shippedAuthKey) + ')');
}
// All three files must agree on the same placeholder string — otherwise
// a copy-paste across files would silently bypass the guard in the
// non-matching one. Pick Code.gs as the canonical reference.
const PLACEHOLDER = extractConst(
  fs.readFileSync(path.join(__dirname, '..', 'Code.gs'), 'utf8'),
  'DEFAULT_AUTH_KEY',
);
for (const file of HANDLER_FILES) {
  const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const v = extractConst(src, 'DEFAULT_AUTH_KEY');
  if (v !== PLACEHOLDER) {
    fail(
      file + ': DEFAULT_AUTH_KEY (' + JSON.stringify(v) + ') diverges from '
        + 'Code.gs (' + JSON.stringify(PLACEHOLDER) + '). Use the same '
        + 'placeholder string across all three handlers.',
    );
  }
}
ok('all three handlers share the same placeholder string');

// ─── 1. _isConfiguredAuthKey helper invariants per file ───────────────
for (const file of HANDLER_FILES) {
  console.log(file + ' :: _isConfiguredAuthKey');
  function check(authKey, expected, label) {
    const sb = buildSandbox(file, {
      AUTH_KEY: authKey,
      DEFAULT_AUTH_KEY: PLACEHOLDER,
    });
    const got = sb._isConfiguredAuthKey();
    if (got !== expected) {
      fail(
        file + ' :: _isConfiguredAuthKey(' + JSON.stringify(authKey) + ') expected '
          + expected + ' got ' + got,
      );
    }
    ok(label);
  }
  check(PLACEHOLDER, false, 'placeholder AUTH_KEY → not configured');
  check('', false, 'empty AUTH_KEY → not configured');
  check('   ', false, 'whitespace AUTH_KEY → not configured');
  check('\t\n', false, 'tab/newline AUTH_KEY → not configured');
  check(REAL_KEY, true, 'real configured AUTH_KEY → configured');
}

// ─── 2. doPost must fail-closed on placeholder + blank ─────────────────
for (const file of HANDLER_FILES) {
  console.log(file + ' :: doPost');
  function expectSetupErrorJson(authKey, label) {
    const sb = buildSandbox(file, {
      AUTH_KEY: authKey,
      DEFAULT_AUTH_KEY: PLACEHOLDER,
    });
    // The body content matters less than the early-return-as-JSON
    // signal: the handler must return a `_json({ e: "configure ..." })`
    // and NOT reach the body parser (which would try to JSON.parse
    // undefined and throw). We pass a no-postData event to confirm
    // the early-return is what fires.
    const res = sb.doPost({});
    if (res.mime !== 'json') {
      fail(
        file + ' :: doPost(' + label + ') must return setup-error JSON (got mime ' + res.mime + ')',
      );
    }
    if (!/configure AUTH_KEY/.test(res.text)) {
      fail(
        file + ' :: doPost(' + label + ') JSON body must mention "configure AUTH_KEY"',
        res.text,
      );
    }
    ok('doPost(' + label + ') → setup-error JSON');
  }
  expectSetupErrorJson(PLACEHOLDER, 'placeholder AUTH_KEY');
  expectSetupErrorJson('', 'empty AUTH_KEY');
  expectSetupErrorJson('   ', 'whitespace AUTH_KEY');

  // Wrong-key with a real configured AUTH_KEY → decoy (existing
  // behaviour preserved; this guards against accidentally short-
  // circuiting the wrong-key path on top of the new setup gate).
  const sb = buildSandbox(file, {
    AUTH_KEY: REAL_KEY,
    DEFAULT_AUTH_KEY: PLACEHOLDER,
  });
  const wrongRes = sb.doPost({
    postData: { contents: JSON.stringify({ k: 'wrong-key' }) },
  });
  if (wrongRes.mime !== 'html') {
    fail(file + ' :: doPost wrong-key must return decoy HTML', 'got mime ' + wrongRes.mime);
  }
  ok('doPost wrong-key (configured AUTH_KEY) → decoy HTML');

  // POST quota op (the URL-safe alternative to GET /quota?k=…). With
  // a configured key + matching `req.k` + `op: "quota"`, the handler
  // must short-circuit BEFORE _doSingle / _doBatch (else our
  // unexpected-relay stubs would throw) and return JSON.
  const quotaRes = sb.doPost({
    postData: { contents: JSON.stringify({ k: REAL_KEY, op: 'quota' }) },
  });
  if (quotaRes.mime !== 'json') {
    fail(file + ' :: doPost {op:"quota"} must return JSON', 'got mime ' + quotaRes.mime);
  }
  if (!/remaining/.test(quotaRes.text)) {
    fail(file + ' :: doPost {op:"quota"} JSON body must include "remaining"', quotaRes.text);
  }
  ok('doPost {k, op:"quota"} (configured AUTH_KEY) → JSON {remaining: ...}');

  // POST quota op with WRONG key must hit the bad-auth decoy, not
  // return quota — this is the regression for "POST quota leaks
  // before the key check".
  const quotaWrong = sb.doPost({
    postData: { contents: JSON.stringify({ k: 'wrong-key', op: 'quota' }) },
  });
  if (quotaWrong.mime !== 'html') {
    fail(file + ' :: doPost {op:"quota"} with wrong key must return decoy HTML');
  }
  ok('doPost {k:wrong, op:"quota"} → decoy HTML');
}

// ─── 3. /exec/quota must reject placeholder AND blank cases ────────────
for (const file of HANDLER_FILES) {
  console.log(file + ' :: doGet /quota');
  function expectDecoy(authKey, reqK, label) {
    const sb = buildSandbox(file, {
      AUTH_KEY: authKey,
      DEFAULT_AUTH_KEY: PLACEHOLDER,
    });
    const res = sb.doGet({ pathInfo: 'quota', parameter: { k: reqK } });
    if (res.mime !== 'html') {
      fail(
        file + ' :: /quota with ' + label + ' must return decoy (got mime ' + res.mime + ')',
        res.text,
      );
    }
    ok('/quota (' + label + ') → decoy HTML');
  }
  // Placeholder AUTH_KEY: even a matching req.k must NOT leak quota.
  expectDecoy(PLACEHOLDER, PLACEHOLDER, 'placeholder AUTH_KEY === req.k');
  // Blank AUTH_KEY: req.k:"" would otherwise match trivially.
  expectDecoy('', '', 'blank AUTH_KEY and blank req.k');
  expectDecoy('   ', '   ', 'whitespace AUTH_KEY and whitespace req.k');

  // Configured AUTH_KEY + matching req.k → quota JSON.
  const sb = buildSandbox(file, {
    AUTH_KEY: REAL_KEY,
    DEFAULT_AUTH_KEY: PLACEHOLDER,
  });
  const res = sb.doGet({ pathInfo: 'quota', parameter: { k: REAL_KEY } });
  if (res.mime !== 'json') {
    fail(file + ' :: /quota (configured + matching key) must return JSON', 'mime ' + res.mime);
  }
  if (!/remaining/.test(res.text)) {
    fail(file + ' :: /quota JSON body must include "remaining"', res.text);
  }
  ok('/quota (configured AUTH_KEY + matching k) → JSON {remaining: ...}');
}

console.log('passed: ' + passed);
