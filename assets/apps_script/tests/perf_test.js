// Focused tests for the perf-instrumentation block in CodeFull.gs.
//
// Run from repo root:  node assets/apps_script/tests/perf_test.js
//
// CodeFull.gs ships with `ENABLE_PERF_LOGGING = false`, so the other
// test suites in this directory exercise the inert (production)
// shape only. This file flips the flag on inside the extracted
// bundle and asserts:
//
//   * `_perfStart` zeroes `_PERF` at the top of every invocation.
//   * `_timedFetch` / `_timedFetchAll` record durations on success
//     AND on failure (the latter is the regression the previous
//     inline `record-after-success` pattern silently dropped, billing
//     slow timeouts as `js=` time).
//   * `_perfReport` emits exactly one `perf:` line, with the
//     documented fields and `js = max(0, total - fetch)`.
//   * Disabled mode: identical observable behaviour with zero writes
//     to `_PERF` and zero `console.log` traffic.

'use strict';

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'CodeFull.gs');
const rawSrc = fs.readFileSync(SRC, 'utf8');

const FUNC_NAMES = [
  '_perfStart', '_perfRecordFetch', '_perfReport',
  '_timedFetch', '_timedFetchAll',
];
const CONST_NAMES = ['ENABLE_PERF_LOGGING', '_PERF'];

function buildBundle(src, perfEnabled) {
  // Toggle the shipped `false` to `true` for the enabled-mode tests.
  // Pinned regex so a future "ENABLE_PERF_LOGGING = ..." rename
  // doesn't silently pass through the test as if it had run.
  const flagRe = /const ENABLE_PERF_LOGGING = (true|false);/;
  if (!flagRe.test(src)) {
    throw new Error(
      'perf_test: source must contain a "const ENABLE_PERF_LOGGING = (true|false);" declaration',
    );
  }
  const adjusted = src.replace(
    flagRe,
    `const ENABLE_PERF_LOGGING = ${perfEnabled ? 'true' : 'false'};`,
  );

  let bundle = '';
  for (const name of CONST_NAMES) {
    const re = new RegExp(`const ${name}\\s*=[\\s\\S]*?;[^\\n]*\\n`);
    const m = adjusted.match(re);
    if (!m) throw new Error('const not found in CodeFull.gs: ' + name);
    bundle += m[0] + '\n';
  }
  for (const name of FUNC_NAMES) {
    const re = new RegExp(`function ${name}\\b[\\s\\S]*?\\n\\}\\n`);
    const m = adjusted.match(re);
    if (!m) throw new Error('function not found in CodeFull.gs: ' + name);
    bundle += m[0] + '\n';
  }
  bundle += `return { ${FUNC_NAMES.concat(CONST_NAMES).join(', ')} };`;
  return bundle;
}

function buildContext(perfEnabled, urlFetchApp) {
  const bundle = buildBundle(rawSrc, perfEnabled);
  // eslint-disable-next-line no-new-func
  const fn = new Function('UrlFetchApp', bundle);
  return fn(urlFetchApp);
}

function makeFetchMock(handler) {
  // `handler({ kind, args })` returns either a fake response object
  // or throws to simulate a UrlFetchApp.fetch failure.
  const calls = [];
  return {
    handle: {
      fetch: (url, opts) => {
        calls.push({ kind: 'fetch', url, opts });
        return handler({ kind: 'fetch', url, opts });
      },
      fetchAll: (args) => {
        calls.push({ kind: 'fetchAll', args });
        return handler({ kind: 'fetchAll', args });
      },
    },
    calls,
  };
}

let _failures = 0;
function ok(label) {
  console.log('  ok — ' + label);
}
function fail(label, detail) {
  _failures++;
  console.log('  FAIL — ' + label + (detail ? ': ' + detail : ''));
}
function eq(label, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    ok(label);
  } else {
    fail(label, `expected ${e}, got ${a}`);
  }
}
function truthy(label, value) {
  if (value) ok(label);
  else fail(label, `expected truthy, got ${JSON.stringify(value)}`);
}

// ───────────────────── perf-enabled tests ─────────────────────

console.log('perf instrumentation (ENABLE_PERF_LOGGING = true)');
{
  const fetchMock = makeFetchMock(() => ({ ok: true }));
  const ctx = buildContext(true, fetchMock.handle);

  // _perfStart resets the scratchpad.
  ctx._PERF.t0 = 99999;
  ctx._PERF.fetch_ms = 7;
  ctx._PERF.fetch_count = 3;
  ctx._perfStart();
  truthy(
    '_perfStart sets t0 to a recent Date.now',
    Math.abs(ctx._PERF.t0 - Date.now()) < 500,
  );
  eq('_perfStart zeroes fetch_ms', ctx._PERF.fetch_ms, 0);
  eq('_perfStart zeroes fetch_count', ctx._PERF.fetch_count, 0);

  // _timedFetch records on success.
  const beforeOk = ctx._PERF.fetch_count;
  const respOk = ctx._timedFetch('https://example/ok', { method: 'get' });
  eq('_timedFetch returns the UrlFetchApp.fetch result', respOk, { ok: true });
  eq(
    '_timedFetch increments fetch_count on success',
    ctx._PERF.fetch_count,
    beforeOk + 1,
  );
  truthy(
    '_timedFetch records a non-negative duration',
    ctx._PERF.fetch_ms >= 0,
  );
}

// _timedFetch records on failure (the Important 1 regression).
{
  const fetchMock = makeFetchMock(() => {
    throw new Error('network: blackholed');
  });
  const ctx = buildContext(true, fetchMock.handle);
  ctx._perfStart();
  let threw = false;
  try {
    ctx._timedFetch('https://example/bad', { method: 'get' });
  } catch (err) {
    threw = true;
  }
  truthy('_timedFetch re-throws the UrlFetchApp error', threw);
  eq(
    '_timedFetch records the failed call (fetch_count++)',
    ctx._PERF.fetch_count,
    1,
  );
  truthy(
    '_timedFetch records duration of the failed call',
    ctx._PERF.fetch_ms >= 0,
  );
}

// _timedFetchAll: same on-failure invariant via fetchAll.
{
  const fetchMock = makeFetchMock((call) => {
    if (call.kind === 'fetchAll') throw new Error('network: blackholed');
    return null;
  });
  const ctx = buildContext(true, fetchMock.handle);
  ctx._perfStart();
  let threw = false;
  try {
    ctx._timedFetchAll([{ url: 'https://a' }, { url: 'https://b' }]);
  } catch (err) {
    threw = true;
  }
  truthy('_timedFetchAll re-throws the UrlFetchApp.fetchAll error', threw);
  eq(
    '_timedFetchAll records the failed call',
    ctx._PERF.fetch_count,
    1,
  );
}

// _perfReport line shape + js clamping.
{
  const ctx = buildContext(true, makeFetchMock(() => ({})).handle);
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    ctx._perfStart();
    // Reach into _PERF to seed deterministic numbers without
    // depending on wall-clock.
    ctx._PERF.t0 = Date.now() - 250; // total ≈ 250 ms
    ctx._PERF.fetch_ms = 200;
    ctx._PERF.fetch_count = 2;
    ctx._perfReport('tunnel_batch', 5);
  } finally {
    console.log = origLog;
  }
  eq('_perfReport emits exactly one line', logs.length, 1);
  const line = logs[0];
  truthy('line starts with perf:', line.startsWith('perf:'));
  truthy('line carries kind', /\bkind=tunnel_batch\b/.test(line));
  truthy('line carries total', /\btotal=\d+\b/.test(line));
  truthy('line carries fetch', /\bfetch=200\b/.test(line));
  truthy('line carries fetches', /\bfetches=2\b/.test(line));
  truthy('line carries js', /\bjs=\d+\b/.test(line));
  truthy('line carries ops', /\bops=5\b/.test(line));

  // js clamping: if fetch > total (clock skew, ungranular Date.now),
  // js must be reported as 0 rather than negative.
  {
    const ctx2 = buildContext(true, makeFetchMock(() => ({})).handle);
    const logs2 = [];
    console.log = (line) => logs2.push(line);
    try {
      ctx2._perfStart();
      ctx2._PERF.t0 = Date.now();      // total ≈ 0
      ctx2._PERF.fetch_ms = 999_999;   // synthetic over-count
      ctx2._PERF.fetch_count = 1;
      ctx2._perfReport('tunnel_data');
    } finally {
      console.log = origLog;
    }
    truthy(
      'js clamps non-negative even when fetch > total',
      /\bjs=0\b/.test(logs2[0]),
    );
    truthy(
      'single-op kinds omit ops field',
      !/\bops=/.test(logs2[0]),
    );
  }
}

// ───────────────────── perf-disabled mode ─────────────────────

console.log('perf instrumentation (ENABLE_PERF_LOGGING = false)');
{
  const fetchMock = makeFetchMock(() => ({ ok: true }));
  const ctx = buildContext(false, fetchMock.handle);

  // _perfStart is a no-op.
  ctx._PERF.t0 = 42;
  ctx._PERF.fetch_ms = 99;
  ctx._PERF.fetch_count = 7;
  ctx._perfStart();
  eq('_perfStart leaves _PERF.t0 untouched', ctx._PERF.t0, 42);
  eq('_perfStart leaves _PERF.fetch_ms untouched', ctx._PERF.fetch_ms, 99);
  eq('_perfStart leaves _PERF.fetch_count untouched', ctx._PERF.fetch_count, 7);

  // _timedFetch tail-calls UrlFetchApp.fetch and writes nothing.
  const beforeMs = ctx._PERF.fetch_ms;
  const beforeCount = ctx._PERF.fetch_count;
  const resp = ctx._timedFetch('https://example', {});
  eq('_timedFetch returns the underlying response', resp, { ok: true });
  eq('_timedFetch.fetch_ms unchanged', ctx._PERF.fetch_ms, beforeMs);
  eq('_timedFetch.fetch_count unchanged', ctx._PERF.fetch_count, beforeCount);

  // _perfReport emits no log line in disabled mode.
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    ctx._perfReport('tunnel_batch', 5);
  } finally {
    console.log = origLog;
  }
  eq('_perfReport emits nothing when disabled', logs.length, 0);
}

if (_failures > 0) {
  console.log('\n' + _failures + ' test(s) failed');
  process.exit(1);
}
console.log('\nperf instrumentation tests passed');
