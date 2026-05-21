/**
 * DomainFront Relay + Full Tunnel — Google Apps Script
 *
 * FOUR modes:
 *   1. Single relay:  POST { k, m, u, h, b, ct, r }           → { s, h, b }
 *   2. Batch relay:   POST { k, q: [{m,u,h,b,ct,r}, ...] }    → { q: [{s,h,b}, ...] }
 *   3. Tunnel:        POST { k, t, h, p, sid, d }              → { sid, d, eof }
 *   4. Tunnel batch:  POST { k, t:"batch", ops:[...] }         → { r: [...] }
 *      Batch ops include TCP (`connect`, `data`) and UDP (`udp_open`,
 *      `udp_data`) tunnel-node operations.
 *
 * CHANGE THESE TO YOUR OWN VALUES!
 */

const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
const TUNNEL_SERVER_URL = "https://YOUR_TUNNEL_NODE_URL";
const TUNNEL_AUTH_KEY = "YOUR_TUNNEL_AUTH_KEY";

// Active-probing defense. When false (production default), bad AUTH_KEY
// requests get a decoy HTML page that looks like a placeholder Apps
// Script web app instead of the JSON `{"e":"unauthorized"}` body. This
// makes the deployment indistinguishable from a forgotten-but-public
// Apps Script project to active scanners that POST malformed payloads
// looking for proxy endpoints.
//
// Set to `true` during initial setup if a misconfigured client is
// hitting "unauthorized" and you want the explicit JSON error to debug
// — then flip back to false before the deployment is widely shared.
const DIAGNOSTIC_MODE = false;

// Connection-level + IP-leak request headers we strip before forwarding
// to the destination. UrlFetchApp rejects most of the connection-level
// names anyway, but we also drop the `X-Forwarded-*` / `Forwarded` /
// `Via` family so that a misconfigured upstream proxy on the user side
// can't leak the user's real IP through the relay path.
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  "priority": 1, te: 1,
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "x-real-ip": 1, "forwarded": 1, "via": 1,
};

// Methods we consider safe to replay if `UrlFetchApp.fetchAll()` raises.
// GET/HEAD/OPTIONS are idempotent per RFC 9110; POST/PUT/PATCH/DELETE
// can have side-effects so we surface the error instead of silently
// re-firing them.
const SAFE_REPLAY_METHODS = { GET: 1, HEAD: 1, OPTIONS: 1 };

// Compiled once to avoid re-parsing per request in the relay hot path.
const URL_RE = /^https?:\/\//i;

// HTML body for the bad-auth decoy. Mimics a minimal Apps Script-style
// placeholder page — no proxy-shaped JSON, nothing distinctive enough
// for a probe to fingerprint as a tunnel endpoint.
const DECOY_HTML =
  '<!DOCTYPE html><html><head><title>Web App</title></head>' +
  '<body><p>The script completed but did not return anything.</p>' +
  '</body></html>';

function _decoyOrError(jsonBody) {
  if (DIAGNOSTIC_MODE) return _json(jsonBody);
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

// True when AUTH_KEY has been customised away from the shipped template
// AND is not blank/whitespace. Centralised so every code path that
// depends on AUTH_KEY being meaningful (doPost, /quota) checks the
// same invariant. See Code.gs for the per-half rationale.
function _isConfiguredAuthKey() {
  if (typeof AUTH_KEY !== "string") return false;
  var trimmed = AUTH_KEY.trim();
  return trimmed.length > 0 && trimmed !== DEFAULT_AUTH_KEY;
}

// Edge DNS cache. Plain UDP/53 queries normally traverse the full
// client → GAS → tunnel-node → public resolver path, and the
// trans-Atlantic round-trip dominates first-hop latency. When
// ENABLE_EDGE_DNS_CACHE is true, _doTunnelBatch intercepts udp_open
// ops with port=53 and serves CacheService hits locally. Cache misses
// may spend a small, bounded number of DoH fetches from inside Google's
// network; once that budget is exhausted, misses fall back to the normal
// tunnel-node batch path and their replies are cached opportunistically.
// Cache hits never reach the tunnel-node and cost zero UrlFetchApp quota.
//
// Safety property: parse errors, refused qtypes, and "every DoH resolver
// failed" return null from _edgeDnsResolve and the op falls through to
// the existing tunnel-node forward path. CacheService failures (transient
// quota, getAll exceptions, oversize keys) are softer: the per-batch
// cache lookup is skipped and no persistent put happens, but the bounded
// DoH miss budget may still run from inside Google's network. The per-op
// outcome degrades to "uncached forward via DoH" or "forwarded all the
// way to the tunnel-node" rather than failing the batch.
// Set ENABLE_EDGE_DNS_CACHE=false to disable the whole feature and route
// all DNS through the tunnel as before.
const ENABLE_EDGE_DNS_CACHE = true;

// Maximum extra UrlFetchApp calls a single tunnel batch may spend on DoH
// cache misses. This is deliberately low: warm cache hits are the real
// quota win, while cold bursts of many distinct names should not explode
// from one tunnel-node fetch into N DoH fetches. Set to 0 for pure
// quota-saving (learn only from forwarded tunnel-node replies), or raise
// if first-hit DNS latency matters more than daily UrlFetchApp count.
const EDGE_DNS_MAX_DOH_FETCHES_PER_BATCH = 1;

// DoH endpoints tried in order on cache miss, subject to the per-batch
// fetch budget above. All speak RFC 8484 over GET. Apps Script's
// outbound network peers well to all three.
const EDGE_DNS_RESOLVERS = [
  "https://1.1.1.1/dns-query",
  "https://dns.google/dns-query",
  "https://dns.quad9.net/dns-query",
];

// CacheService bounds: 6h max TTL, 100KB per value, ~1000 keys, 250-char keys.
const EDGE_DNS_MIN_TTL_S = 30;
const EDGE_DNS_MAX_TTL_S = 21600;   // 6h CacheService ceiling
// Used for NXDOMAIN/SERVFAIL and the rare "no answer + no SOA in authority"
// case. NOERROR/NODATA replies normally carry an SOA, and per RFC 2308 §5
// we honor that SOA's TTL via _dnsMinTtl (the positive path).
const EDGE_DNS_NEG_TTL_S = 45;
const EDGE_DNS_CACHE_PREFIX = "edns:";
// CacheService rejects keys longer than 250 chars. Names approaching the
// 253-char DNS limit + prefix + qtype digits can exceed that, so keys
// over this length get switched to a SHA-256-hashed form (see
// _edgeDnsPrepare) rather than skipping the cache entirely.
const EDGE_DNS_MAX_KEY_LEN = 240;

// qtypes we refuse to cache and pass through to the tunnel-node:
//   255 = ANY (resolvers handle it more correctly than we would)
const EDGE_DNS_REFUSE_QTYPES = { 255: 1 };

// Per-request latency instrumentation. Off by default — turn on to
// capture timing data and tell whether the per-RTT cost is in our
// JS (parse / dispatch / serialize) or in fixed Apps Script /
// UrlFetchApp overhead we can't fix from this file.
//
// When true, `doPost` records the total handler wall-clock and the
// sum of all `UrlFetchApp.fetch` / `fetchAll` durations, then emits
// a single grep-friendly line to Stackdriver via `console.log`:
//
//   perf: kind=tunnel_batch total=712 fetch=620 fetches=1 js=92 ops=5
//
// `js = total - fetch` is the cost we own; high `js` numbers point at
// things this file can optimise (parse cost, edge-DNS bookkeeping,
// splice/serialize). High `fetch` numbers with low `js` are the
// Apps-Script / Google-network floor and are not fixable here.
//
// Reading the logs: View → Executions in the Apps Script editor (or
// the Cloud Logging console for the script's GCP project). Each
// invocation emits at most one `perf:` line. Filter the log query
// for `"perf:"` to get a clean stream.
//
// Disable in production once you've captured enough samples —
// `console.log` round-trips add a tiny but non-zero overhead even
// at no-op-log levels under heavy load.
const ENABLE_PERF_LOGGING = false;

// Per-invocation timing scratchpad. Reset at the top of every
// `doPost` so totals never carry across requests, even on the rare
// long-lived V8 context that retains module globals between
// invocations. `const` with mutable fields satisfies the test
// extractor (which only matches `const NAME = ...`) while allowing
// the counters to update in place.
const _PERF = { t0: 0, fetch_ms: 0, fetch_count: 0 };

// Allowlist of tunnel op names whose verbatim form is safe to put in
// the `perf:` log line. Anything not in this map buckets to
// `tunnel_unknown` so a malformed / hostile `req.t` can't smuggle
// control characters or oversize strings into Cloud Logging.
const _PERF_TUNNEL_KIND = {
  batch: "tunnel_batch",
  connect: "tunnel_connect",
  connect_data: "tunnel_connect_data",
  data: "tunnel_data",
  close: "tunnel_close",
};

// ═══════════════════════════════════════════════════════════════════
//  ▸▸▸  SENTINELS — DO NOT EDIT  ◂◂◂
//
//  These constants are NOT configuration. They are the literal
//  template-default values used by `_isConfiguredAuthKey()` to detect
//  a deployment whose AUTH_KEY hasn't been changed from the shipped
//  placeholder, so we can fail-closed instead of silently accepting
//  the public-knowledge secret as valid auth.
//
//  IMPORTANT: the placeholder string is reconstructed at runtime from
//  two non-matching fragments. A naive find-replace of the AUTH_KEY
//  literal at the top of this file (e.g. "CHANGE_ME_TO_A_STRONG_SECRET"
//  → "my-secret") would otherwise simultaneously overwrite this
//  sentinel and silently disable the fail-closed check. Splitting the
//  literal means the same find-replace leaves the sentinel intact and
//  the guard keeps working. Do not "fix" this by collapsing the
//  concatenation back into one string literal.
// ═══════════════════════════════════════════════════════════════════
const DEFAULT_AUTH_KEY = "CHANGE_ME_" + "TO_A_STRONG_SECRET";

// ========================== Perf instrumentation ==========================

function _perfStart() {
  if (!ENABLE_PERF_LOGGING) return;
  _PERF.t0 = Date.now();
  _PERF.fetch_ms = 0;
  _PERF.fetch_count = 0;
}

// Called by `_timedFetch` / `_timedFetchAll` to fold a measured
// duration into the per-invocation totals. No-op when
// instrumentation is off.
function _perfRecordFetch(ms) {
  if (!ENABLE_PERF_LOGGING) return;
  _PERF.fetch_ms += ms;
  _PERF.fetch_count += 1;
}

// Drop-in replacements for `UrlFetchApp.fetch` / `fetchAll` that
// record the call's wall-clock duration into the perf totals. Two
// invariants over the prior inline pattern:
//
//   1. **Failures are counted.** The try/finally ensures
//      `_perfRecordFetch` runs even when UrlFetchApp throws (slow
//      timeout, network error, quota throttle). The earlier "record
//      after success" pattern billed those exact-when-diagnostic
//      durations as `js=` time, hiding the real source.
//   2. **Zero overhead when disabled.** When `ENABLE_PERF_LOGGING`
//      is false the helper is one tail call to UrlFetchApp — no
//      Date.now, no try/finally bookkeeping, no helper-call frame.
//
// All call sites in this file go through these two functions so the
// invariants stay centralised. Don't call `UrlFetchApp.fetch`
// directly from new code in this file — use `_timedFetch`.
function _timedFetch(url, opts) {
  if (!ENABLE_PERF_LOGGING) return UrlFetchApp.fetch(url, opts);
  var t = Date.now();
  try {
    return UrlFetchApp.fetch(url, opts);
  } finally {
    _perfRecordFetch(Date.now() - t);
  }
}

function _timedFetchAll(args) {
  if (!ENABLE_PERF_LOGGING) return UrlFetchApp.fetchAll(args);
  var t = Date.now();
  try {
    return UrlFetchApp.fetchAll(args);
  } finally {
    // `fetchAll` is one HTTP execution slot from Apps Script's POV
    // regardless of per-item count, so we record one sample for the
    // whole call. Per-item breakdown isn't available from the sync
    // `fetchAll` API.
    _perfRecordFetch(Date.now() - t);
  }
}

// Single perf line emitted at the end of every `doPost` invocation.
// `kind` is the dispatch branch (tunnel_batch / single_relay / etc.)
// so logs from a mixed-mode deployment can be filtered. `opsCount` is
// included only when meaningful (batch sizes); single-shot kinds pass
// null and the field is omitted.
function _perfReport(kind, opsCount) {
  if (!ENABLE_PERF_LOGGING) return;
  var total = Date.now() - _PERF.t0;
  var fetch = _PERF.fetch_ms;
  var js = total - fetch;
  if (js < 0) js = 0; // clock drift defensive — never report negative
  var line =
    "perf: kind=" + kind +
    " total=" + total +
    " fetch=" + fetch +
    " fetches=" + _PERF.fetch_count +
    " js=" + js;
  if (opsCount != null) line += " ops=" + opsCount;
  console.log(line);
}

// ========================== Entry point ==========================

function doPost(e) {
  _perfStart();
  // Classification captured outside the try so the finally clause
  // can report it even on parse failure / unauthorized / decoy.
  // Defaults to "error" so anything that exits via the catch is
  // visibly bucketed.
  var perfKind = "error";
  var perfOps = null;
  try {
    // Fail-closed BEFORE parsing if AUTH_KEY is still the template
    // placeholder or blank — see Code.gs::doPost for the rationale.
    if (!_isConfiguredAuthKey()) {
      perfKind = "no_auth_config";
      return _json({ e: "configure AUTH_KEY in CodeFull.gs" });
    }

    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) {
      perfKind = "bad_auth";
      return _decoyOrError({ e: "unauthorized" });
    }

    // Quota probe: `{ k, op: "quota" }` → `{ remaining: N }`. The
    // preferred quota path — auth key in the body rather than the URL
    // (which `GET /exec/quota?k=…` leaks into history / logs).
    if (req.op === "quota") {
      perfKind = "quota";
      return _json({ remaining: _remainingUrlFetchQuota() });
    }

    // Tunnel mode
    if (req.t) {
      // Allowlist the known tunnel ops so adversarial `req.t` values
      // (control characters, oversize strings, log-injection
      // attempts) bucket cleanly to `tunnel_unknown` instead of
      // landing verbatim in Cloud Logging.
      perfKind = _PERF_TUNNEL_KIND[req.t] || "tunnel_unknown";
      if (req.t === "batch" && req.ops && req.ops.length != null) {
        perfOps = req.ops.length;
      }
      return _doTunnel(req);
    }

    // Batch relay mode
    if (Array.isArray(req.q)) {
      perfKind = "batch_relay";
      perfOps = req.q.length;
      return _doBatch(req.q);
    }

    // Single relay mode
    perfKind = "single_relay";
    return _doSingle(req);
  } catch (err) {
    // Parse failures of the request body are also probe-shaped — a real
    // rahgozar client never sends invalid JSON. Decoy for the same reason.
    return _decoyOrError({ e: String(err) });
  } finally {
    _perfReport(perfKind, perfOps);
  }
}

// ========================== Tunnel mode ==========================

function _doTunnel(req) {
  // Batch tunnel: { k, t:"batch", ops:[...] }
  if (req.t === "batch") {
    return _doTunnelBatch(req);
  }

  // Single tunnel op
  var payload = { k: TUNNEL_AUTH_KEY };
  switch (req.t) {
    case "connect":
      payload.op = "connect";
      payload.host = req.h;
      payload.port = req.p;
      break;
    case "connect_data":
      payload.op = "connect_data";
      payload.host = req.h;
      payload.port = req.p;
      if (req.d) payload.data = req.d;
      break;
    case "data":
      payload.op = "data";
      payload.sid = req.sid;
      if (req.d) payload.data = req.d;
      break;
    case "close":
      payload.op = "close";
      payload.sid = req.sid;
      break;
    default:
      // Structured `code` lets the Rust client detect version skew
      // without substring-matching the error text. Must match
      // CODE_UNSUPPORTED_OP in tunnel_client.rs and tunnel-node/src/main.rs.
      return _json({ e: "unknown tunnel op: " + req.t, code: "UNSUPPORTED_OP" });
  }

  var resp = _timedFetch(TUNNEL_SERVER_URL + "/tunnel", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true,
  });

  if (resp.getResponseCode() !== 200) {
    return _json({ e: "tunnel node HTTP " + resp.getResponseCode() });
  }

  return ContentService.createTextOutput(resp.getContentText())
    .setMimeType(ContentService.MimeType.JSON);
}

// Batch tunnel: forward all ops in one request to /tunnel/batch.
// When ENABLE_EDGE_DNS_CACHE is true, udp_open/port=53 ops are served
// locally where possible and only the remainder is forwarded.
//
// Edge-DNS resolution runs in two passes so the CacheService backend
// is hit exactly once for the whole batch:
//   pass 1: parse each candidate's question and collect cache keys
//   one cache.getAll(keys) call serves every hit
//   pass 2: resolve each candidate (cache hit → synth; miss → bounded DoH;
//           null → tunnel-node forward)
// On a 5-DNS-query batch, this collapses 5 serial cache.get round trips
// into one cache.getAll round trip.
function _doTunnelBatch(req) {
  // Compressed batch: forward opaquely, skip edge-DNS inspection.
  if (req.zops) {
    return _doTunnelBatchForwardCompressed(req.zops);
  }

  var ops = (req && req.ops) || [];
  var zc = req && req.zc;

  // Feature off: byte-identical to the pre-feature behavior.
  if (!ENABLE_EDGE_DNS_CACHE) {
    return _doTunnelBatchForward(ops, zc);
  }

  var results = new Array(ops.length);   // sparse: filled by edge-DNS hits
  var forwardOps = [];
  var forwardIdx = [];
  var forwardPrep = [];  // same shape as forwardOps; DNS prep or null

  // Pass 1: route non-DNS ops to forward, parse DNS candidates.
  var candidates = [];   // [{ i, prep }, ...]
  for (var i = 0; i < ops.length; i++) {
    var op = ops[i];
    if (op && op.op === "udp_open" && op.port === 53 && op.d) {
      var prep = _edgeDnsPrepare(op);
      if (prep) {
        candidates.push({ i: i, prep: prep });
        continue;
      }
    }
    forwardOps.push(op);
    forwardIdx.push(i);
    forwardPrep.push(null);
  }

  // One batched cache lookup for every DNS candidate. CacheService.getAll
  // returns a {key: value} map populated only for hits; missing keys are
  // simply absent. Any failure (transient quota, backend hiccup) returns
  // an empty map so candidates fall through to the bounded DoH/tunnel
  // path with no persistent cache put — the safe degradation path.
  var cacheMap = {};
  var cache = null;
  if (candidates.length > 0) {
    try {
      cache = CacheService.getScriptCache();
      var keys = [];
      var seenKeys = {};
      for (var c = 0; c < candidates.length; c++) {
        var key = candidates[c].prep.key;
        if (!Object.prototype.hasOwnProperty.call(seenKeys, key)) {
          seenKeys[key] = 1;
          keys.push(key);
        }
      }
      cacheMap = cache.getAll(keys) || {};
    } catch (_) {
      cacheMap = {};
      cache = null;
    }
  }

  // Pass 2: resolve each candidate. cacheMap doubles as the in-batch dedup
  // table — a successful DoH writes its encoded reply back into cacheMap
  // so a later candidate with the same qname/qtype hits without re-DoH.
  // On null (cache miss + DoH failed or budget exhausted), append to the
  // forward path so the tunnel-node still gets a chance.
  var dohBudget = { remaining: EDGE_DNS_MAX_DOH_FETCHES_PER_BATCH };
  for (var c = 0; c < candidates.length; c++) {
    var cand = candidates[c];
    var synth = _edgeDnsResolve(
      cand.prep, cacheMap[cand.prep.key] || null, cache, cacheMap, dohBudget);
    if (synth) {
      results[cand.i] = synth;
    } else {
      forwardOps.push(ops[cand.i]);
      forwardIdx.push(cand.i);
      forwardPrep.push(cand.prep);
    }
  }

  // All ops served locally — no tunnel-node round-trip.
  if (forwardOps.length === 0) {
    return _json({ r: results });
  }

  // Nothing was served locally and there were no DNS candidates to learn
  // from — forward verbatim, no parse/splice overhead.
  if (forwardOps.length === ops.length && candidates.length === 0) {
    return _doTunnelBatchForward(ops, zc);
  }

  // Forward the un-served ops. DNS replies that came back from the
  // tunnel-node are cached here, so the next batch can hit locally without
  // spending an extra DoH fetch first. zc is intentionally not passed —
  // Apps Script must parse r[] for the splice path, so the response can't
  // be compressed.
  var resp = _doTunnelBatchFetch(forwardOps);
  if (resp.error) return _json({ e: resp.error });
  if (resp.r.length !== forwardOps.length) {
    // Tunnel-node version skew — bail explicitly rather than silently
    // route TCP responses to UDP sids.
    return _json({ e: "tunnel batch length mismatch" });
  }
  _edgeDnsCacheForwardedReplies(forwardPrep, resp.r, cache);
  if (forwardOps.length === ops.length) {
    return ContentService.createTextOutput(resp.text)
      .setMimeType(ContentService.MimeType.JSON);
  }
  return _json({ r: _spliceTunnelResults(forwardIdx, resp.r, results) });
}

// Verbatim forward: no splice, response passed through unchanged.
function _doTunnelBatchForward(ops, zc) {
  var body = { k: TUNNEL_AUTH_KEY, ops: ops };
  if (zc) body.zc = zc;
  var resp = _timedFetch(TUNNEL_SERVER_URL + "/tunnel/batch", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(body),
    muteHttpExceptions: true,
    followRedirects: true,
  });
  if (resp.getResponseCode() !== 200) {
    return _json({ e: "tunnel batch HTTP " + resp.getResponseCode() });
  }
  return ContentService.createTextOutput(resp.getContentText())
    .setMimeType(ContentService.MimeType.JSON);
}

// Compressed forward: zops is an opaque blob, passed to tunnel-node as-is.
// Response is also opaque (may contain zr instead of r).
function _doTunnelBatchForwardCompressed(zops) {
  var resp = _timedFetch(TUNNEL_SERVER_URL + "/tunnel/batch", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ k: TUNNEL_AUTH_KEY, zops: zops }),
    muteHttpExceptions: true,
    followRedirects: true,
  });
  if (resp.getResponseCode() !== 200) {
    return _json({ e: "tunnel batch HTTP " + resp.getResponseCode() });
  }
  return ContentService.createTextOutput(resp.getContentText())
    .setMimeType(ContentService.MimeType.JSON);
}

// Forward + parse for the splice path. Returns { r:[...] } on success or
// { error: "..." } on any failure.
function _doTunnelBatchFetch(ops) {
  var body = { k: TUNNEL_AUTH_KEY, ops: ops };
  var resp = _timedFetch(TUNNEL_SERVER_URL + "/tunnel/batch", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(body),
    muteHttpExceptions: true,
    followRedirects: true,
  });
  if (resp.getResponseCode() !== 200) {
    return { error: "tunnel batch HTTP " + resp.getResponseCode() };
  }
  try {
    var text = resp.getContentText();
    var parsed = JSON.parse(text);
    return { r: (parsed && parsed.r) || [], text: text };
  } catch (err) {
    return { error: "tunnel batch parse error" };
  }
}

// Pure helper: writes forwardedResults[j] into allResults[forwardIdx[j]]
// for each j. Returns the mutated allResults so callers can chain. Pure
// function — testable without the GAS runtime.
function _spliceTunnelResults(forwardIdx, forwardedResults, allResults) {
  for (var j = 0; j < forwardIdx.length; j++) {
    allResults[forwardIdx[j]] = forwardedResults[j];
  }
  return allResults;
}

// ========================== HTTP relay mode ==========================

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !URL_RE.test(req.u)) {
    return _json({ e: "bad url" });
  }
  try {
    var opts = _buildOpts(req);
    var resp = _timedFetch(req.u, opts);

    // Raw-return mode for the exit-node outer hop — see Code.gs _doSingle
    // for the rationale. CodeFull.gs's HTTP relay path mirrors Code.gs's
    // wire contract, so the same flag needs the same handling here.
    if (req.raw === true) {
      return ContentService
        .createTextOutput(resp.getContentText())
        .setMimeType(ContentService.MimeType.JSON);
    }

    return _json({
      s: resp.getResponseCode(),
      h: _respHeaders(resp),
      b: Utilities.base64Encode(resp.getContent()),
    });
  } catch (err) {
    return _json({ e: "fetch failed: " + String(err) });
  }
}

function _doBatch(items) {
  var fetchArgs = [];
  var fetchIndex = [];
  var fetchMethods = [];
  var errorMap = {};
  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    if (!item || typeof item !== "object") {
      errorMap[i] = "bad item";
      continue;
    }
    if (!item.u || typeof item.u !== "string" || !URL_RE.test(item.u)) {
      errorMap[i] = "bad url";
      continue;
    }
    try {
      var opts = _buildOpts(item);
      opts.url = item.u;
      fetchArgs.push(opts);
      fetchIndex.push(i);
      fetchMethods.push(String(item.m || "GET").toUpperCase());
    } catch (buildErr) {
      errorMap[i] = String(buildErr);
    }
  }

  // Single-item batches use fetch() directly to avoid fetchAll overhead.
  // Multi-item batches use fetchAll(), which runs requests in parallel
  // inside Google. If fetchAll() throws as a whole (e.g. one URL violates
  // UrlFetchApp limits and poisons the whole batch), degrade to per-item
  // fetch so a single bad request does not zero out the entire batch's
  // responses. Mirrors upstream `masterking32/MasterHttpRelayVPN@3094288`.
  //
  // Single-item failures bypass the SAFE_REPLAY_METHODS dance: fetch()
  // is the first attempt, not a replay, so there is nothing safe to
  // re-run. We surface the underlying error string verbatim instead.
  var responses = [];
  if (fetchArgs.length > 0) {
    try {
      if (fetchArgs.length === 1) {
        var single = _unpackFetchArg(fetchArgs[0]);
        responses = [_timedFetch(single.url, single.opts)];
      } else {
        responses = _timedFetchAll(fetchArgs);
      }
    } catch (fetchErr) {
      responses = [];
      if (fetchArgs.length === 1) {
        errorMap[fetchIndex[0]] = "fetch failed: " + String(fetchErr);
        responses[0] = null;
      } else {
        for (var j = 0; j < fetchArgs.length; j++) {
          try {
            if (!SAFE_REPLAY_METHODS[fetchMethods[j]]) {
              errorMap[fetchIndex[j]] =
                "batch fetchAll failed; unsafe method not replayed";
              responses[j] = null;
              continue;
            }
            var fallback = _unpackFetchArg(fetchArgs[j]);
            responses[j] = _timedFetch(fallback.url, fallback.opts);
          } catch (singleErr) {
            errorMap[fetchIndex[j]] = String(singleErr);
            responses[j] = null;
          }
        }
      }
    }
  }

  var results = [];
  var rIdx = 0;
  for (var i = 0; i < items.length; i++) {
    if (Object.prototype.hasOwnProperty.call(errorMap, i)) {
      results.push({ e: errorMap[i] });
    } else {
      var resp = responses[rIdx++];
      if (!resp) {
        results.push({ e: "fetch failed" });
      } else {
        results.push({
          s: resp.getResponseCode(),
          h: _respHeaders(resp),
          b: Utilities.base64Encode(resp.getContent()),
        });
      }
    }
  }
  return _json({ q: results });
}

// ========================== Helpers ==========================

function _buildOpts(req) {
  var opts = {
    method: (req.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false,
  };
  if (req.h && typeof req.h === "object") {
    var headers = {};
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        headers[k] = req.h[k];
      }
    }
    opts.headers = headers;
  }
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

// Splits a fetchAll-shaped request object (opts + `url` key) into the
// `(url, opts)` pair that UrlFetchApp.fetch() expects. Used by both the
// single-item fast path and the per-item replay loop in _doBatch.
function _unpackFetchArg(arg) {
  var url = arg.url;
  var opts = {};
  for (var key in arg) {
    if (
      Object.prototype.hasOwnProperty.call(arg, key) &&
      key !== "url"
    ) {
      opts[key] = arg[key];
    }
  }
  return { url: url, opts: opts };
}

// Lazy module-level cache of the runtime feature check; reset between GAS
// executions but reused across all responses inside a single execution
// (batches of 50+ make this matter).
var _hasGetAllHeaders = null;

function _respHeaders(resp) {
  if (_hasGetAllHeaders === null) {
    _hasGetAllHeaders = (typeof resp.getAllHeaders === "function");
  }
  if (_hasGetAllHeaders) {
    try {
      return resp.getAllHeaders();
    } catch (err) {}
  }
  return resp.getHeaders();
}

// `doGet` is what active scanners hit first (HTTP GET probes are cheaper
// than POSTs). We use ContentService here so the response body is the
// raw HTML we wrote — `HtmlService.createHtmlOutput` would wrap it in
// a `goog.script.init` sandbox iframe, which the Rust client would then
// see if it ever GET-followed a redirect back onto /macros/.../exec
// (decoy/no-json error path). ContentService keeps the doGet response
// indistinguishable from a forgotten static-HTML web app.
//
// Authenticated branch: `/exec/quota?k=<AUTH_KEY>` returns the remaining
// `UrlFetchApp` daily quota as JSON.
//
// ⚠ SENSITIVE DIAGNOSTIC URL — the auth key is in the query string, so
// hitting this endpoint from a browser leaks the secret into history,
// server-side request logs, shared screenshots, and any URL copied to
// chat / a ticket. Prefer the POST equivalent (`{k, op: "quota"}`) for
// any non-throwaway use; this GET form is kept for ad-hoc curl from
// the operator's own machine where the URL exposure is acceptable.
//
// The auth guard matters — otherwise scanners could hit `/exec/quota`
// and trivially fingerprint any deployment as a rahgozar relay.
// `_isConfiguredAuthKey()` covers both the placeholder-still-set and
// blank-AUTH_KEY cases; see its docstring above. Wrong / missing key
// falls through to the same DECOY_HTML response. Feature #921.
function doGet(e) {
  if (
    e && e.pathInfo === "quota" &&
    e.parameter && e.parameter.k === AUTH_KEY &&
    _isConfiguredAuthKey()
  ) {
    return _json({ remaining: _remainingUrlFetchQuota() });
  }
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

function _remainingUrlFetchQuota() {
  try {
    if (typeof UrlFetchApp.getRemainingDailyQuota === "function") {
      return UrlFetchApp.getRemainingDailyQuota();
    }
  } catch (_) {}
  return null;
}

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}

// ========================== Edge DNS helpers ==========================

// Phase-1 helper: parses a udp_open op into the data needed for both the
// batched cache lookup and the eventual resolve. Returns {bytes, q, key}
// on success, or null for unparseable/refused ops so the caller can route
// them to the tunnel-node forward path.
//
// Long qnames that would exceed CacheService's 250-char key limit fall back
// to a SHA-256-hashed key under a separate `edns:h:` namespace. The
// 256-bit digest makes accidental collisions astronomically unlikely, and
// the distinct namespace prevents short-name keys from colliding with
// hashed long-name keys.
function _edgeDnsPrepare(op) {
  try {
    var bytes = Utilities.base64Decode(op.d);
    if (!bytes || bytes.length < 12) return null;
    var q = _dnsParseQuestion(bytes);
    if (!q) return null;
    if (EDGE_DNS_REFUSE_QTYPES[q.qtype]) return null;
    var key = EDGE_DNS_CACHE_PREFIX + q.qtype + ":" + q.qname;
    if (key.length > EDGE_DNS_MAX_KEY_LEN) {
      key = EDGE_DNS_CACHE_PREFIX + "h:" + q.qtype + ":" + _sha256Hex(q.qname);
    }
    return { bytes: bytes, q: q, key: key };
  } catch (_) {
    return null;
  }
}

// Phase-2 helper: given a prepared op and an optional pre-fetched cache
// value, returns a synthesized batch-result {sid, pkts, eof} on success,
// or null on any failure so the caller can forward to the tunnel-node.
//
// `cache`    is the CacheService handle reused across the batch (or null
//            if CacheService is unavailable, in which case DoH still runs
//            but no put).
// `localMap`  is an optional in-batch lookup table (typically the same
//             object returned by cache.getAll). When DoH succeeds, the
//             encoded reply is written back to localMap[prep.key] so that
//             a later candidate in the same batch with the same qname/qtype
//             hits without a second DoH round-trip.
// `dohBudget` is an optional mutable `{remaining:N}` guard. When present,
//             each DoH UrlFetchApp call decrements it; once it reaches
//             zero, misses return null and ride the tunnel-node batch.
function _edgeDnsResolve(prep, cachedReplyB64, cache, localMap, dohBudget) {
  try {
    if (cachedReplyB64) {
      try {
        var hit = Utilities.base64Decode(cachedReplyB64);
        if (hit && hit.length >= 12) {
          // Rewrite txid to match this query (RFC 1035 §4.1.1). Returns a
          // copy so the cached bytes themselves are never mutated.
          var rewritten = _dnsRewriteTxid(hit, prep.q.txid);
          return {
            sid: "edns-cache",
            pkts: [Utilities.base64Encode(rewritten)],
            eof: true,
          };
        }
      } catch (_) { /* corrupt cache entry — fall through to DoH */ }
    }

    for (var i = 0; i < EDGE_DNS_RESOLVERS.length; i++) {
      if (dohBudget && dohBudget.remaining <= 0) return null;
      if (dohBudget) dohBudget.remaining--;
      var reply = _edgeDnsDoh(EDGE_DNS_RESOLVERS[i], prep.bytes);
      if (!reply) continue;
      if (!_edgeDnsReplyMatchesPrep(prep, reply)) continue;

      var ttl = _edgeDnsReplyTtl(reply);

      // Encode once and reuse for both the persistent cache and the
      // in-batch dedup map. The reply bytes carry the resolver-echoed
      // txid; any future hit rewrites it to that request's txid.
      var encoded = (cache || localMap) ? Utilities.base64Encode(reply) : null;
      if (cache) {
        try {
          cache.put(prep.key, encoded, ttl);
        } catch (_) {
          // >100KB value or transient quota — still return the live answer.
        }
      }
      if (localMap) {
        localMap[prep.key] = encoded;
      }

      // The DoH reply already echoes our query's txid; rewrite defensively
      // in case a resolver mangles it.
      var fixed = _dnsRewriteTxid(reply, prep.q.txid);
      return {
        sid: "edns-doh",
        pkts: [Utilities.base64Encode(fixed)],
        eof: true,
      };
    }
    return null;
  } catch (err) {
    return null;
  }
}

// Computes the CacheService TTL for a DNS reply. Kept separate so DoH
// replies and tunnel-node-forwarded replies use identical cache semantics.
function _edgeDnsReplyTtl(reply) {
  var rcode = reply[3] & 0x0F;
  if (rcode === 2 || rcode === 3) {
    return EDGE_DNS_NEG_TTL_S;
  }

  var minTtl = _dnsMinTtl(reply);
  var ttl = (minTtl === null) ? EDGE_DNS_NEG_TTL_S : minTtl;
  if (ttl < EDGE_DNS_MIN_TTL_S) ttl = EDGE_DNS_MIN_TTL_S;
  if (ttl > EDGE_DNS_MAX_TTL_S) ttl = EDGE_DNS_MAX_TTL_S;
  return ttl;
}

// Caches DNS replies that came back from the tunnel-node forward path.
// This converts the unavoidable cold-miss tunnel fetch into a future
// zero-UrlFetchApp cache hit, without spending a separate DoH fetch.
// Pass-2 is already complete by the time this runs, so the in-batch
// dedup map is not threaded through — only the persistent CacheService
// put matters here.
function _edgeDnsCacheForwardedReplies(forwardPrep, forwardedResults, cache) {
  if (!cache) return;
  for (var i = 0; i < forwardPrep.length; i++) {
    if (!forwardPrep[i]) continue;
    var res = forwardedResults[i];
    if (!res || !res.pkts || !res.pkts.length) continue;
    _edgeDnsStoreReply(forwardPrep[i], res.pkts[0], cache);
  }
}

function _edgeDnsStoreReply(prep, replyB64, cache) {
  if (!cache) return false;
  try {
    var reply = Utilities.base64Decode(replyB64);
    if (!_edgeDnsReplyMatchesPrep(prep, reply)) return false;

    var ttl = _edgeDnsReplyTtl(reply);
    try {
      cache.put(prep.key, Utilities.base64Encode(reply), ttl);
    } catch (_) {
      // >100KB value or transient quota — the live reply already went out.
    }
    return true;
  } catch (_) {
    return false;
  }
}

function _edgeDnsReplyMatchesPrep(prep, reply) {
  if (!reply || reply.length < 12) return false;
  // Only cache actual DNS responses, and skip truncated UDP answers.
  if ((reply[2] & 0x80) === 0 || (reply[2] & 0x02) !== 0) return false;

  var q = _dnsParseQuestion(reply);
  return !!q && q.qname === prep.q.qname && q.qtype === prep.q.qtype;
}

// Hex-encodes the SHA-256 of a UTF-8 string. Used to keep long-qname cache
// keys under CacheService's 250-char limit. 64 hex chars is well below the
// cap and survives any future bumps to EDGE_DNS_MAX_KEY_LEN. SHA-256 over
// MD5 here is just future-proofing — the hash isn't security-sensitive
// (cache namespace only), but SHA-256 avoids any "why MD5?" discussion.
function _sha256Hex(s) {
  var d = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8);
  var hex = "";
  for (var i = 0; i < d.length; i++) {
    var b = d[i] & 0xFF;
    hex += (b < 16 ? "0" : "") + b.toString(16);
  }
  return hex;
}

// Single DoH GET against `url`. Returns the reply as a byte array, or null
// on any failure (HTTP non-200, network error, malformed body).
function _edgeDnsDoh(url, queryBytes) {
  try {
    var dns = Utilities.base64EncodeWebSafe(queryBytes).replace(/=+$/, "");
    var resp = _timedFetch(url + "?dns=" + dns, {
      method: "get",
      muteHttpExceptions: true,
      followRedirects: true,
      headers: { accept: "application/dns-message" },
    });
    if (resp.getResponseCode() !== 200) return null;
    var body = resp.getContent();
    if (!body || body.length < 12) return null;
    return body;
  } catch (err) {
    return null;
  }
}

// Returns { txid, qname, qtype } from a DNS wire-format query.
// qname is lowercased and dot-joined (no trailing dot). Null on malformed.
function _dnsParseQuestion(bytes) {
  if (bytes.length < 12) return null;
  var qdcount = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
  // RFC ambiguity: multi-question queries are essentially unused in
  // practice and would mis-key the cache (we'd cache a multi-answer reply
  // under only the first question). Bail and let the tunnel-node handle it.
  if (qdcount !== 1) return null;

  var off = 12;
  var labels = [];
  var nameLen = 0;
  while (off < bytes.length) {
    var len = bytes[off] & 0xFF;
    if (len === 0) { off++; break; }
    if ((len & 0xC0) !== 0) return null;   // questions don't use compression
    if (len > 63) return null;
    off++;
    if (off + len > bytes.length) return null;
    var label = "";
    for (var i = 0; i < len; i++) {
      var c = bytes[off + i] & 0xFF;
      if (c >= 0x41 && c <= 0x5A) c += 0x20;   // ASCII lowercase
      label += String.fromCharCode(c);
    }
    labels.push(label);
    off += len;
    nameLen += len + 1;
    if (nameLen > 255) return null;
  }
  if (off + 4 > bytes.length) return null;
  var qtype = ((bytes[off] & 0xFF) << 8) | (bytes[off + 1] & 0xFF);

  return {
    txid: ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF),
    qname: labels.join("."),
    qtype: qtype,
  };
}

// Walks the DNS reply's answer + authority sections and returns the min RR
// TTL, or null if there are no RRs (caller treats null as "use neg TTL").
// Returns null on any malformed input.
function _dnsMinTtl(bytes) {
  if (bytes.length < 12) return null;
  var qdcount = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
  var ancount = ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
  var nscount = ((bytes[8] & 0xFF) << 8) | (bytes[9] & 0xFF);

  var off = 12;
  for (var q = 0; q < qdcount; q++) {
    off = _dnsSkipName(bytes, off);
    if (off < 0 || off + 4 > bytes.length) return null;
    off += 4;
  }

  var min = null;
  var rrTotal = ancount + nscount;
  for (var r = 0; r < rrTotal; r++) {
    off = _dnsSkipName(bytes, off);
    if (off < 0 || off + 10 > bytes.length) return null;
    // 2B type, 2B class, 4B TTL, 2B rdlength
    var ttl = ((bytes[off + 4] & 0xFF) * 0x1000000)
            + (((bytes[off + 5] & 0xFF) << 16)
            |  ((bytes[off + 6] & 0xFF) << 8)
            |   (bytes[off + 7] & 0xFF));
    // RFC 2181: TTLs are 32-bit unsigned; values with the top bit set are
    // treated as 0. Multiplying the high byte (instead of <<24) avoids V8
    // sign-extension and keeps `ttl` in [0, 2^32).
    if (ttl < 0 || ttl > 0x7FFFFFFF) ttl = 0;
    if (min === null || ttl < min) min = ttl;
    var rdlen = ((bytes[off + 8] & 0xFF) << 8) | (bytes[off + 9] & 0xFF);
    off += 10 + rdlen;
    if (off > bytes.length) return null;
  }
  return min;
}

// Advances past a DNS name (sequence of labels or 16-bit pointer).
// Returns the new offset, or -1 on malformed input.
function _dnsSkipName(bytes, off) {
  while (off < bytes.length) {
    var len = bytes[off] & 0xFF;
    if (len === 0) return off + 1;
    if ((len & 0xC0) === 0xC0) {
      if (off + 2 > bytes.length) return -1;
      return off + 2;   // pointer terminates the name in-place
    }
    if ((len & 0xC0) !== 0) return -1;   // reserved label type
    if (len > 63) return -1;
    off += 1 + len;
  }
  return -1;
}

// Returns a copy of `bytes` with the first 2 bytes overwritten by the
// big-endian 16-bit transaction id. Coerces to signed-byte range so the
// result round-trips through Utilities.base64Encode regardless of whether
// the runtime exposes bytes as signed Java int8 or unsigned JS numbers.
//
// Always copies — the cache-safety invariant (callers can hand in a buffer
// they may reuse, e.g. a CacheService string round-tripped through decode)
// is enforced here rather than via per-call-site reasoning. The copy is
// cheap (~100 bytes for a typical DNS reply) compared to the surrounding
// base64 encode/decode work.
function _dnsRewriteTxid(bytes, txid) {
  var out = [];
  for (var i = 0; i < bytes.length; i++) out.push(bytes[i]);
  var hi = (txid >> 8) & 0xFF;
  var lo = txid & 0xFF;
  out[0] = hi > 127 ? hi - 256 : hi;
  out[1] = lo > 127 ? lo - 256 : lo;
  return out;
}
