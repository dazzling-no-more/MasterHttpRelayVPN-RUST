# Multi-edge fronting groups

The default rahgozar SNI-rewrite path targets Google's edge: TLS goes out
with `SNI=www.google.com` to a Google IP, the inner `Host` header (after
the local MITM CA terminates the browser's TLS) names the real
destination, and Google's frontend routes by `Host`. That's how
`www.youtube.com`, `script.google.com`, and friends reach you despite a
DPI box that drops anything not SNI'd as `www.google.com`.

The same trick works on any multi-tenant CDN edge that:

1. serves multiple tenant domains on the same IP pool, and
2. dispatches to the right backend by inner HTTP `Host`, and
3. presents a TLS cert whose name matches the SNI you choose.

Vercel, Fastly, and AWS CloudFront (which is what Netlify-hosted sites
sit behind) all fit the bill. Pick a benign-looking domain hosted on
the same edge, use it as the SNI, and you can route many other domains
on that edge through the same tunnel without burning Apps Script quota.

## Config shape

```jsonc
{
  "mode": "direct",                         // or apps_script / full
  "fronting_groups": [
    {
      "name":    "vercel",                  // free-form, used in logs
      "ip":      "76.76.21.21",             // a Vercel edge IP
      "sni":     "react.dev",               // a Vercel-hosted domain
      "domains": [                          // hosts to route via this group
        "vercel.com", "vercel.app",
        "nextjs.org", "now.sh"
      ]
    }
  ]
}
```

`domains` matches case-insensitively, exact OR dot-anchored suffix —
`vercel.com` covers both `vercel.com` and `*.vercel.com`. First group
in the list whose member matches wins.

A working example is shipped at `config.fronting-groups.example.json`. It
mirrors the same coverage as the curated bundle below.

## Curated bundle (no-typing path)

The binary ships [`assets/fronting-groups/curated.json`](../assets/fronting-groups/curated.json)
with eleven groups derived from the
[`patterniha/MITM-DomainFronting`](https://github.com/patterniha/MITM-DomainFronting)
Xray config — the same set of (sni, edge IP, member-domain) tuples that
project's author has tested in the field:

| Group | SNI | Covers |
| --- | --- | --- |
| `github-central` | `collector.github.com` | `objects-origin.githubusercontent.com`, `api.githubcopilot.com`, `central.github.com`, `collector.github.com`, … |
| `github-alive` | `alive.github.com` | `alive.github.com`, `live.github.com` |
| `github-uploads` | `uploads.github.com` | `uploads.github.com`, `alambic-origin.githubusercontent.com`, `camo-origin.githubusercontent.com` |
| `github` | `www.github.com` | bare `github.com` — under the suffix matcher this is the **entire `*.github.com` zone** minus what the earlier `github-*` groups peel off (gist, www, and any unknown subdomain like `api.github.com`) |
| `vercel` | `nextjs.org` | `vercel.com`, `vercel.app`, `nextjs.org`, `cursor.com`, `zeit.co`, … (29 domains) |
| `fastly` | `pypi.org` | `reddit.com`, `cnn.com`, `pinterest.com`, `buzzfeed.com`, `githubusercontent.com`, `pypi.org`, … (40 domains) |
| `amazon-cloudfront` | `kubernetes.io` | `netlify.app`, `netlify.com` |
| `pubmed` | `pubmed.ncbi.nlm.nih.gov` | `pmc.ncbi.nlm.nih.gov` |
| `youtube-web` ⚡ | `www.google.com` (camouflage) | `youtube.com`, `youtu.be`, `youtube-nocookie.com`, `ytimg.com`, `youtubei.googleapis.com` — the YouTube web app + feed API + thumbnails |
| `google-video` ⚡ | `www.google.com` (camouflage) | `googlevideo.com` — YouTube's video CDN (the EVA edge) |
| `meta` ⚡ | `www.microsoft.com` (camouflage) | `instagram.com`, `cdninstagram.com`, `whatsapp.com`/`.net`, `facebook.com`/`.net`, `fbcdn.net`, `threads.net`, `messenger.com` |

⚡ = **camouflage mode** (`force_ip: true`). These edges have no shared
front IP you can pin, so they use a different mechanism — see
[Camouflage mode](#camouflage-mode-force_ip--for-edges-with-no-shared-front)
below.

Ordering is load-bearing. `match_fronting_group` is single-shot
first-match-wins with **dot-anchored suffix** matching — an entry
`github.com` catches every `*.github.com` host too. So the bundle
threads the needle by ordering the github-* groups from most-specific
to least-specific:

1. `github-central`, `github-alive`, `github-uploads` claim their
   explicit subdomains first.
2. `github` (with bare `github.com` in its `domains`) catches
   everything else under the zone.
3. `fastly` runs last, so its broader `githubusercontent.com` suffix
   can't eat `*-origin.githubusercontent.com` from earlier
   github-content routes.

Pinned by [`curated_groups::tests::curated_first_match_winners`](../src/curated_groups.rs) — a routing-winner test
that exercises the real matcher (rather than just checking domains
appear somewhere in the JSON) so future edits can't silently shadow
a group by reordering or expanding suffixes.

**Desktop UI** — open the *Advanced* section and click **Load curated
fronting groups**. The button appends groups whose `name` isn't already
in your config; hand-edited entries are never overwritten. Then press
**Save config** to persist.

**Android UI** — same flow under *Advanced*, **Load curated fronting
groups**. (Android did not round-trip the `fronting_groups` field at all
before this — earlier Android builds silently dropped the field on
Save. If you previously hand-edited groups into `config.json` on a
phone, re-add them or load the curated bundle.)

**CLI / config-file users** — copy `config.fronting-groups.example.json`
into place, or splice the `fronting_groups` array from
`assets/fronting-groups/curated.json` into your existing `config.json`.

## Camouflage mode (`force_ip`) — for edges with no shared front

The pinned-`ip` model above only works on edges that let you front
*other* tenants through one shared IP (Vercel, Fastly, CloudFront).
Several high-value targets don't:

- **YouTube** — both the video CDN (`googlevideo.com`, on Google's
  separate "EVA" edge) and the web app / feed API (`youtube.com`,
  `youtubei.googleapis.com`, `ytimg.com`). Pinning a GFE IP and sending
  `Host: …googlevideo.com` returns a wrong-cert / wrong-edge error — this
  is exactly why `googlevideo.com` was pulled from the built-in
  SNI-rewrite list in v1.7.6. The web app additionally needs HTTP/2 (see
  below), which the pinned/SNI-rewrite paths can't provide.
- **Meta** (Instagram / WhatsApp / Facebook) has no neutral shared front
  you can pin either.

patterniha's Xray config (v22) handles these with `domainStrategy:
ForceIP` + `verifyPeerCertByName`. rahgozar ports that as **camouflage
mode**:

```jsonc
{
  "name": "meta",
  "sni": "www.microsoft.com",   // FAKE — only to blind the on-path DPI
  "domains": ["instagram.com", "whatsapp.com", "facebook.com", "..."],
  "force_ip": true,             // <-- the switch
  "verify_names": ["www.microsoft.com"]  // extra accepted cert name(s) —
                                // the real host is ALWAYS accepted too;
                                // pin the decoy SNI's name here (see #3)
}
```

What changes when `force_ip: true`:

1. **Dial the destination's own IP.** Instead of a pinned `ip`, the
   proxy resolves the real host's IP per-connection. Because Iran
   DNS-poisons exactly these hosts, resolution goes through a built-in
   **DoH client** (Cloudflare `1.1.1.1`) whose *own* TLS handshake is
   itself camouflaged (SNI `www.microsoft.com`), so the lookups can't be
   SNI-blocked. `ip` is ignored (leave it out).
2. **Send a fake SNI.** The `sni` (`www.microsoft.com`,
   `www.google.com`) is put on the wire purely so the DPI box sees a
   benign, allow-listed name and lets the handshake through.
3. **Verify the cert.** The cert the real edge returns is validated —
   always against the actual destination host, **plus** any names pinned
   in `verify_names` (patterniha's `verifyPeerCertByName`). The pinned
   names matter because some edges answer with a cert matching the *SNI
   you sent* rather than the inner Host — Google's GFE returns a
   `www.google.com` cert for a `www.google.com`-SNI handshake — so the
   curated `youtube-web` / `google-video` groups pin `www.google.com` and
   `meta` pins `www.microsoft.com`. Either way it's full webpki chain
   validation against a name owned by the legitimate destination (or the
   decoy provider); a wrong/poisoned IP can't present any valid public
   cert, so it **fails closed** rather than splicing you into a hostile
   peer. The fake SNI never weakens this: the certificate, not the SNI,
   is the trust anchor.

> **Security review note (maintainers):** camouflage mode is the only
> fronting path that verifies the cert against a name *other* than the
> SNI on the wire (see `src/camouflage.rs::CamouflageVerifier` and
> `src/doh.rs`). The reasoning is sound — verification is full webpki
> chain validation against the real host — but because users at risk
> rely on it, **field-test against the live censor and review the
> verifier before shipping in a release.** Camouflage groups only
> activate when at least one `force_ip` group is present (the DoH
> resolver is built lazily); existing pinned groups are unaffected.

**HTTP/2 across the splice.** Camouflage dials the upstream offering
`h2` + `http/1.1`, sees which the real edge picked, and then presents the
browser *exactly that* protocol — so the raw byte-splice stays
protocol-coherent end to end. This is why `youtube-web` is a camouflage
group rather than a pinned/SNI-rewrite route: YouTube's web app (the feed
/ infinite scroll) is built for HTTP/2 multiplexing and stalls — "spins,
nothing loads" — when forced through the relay/SNI-rewrite path, which is
locked to HTTP/1.1 because those paths parse HTTP. The pinned and
built-in Google paths remain http/1.1-only.

When camouflage mode helps and when it doesn't: it defeats **SNI-based**
blocking only. If an ISP IP-blocks the destination outright, neither
camouflage nor TLS-fragmentation reaches it — the Apps Script relay
(`mode = apps_script`) remains the fallback. For YouTube specifically,
`mode = local_bypass` is the other serverless option (it fragments the
real ClientHello instead of camouflaging the SNI).

## Picking the (ip, sni) pair

The SNI must be a real, currently-live domain on the same edge. rustls
validates the upstream cert against the SNI you send; if the edge
returns a cert that doesn't cover that name, the handshake fails. So
the recipe is:

1. Pick the target edge (Vercel, Fastly, …).
2. Find a neutral, never-blocked domain hosted there. Vercel: `react.dev`,
   `nextjs.org`. Fastly: `www.python.org`, `pypi.org`. AWS CloudFront
   (where Netlify lives): `letsencrypt.org`, `aws.amazon.com`.
3. Resolve that domain (`dig +short react.dev A`) — pick one IP, drop
   it in `ip`.
4. List the domains you actually want to reach via this edge in
   `domains` — **only domains you've verified are hosted on the same
   edge as `sni`** (see warning below).

Edge IPs rotate. If a group's `ip` stops working, re-resolve the SNI
domain and update the config — IP rotation per-group is on the
roadmap but not implemented yet.

## ⚠️ Cross-tenant leak: don't list domains that aren't on the edge

If you put a domain in `domains` that is **not** actually hosted on the
edge you've configured, two things happen, both bad:

1. **Privacy leak.** The proxy completes a TLS handshake with the edge
   (validated against `sni`, which IS on the edge), then sends `Host:
   <your-domain>` inside that encrypted stream. The edge — which is
   not your-domain's host — now sees a request labelled with
   your-domain's name. From the edge's perspective, *you* deliberately
   sent that request to them. Vercel/Fastly logs will show your-domain
   in their access logs, attributable to your IP and timestamps.

2. **UX failure.** The edge has no backend for your-domain, so it
   returns its default 404 / wrong-tenant page. The site appears
   "broken via rahgozar" but works fine over a normal connection,
   which is confusing to debug.

**Verify before listing.** A simple check: if `dig +short your-domain
A` returns an IP that's *also* one of the edge's IPs, you're fine. If
the IPs differ, your-domain is hosted somewhere else and listing it
will leak. This is also why the upstream MITM-DomainFronting Xray
config uses `verifyPeerCertByName` with an explicit SAN allowlist —
it's a second guard against accidentally fronting unrelated domains
through the same edge. rahgozar leaves verification to rustls + the
SNI you send; the leak guard is "you, the operator, listing only
domains you've verified."

Only listed domains are routed to the group. Anything else falls
through to the next dispatch step (Google SNI-rewrite or Apps Script
relay), so unrelated traffic does NOT accidentally hit a group's edge.

## Routing precedence

Within a single CONNECT, the dispatch order is:

1. `passthrough_hosts` — explicit user opt-out.
2. DoH bypass (port 443, known DoH host).
3. `mode = full` — everything via the batch tunnel mux.
4. **`fronting_groups` match (port 443).** — this feature.
5. TLS-fragmentation Direct Mode for Google-owned domains (port 443,
   `direct_mode.enabled = true`, host in `direct_mode.google_domains`).
   Falls back to the SNI-rewrite path below on dial failure.
6. Sanctioned-domain override (only in `mode = apps_script`): Gemini /
   AI Studio / Bard / Labs skip SNI-rewrite so they reach the relay
   instead (Google geo-blocks Iranian IPs).
7. Built-in Google SNI-rewrite suffix list (port 443).
8. `mode = direct` fallback → raw TCP.
9. `mode = apps_script` peek + relay.

So fronting groups beat the Google-edge default for hosts they list,
but lose to user-explicit passthrough/DoH choices. Putting `vercel.com`
in a Vercel fronting group will route Vercel traffic through Vercel's
edge directly, not through the Apps Script relay or the Google edge.

## Limitations / what's not here yet

- **Single IP per group.** Real edges have many; we'll add a pool with
  health-checking when there's a clear need. Workaround: when the
  configured IP starts failing, swap it.
- **No bundled domain catalog.** The upstream Xray config uses
  `geosite:vercel` / `geosite:fastly` lists from a binary geosite
  database — we don't ship that, you list domains explicitly.
- **No UI editor.** Edit `config.json` directly. The UI's Save path
  preserves your `fronting_groups` block (round-tripped) — it just
  doesn't render an editor for it.
- **Browsers only for Android non-root**, same as the Google path —
  third-party apps that don't trust user CAs (Telegram, Instagram, …)
  can't be MITM'd, so this trick doesn't help them.
- **Cert verification: pinned groups match the SNI; camouflage groups
  match the real host.** For pinned (`force_ip: false`) groups the SNI
  you send IS what rustls validates against, so pick an SNI whose cert
  genuinely covers your targets. For camouflage (`force_ip: true`)
  groups the SNI is fake and the cert is validated against the real
  destination host (or an explicit `verify_names` allow-list —
  patterniha's `verifyPeerCertByName`). Note `verify_ssl: false` only
  affects the pinned/built-in shared connector — camouflage groups build
  their own verifier and **always** validate the real-host cert chain
  regardless of that flag (a wrong/poisoned IP can't present a valid cert
  for the real host, so it fails closed). Don't reach for `verify_ssl:
  false` regardless; it disables verification on the pinned + Google
  paths.

## Credit

The technique is the same one [@masterking32]'s original
MasterHttpRelayVPN demonstrated for Google's edge. The Vercel +
Fastly extension and the matching Xray config came from
[@patterniha]'s [MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting)
project — this `fronting_groups` field is a Rust port of that idea
into rahgozar's existing dispatcher.
