# rahgozar — bypass censorship for free, with your own Google account

[![Latest release](https://img.shields.io/github/v/release/dazzling-no-more/rahgozar?display_name=tag&logo=github&label=release&color=blue&cacheSeconds=300)](https://github.com/dazzling-no-more/rahgozar/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/dazzling-no-more/rahgozar/total.svg?label=downloads&logo=github&cacheSeconds=300)](https://github.com/dazzling-no-more/rahgozar/releases)
[![CI](https://github.com/dazzling-no-more/rahgozar/actions/workflows/release.yml/badge.svg)](https://github.com/dazzling-no-more/rahgozar/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/github/license/dazzling-no-more/rahgozar?color=blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/dazzling-no-more/rahgozar?style=flat&logo=github)](https://github.com/dazzling-no-more/rahgozar/stargazers)

> ## About this fork
>
> **rahgozar** (Persian for *passerby* / *traveler*, رهگذر) is a community-maintained continuation of [therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST) — the original `mhrv-rs` Apps-Script-relay VPN that's a lifeline for users behind heavy censorship.
>
> Upstream went quiet with a queue of unmerged fixes and features piling up. This fork brings that queued work into a usable, releasable state so users have somewhere to get current builds. It's **fully separate** from upstream: different repo, different Android applicationId (`com.dazzlingnomore.mhrv`), different version line (starting at v2.0.0 to avoid colliding with upstream's historical v1.x tags). You can install both side-by-side.
>
> **If the upstream maintainer returns,** this fork will gladly hand work back, fold improvements upstream, or wind down. No hard feelings — just keeping the project usable in the meantime. See the [original repo](https://github.com/therealaleph/MasterHttpRelayVPN-RUST) for the project's roots.
>
> **What's in v2.0.0 that's not in upstream v1.9.25** (all from queued upstream PRs):
> - Apps Script edge-DNS batching + cache `getAll` perf wins
> - YouTube `relay_url_patterns` + SABR strip + exit-node-full SNI
> - Bundled curated CDN fronting groups (Vercel, Fastly, AWS CloudFront, GitHub) with one-tap loader
> - Multi-profile config storage (desktop + Android)
> - Use as upstream proxy for Psiphon / xray (Direct mode)
> - In-app auto-updater

**A small program that runs on your computer and lets you visit blocked websites for free, using a Google Apps Script you deploy in your own free Google account. Your ISP only sees encrypted traffic to `www.google.com` — it can't tell what you're really visiting.**

🇬🇧 [English Quick Start](#quick-start) · [Full Guide (advanced topics)](docs/guide.md)
🇮🇷 [راه‌اندازی سریع فارسی](#راه‌اندازی-سریع) · [راهنمای کامل (مباحث پیشرفته)](docs/guide.fa.md)

<p align="center" dir="rtl">
  ۱. <a href="https://www.youtube.com/watch?v=voCwxgvWR5U" target="_blank" rel="noopener noreferrer">راهنمای تصویری راه اندازی به زبان فارسی</a> (YouTube)
  <br>
  ۲. <a href="https://kian-irani.github.io/mhrv-setup-full-tunell/" target="_blank" rel="noopener noreferrer">راهنمای جامع متنی راه اندازی به زبان فارسی</a> با تشکر از <a href="https://github.com/KIAN-IRANi" target="_blank" rel="noopener noreferrer">Kian Irani</a>
</p>

---

## What you get

- 🌐 **Bypasses DPI / SNI blocking** by using Google's edge as a relay
- 💯 **Completely free** — runs on your own Google account's free tier
- ⚡ **One small file** (~3 MB), no Python, no Node.js, no dependencies
- 🖥️ **Works on** Mac, Windows, Linux, Android, OpenWRT routers
- 🦊 **Any browser or app** that supports HTTP proxy or SOCKS5

## How it works (the simple picture)

```
   you  →  browser  →  mhrv-rs  ──┐
                                  │ ISP only sees:  www.google.com
                                  ▼
                          Google's network
                                  │
                                  ▼
              your free Apps Script  fetches  the real site
                                  │
                                  ▼
                Twitter / ChatGPT / blocked-site of your choice
```

ISPs can't read inside encrypted HTTPS. They only see the address — `www.google.com`. The actual page lookup happens inside Google's network, hidden in the encrypted tunnel.

## Quick Start

**About 5 minutes.** You need:

- A free Google account (any Gmail works)
- A computer (Mac, Windows, or Linux)
- Firefox or Chrome

### Step 1 — Make the Google Apps Script (one-time)

1. Go to **[script.google.com](https://script.google.com)**, sign in with your Google account
2. Click **New project** at the top left
3. Delete the default code in the editor
4. Open the file [`assets/apps_script/Code.gs`](assets/apps_script/Code.gs) in this repo, copy all of it, paste into the Apps Script editor (replacing what was there)
5. Find this line near the top:
   ```js
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   ```
   Change `CHANGE_ME_TO_A_STRONG_SECRET` to a long random string of your own. **Keep this string** — you'll paste it into the app in Step 3. Treat it like a password.
6. Click 💾 **Save** (or `Ctrl/Cmd+S`)
7. Click **Deploy** (top right) → **New deployment**
8. Click the gear icon ⚙ next to "Select type" → choose **Web app**
9. Set:
   - **Execute as:** *Me* (your Google account)
   - **Who has access:** *Anyone*
10. Click **Deploy**. Google may ask for permissions — click **Authorize access** and approve
11. Google shows a **Deployment ID** (a long random string). **Copy it** — you'll need it in Step 3.

> **Tip:** if you ever update `Code.gs` later, don't make a new deployment. Edit the code, then go to **Deploy → Manage deployments → ✏️ → Version: New version → Deploy**. The Deployment ID stays the same.

### Step 2 — Download mhrv-rs

Go to the [latest release page](https://github.com/dazzling-no-more/rahgozar/releases/latest) and download the file for your computer:

| You're on | Download this |
|---|---|
| Mac with Apple Silicon (M1 / M2 / M3 / M4 chip) | `mhrv-rs-macos-arm64-app.zip` |
| Mac with Intel chip | `mhrv-rs-macos-amd64-app.zip` |
| Windows | `mhrv-rs-windows-amd64.zip` |
| Linux (Ubuntu / Mint / Fedora / Debian / Arch) | `mhrv-rs-linux-amd64.tar.gz` |
| Android phone or tablet | `mhrv-rs-android-universal-v*.apk` |
| OpenWRT router or Alpine | `mhrv-rs-linux-musl-amd64.tar.gz` |

> **Mac: not sure if Apple Silicon or Intel?** Click  → **About This Mac**. If "Chip" says **Apple**, get arm64. If **Intel**, get amd64.

> **Linux: getting a `GLIBC` error?** Use the `linux-musl-amd64` file instead — it works on any Linux without dependencies.

Unzip it.

### Step 3 — First run

Double-click the launcher:

| Mac | `run.command` |
| Windows | `run.bat` |
| Linux | `./run.sh` (in a terminal) |

The first time, it asks for your computer password. This is to install one small certificate so your browser trusts mhrv-rs. **The certificate is generated on your computer and never leaves it** — no cloud, no Google, nothing remote can use it.

The mhrv-rs window opens. Fill in:

- **Apps Script ID(s)** → paste the **Deployment ID** from Step 1
- **Auth key** → paste the random string you put in `Code.gs`
- Leave everything else at the defaults

Click **Save config**, then **Start**. The status circle goes green if it works.

> **Test it:** click the **Test** button. It sends one request through the relay and tells you if it worked.

### Step 4 — Tell your browser to use mhrv-rs

#### Firefox (recommended — easiest)

1. Firefox → ☰ menu → **Settings**
2. Search "proxy" in the search box
3. Click **Settings…** under Network Settings
4. Choose **Manual proxy configuration**
5. **HTTP Proxy:** `127.0.0.1` Port: `8085`
6. ☑ Check **"Also use this proxy for HTTPS"**
7. Click **OK**

#### Chrome / Edge

Install the [Proxy SwitchyOmega](https://chromewebstore.google.com/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif) extension and set proxy to `127.0.0.1:8085`.

#### macOS (whole system)

System Settings → Network → Wi-Fi → Details → **Proxies** → enable both **Web Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**, both pointing to `127.0.0.1:8085`.

### Step 5 — Try it

Open any blocked site in your browser. It should load.

If something doesn't work:

- Click **Test** in the mhrv-rs window — it pinpoints which step is failing
- Look at the **Recent log** panel at the bottom of the window
- See [Common questions](#common-questions) below

---

## Common questions

**Is this really free?** Yes. Google gives every account 20,000 outbound URL fetches per day on the free tier. That's plenty for one person's normal browsing. For a family of 3–4 sharing the same setup, make 2–3 deployments in different Google accounts and add all the IDs.

**Is it safe?** The certificate stays on your computer — no one else has the private key. Your `auth_key` is your secret. Google sees the websites you visit through the relay (because Apps Script fetches them on your behalf) — same as any hosted proxy. If you're not OK with that, use Full Tunnel mode with your own VPS — see the [full guide](docs/guide.md#full-tunnel-mode).

**YouTube videos don't play.** YouTube's video chunks come from `googlevideo.com`, which Apps Script can't reach (Google blocks Apps Script from accessing Google's own video CDN). The page itself loads fine; only video playback is affected. Fix: Full Tunnel + VPS, or add `.googlevideo.com` to `passthrough_hosts` in your config (browser hits it directly, but on Iran ISPs it's still throttled).

**ChatGPT / Claude / Grok shows a Cloudflare CAPTCHA.** Cloudflare flags Google datacenter IPs as bots. Fix: set up an **exit node** — a small TypeScript handler you deploy on a serverless host (Deno Deploy, fly.io, your own VPS) that bridges Apps Script → your exit node → claude.ai. See [`assets/exit_node/README.md`](assets/exit_node/README.md).

**Telegram is unstable.** Telegram uses MTProto, which Apps Script doesn't speak. Pair with [xray](https://github.com/XTLS/Xray-core) on your machine — see [Telegram via xray in the full guide](docs/guide.md#telegram-via-xray).

**ISP blocks `script.google.com` itself.** mhrv-rs has a `direct` mode that uses only the SNI-rewrite tunnel (no Apps Script). Use it once to access `script.google.com` to deploy your script, then switch to apps_script mode. See [direct mode](docs/guide.md#direct-mode).

**I want to use mhrv-rs as Psiphon's (or xray's) upstream proxy.** Run mhrv-rs in `direct` mode and point Psiphon's *upstream proxy* setting at the host:port shown under the Connect button. Unfronted hosts pass through as raw TCP, so Psiphon's bootstrap traffic reaches Psiphon's servers untouched. See [docs/use-as-upstream.md](docs/use-as-upstream.md).

**My Google search shows up without JavaScript.** The Apps Script `User-Agent` is fixed to `Google-Apps-Script` (Google won't let scripts change it), so some sites serve a no-JS fallback. Workaround: add the affected domain to your `hosts` map so it goes through the SNI-rewrite tunnel with your real browser User-Agent. `google.com`, `youtube.com`, `fonts.googleapis.com` are already on this list by default.

**More questions:** [full FAQ in the long guide](docs/guide.md#faq).

## Need help?

- Search [open and closed issues on rahgozar](https://github.com/dazzling-no-more/rahgozar/issues?q=is%3Aissue) — and the larger [upstream archive on therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues?q=is%3Aissue) where most of the project's history lives — your problem might already be answered
- Open a [new issue on rahgozar](https://github.com/dazzling-no-more/rahgozar/issues/new) with: your config (mask `auth_key`!), exactly what you tried, exactly what you saw in the log

## Credits

This fork stands on three upstream projects you should know about and support before considering anything for the fork:

- **[@masterking32/MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN)** — the original Python project where it all started. The Apps Script relay protocol, the proxy architecture, the idea of turning your own free Google account into a relay — all his. Without this, none of the rest exists.
- **[@therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST)** — the Rust port (`mhrv-rs`) this fork continues. therealaleph rewrote the Python project in Rust to ship single-binary clients, built the desktop + Android UIs, and ran the project through the entire v1.x → v1.9.25 era. Almost every line of code in this fork is his work; we just kept the lights on while upstream went quiet.
- **[@patterniha/MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting)** — the CDN fronting-groups concept (routing specific domains through Vercel / Fastly / CloudFront edges via SNI) that became the curated fronting bundle shipped here. Independent project; the Xray config there inspired our integration. See [`docs/fronting-groups.md`](docs/fronting-groups.md) for the lineage.

Most of the Rust code in this port (including this fork's merge and rebrand work) was written with [Anthropic's Claude](https://claude.com), reviewed by a human on every commit.

## Support these projects

**If you've benefited from this software, send your support upstream — not to this fork.** rahgozar takes no donations and exists only to keep users covered while upstream is inactive. The substantive engineering happened in the three projects above; please support them directly:

- **[@masterking32](https://github.com/masterking32)** — author of the original Python project. Sponsor on GitHub or via any method listed on his profile / repo.
- **[@therealaleph](https://github.com/therealaleph)** — Rust port author. Donate at **[sh1n.org/donate](https://sh1n.org/donate)** (covers hosting / CI / years of maintenance).
- **[@patterniha](https://github.com/patterniha)** — MITM-DomainFronting author. Sponsor on GitHub or via methods listed in his repo.

Starring those three upstream repos also signals their work is worth keeping alive. If upstream `mhrv-rs` resumes, this fork will fold work back and wind down — the goal here is continuity of access for users behind heavy censorship, nothing more.

---

<div dir="rtl">

# mhrv-rs — دور زدن سانسور به‌رایگان، با حساب گوگل خودت

**یک برنامهٔ کوچک که روی کامپیوترت اجرا می‌شود و کمک می‌کند سایت‌های مسدودشده را با یک اسکریپت رایگان که توی حساب گوگل خودت می‌سازی، باز کنی. ISP فقط می‌بیند که داری به `www.google.com` وصل می‌شوی — نمی‌فهمد در واقع چه سایتی را باز کرده‌ای.**

🇬🇧 [English Quick Start](#quick-start) · [Full Guide (advanced)](docs/guide.md)
🇮🇷 [راه‌اندازی سریع](#راه‌اندازی-سریع) · [راهنمای کامل (پیشرفته)](docs/guide.fa.md)

## چی به دست می‌آوری

- 🌐 **عبور از DPI / مسدودسازی SNI** با لبهٔ گوگل به‌عنوان رله
- 💯 **کاملاً رایگان** — روی سهمیهٔ رایگان حساب گوگل خودت
- ⚡ **یک فایل کوچک** (~۳ مگابایت)، بدون پایتون، بدون Node.js، بدون وابستگی
- 🖥️ **روی** مک، ویندوز، لینوکس، اندروید، روتر OpenWRT کار می‌کند
- 🦊 **هر مرورگر یا برنامه‌ای** که از HTTP proxy یا SOCKS5 پشتیبانی کند

## چطور کار می‌کند (تصویر ساده)

```
  تو  ←  مرورگر  ←  mhrv-rs  ──┐
                                │ ISP فقط می‌بیند:  www.google.com
                                ▼
                         شبکهٔ گوگل
                                │
                                ▼
            اسکریپت رایگان گوگل تو  سایت اصلی را  باز می‌کند
                                │
                                ▼
              توییتر / ChatGPT / هر سایت مسدودی
```

ISP داخل HTTPS رمزشده را نمی‌تواند بخواند. فقط آدرس را می‌بیند — `www.google.com`. جست‌وجوی واقعی صفحه داخل شبکهٔ گوگل، در تونل رمزشده اتفاق می‌افتد.

## راه‌اندازی سریع

**حدود ۵ دقیقه.** نیاز داری به:

- یک حساب گوگل رایگان (هر Gmail‌ای کار می‌کند)
- یک کامپیوتر (مک، ویندوز یا لینوکس)
- فایرفاکس یا کروم

### مرحلهٔ ۱ — ساخت اسکریپت گوگل (یک‌بار)

۱. به **[script.google.com](https://script.google.com)** برو، با حساب گوگل خودت وارد شو
۲. روی **New project** بالا سمت چپ کلیک کن
۳. کد پیش‌فرض ویرایشگر را پاک کن
۴. فایل [`assets/apps_script/Code.gs`](assets/apps_script/Code.gs) را در همین ریپو باز کن، همه‌اش را کپی کن، در ویرایشگر Apps Script پیست کن (جایگزین متن قبلی)
۵. این خط را نزدیک بالای کد پیدا کن:
   ```js
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   ```
   مقدار `CHANGE_ME_TO_A_STRONG_SECRET` را با یک رشتهٔ تصادفی طولانیِ خودت عوض کن. **این رشته را نگه دار** — در مرحلهٔ ۳ داخل برنامه پیست می‌کنی. مثل پسورد محرمانه نگه‌اش دار.
۶. روی 💾 **Save** کلیک کن (یا `Ctrl/Cmd+S`)
۷. روی **Deploy** (بالا سمت راست) → **New deployment**
۸. روی آیکون چرخ‌دندهٔ ⚙ کنار "Select type" کلیک کن → **Web app** را انتخاب کن
۹. تنظیم کن:
   - **Execute as:** *Me* (حساب گوگل خودت)
   - **Who has access:** *Anyone*
۱۰. **Deploy** را بزن. ممکن است گوگل برای دادن دسترسی سؤال کند — **Authorize access** را بزن و تأیید کن
۱۱. گوگل یک **Deployment ID** نشانت می‌دهد (یک رشتهٔ تصادفی طولانی). **کپی‌اش کن** — در مرحلهٔ ۳ لازم داری.

> **نکته:** اگر بعداً `Code.gs` را به‌روزرسانی کنی، Deployment جدید نساز. کد را ویرایش کن، بعد **Deploy → Manage deployments → ✏️ → Version: New version → Deploy**. Deployment ID همان قبلی می‌ماند.

### مرحلهٔ ۲ — دانلود mhrv-rs

به [صفحهٔ آخرین release](https://github.com/dazzling-no-more/rahgozar/releases/latest) برو و فایل مناسب کامپیوترت را دانلود کن:

| سیستم تو | فایل دانلود |
|---|---|
| مک با تراشهٔ Apple Silicon (M1 / M2 / M3 / M4) | `mhrv-rs-macos-arm64-app.zip` |
| مک با تراشهٔ Intel | `mhrv-rs-macos-amd64-app.zip` |
| ویندوز | `mhrv-rs-windows-amd64.zip` |
| لینوکس (Ubuntu / Mint / Fedora / Debian / Arch) | `mhrv-rs-linux-amd64.tar.gz` |
| گوشی یا تبلت اندروید | `mhrv-rs-android-universal-v*.apk` |
| روتر OpenWRT یا Alpine | `mhrv-rs-linux-musl-amd64.tar.gz` |

> **مک: مطمئن نیستی Apple Silicon است یا Intel؟** کلیک کن  → **About This Mac**. اگر "Chip" نوشت **Apple**، arm64 بگیر. اگر **Intel** بود، amd64.

> **لینوکس: خطای `GLIBC` می‌گیری؟** به‌جای آن از `linux-musl-amd64` استفاده کن — روی هر لینوکسی بدون وابستگی کار می‌کند.

از حالت فشرده دربیار.

### مرحلهٔ ۳ — اجرای اول

روی فایل اجرا دو بار کلیک کن:

| مک | `run.command` |
| ویندوز | `run.bat` |
| لینوکس | `./run.sh` (در ترمینال) |

اولین بار رمز کامپیوترت را می‌خواهد. این برای نصب یک گواهی کوچک است تا مرورگرت به mhrv-rs اعتماد کند. **گواهی روی کامپیوتر خودت ساخته می‌شود و هیچ‌وقت جایی ارسال نمی‌شود** — نه روی ابر، نه به گوگل، هیچ منبع راه‌دوری نمی‌تواند ازش استفاده کند.

پنجرهٔ mhrv-rs باز می‌شود. این فیلدها را پر کن:

- **Apps Script ID(s)** ← **Deployment ID** از مرحلهٔ ۱ را پیست کن
- **Auth key** ← همان رشتهٔ تصادفی که در `Code.gs` گذاشتی
- بقیه را پیش‌فرض ول کن

روی **Save config** و بعد **Start** بزن. اگر کار کند، دایرهٔ وضعیت سبز می‌شود.

> **تستش کن:** دکمهٔ **Test** را بزن. یک درخواست از طریق رله می‌فرستد و می‌گوید کار کرد یا نه.

### مرحلهٔ ۴ — مرورگر را روی mhrv-rs تنظیم کن

#### فایرفاکس (پیشنهادی — ساده‌ترین)

۱. فایرفاکس → منوی ☰ → **Settings**
۲. در کادر جست‌وجو "proxy" تایپ کن
۳. زیر Network Settings روی **Settings…** کلیک کن
۴. **Manual proxy configuration** را انتخاب کن
۵. **HTTP Proxy:** `127.0.0.1` پورت: `8085`
۶. ☑ **"Also use this proxy for HTTPS"** را تیک بزن
۷. **OK**

#### کروم / Edge

افزونهٔ [Proxy SwitchyOmega](https://chromewebstore.google.com/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif) را نصب کن و پروکسی را روی `127.0.0.1:8085` تنظیم کن.

#### مک (سراسری)

System Settings → Network → Wi-Fi → Details → **Proxies** → هر دو **Web Proxy (HTTP)** و **Secure Web Proxy (HTTPS)** را روشن کن، هر دو روی `127.0.0.1:8085`.

### مرحلهٔ ۵ — امتحان کن

در مرورگرت یک سایت مسدود را باز کن. باید لود شود.

اگر چیزی کار نکرد:

- در پنجرهٔ mhrv-rs دکمهٔ **Test** را بزن — می‌گوید کجا گیر کرده
- پنل **Recent log** پایین پنجره را نگاه کن
- بخش [سؤالات رایج](#سؤالات-رایج) پایین را ببین

---

## سؤالات رایج

**واقعاً رایگانه؟** بله. گوگل به هر حساب روزانه ۲۰٬۰۰۰ درخواست خروجی URL در سهمیهٔ رایگان می‌دهد. برای مرور عادی یک نفر کاملاً کافی است. برای خانوادهٔ ۳-۴ نفره که از یک سرویس استفاده می‌کنند، در ۲-۳ حساب گوگل مختلف Deployment بساز و همهٔ ID‌ها را اضافه کن.

**امنه؟** گواهی روی کامپیوتر خودت می‌ماند — کسی کلید خصوصی را ندارد. `auth_key` رمز محرمانهٔ توست. گوگل سایت‌هایی که از طریق رله باز می‌کنی را می‌بیند (چون Apps Script برای تو fetch می‌کند) — مثل هر پروکسی میزبانی‌شدهٔ دیگری. اگر این برایت قابل قبول نیست، از Full Tunnel با VPS شخصی استفاده کن — در [راهنمای کامل](docs/guide.fa.md#حالت-تونل-کامل).

**ویدیوی یوتیوب پخش نمی‌شود.** chunkهای ویدیوی یوتیوب از `googlevideo.com` می‌آیند و Apps Script نمی‌تواند به آن برسد (گوگل اجازهٔ دسترسی Apps Script به CDN ویدیوی خودش را نمی‌دهد). صفحهٔ خود یوتیوب لود می‌شود، فقط پخش ویدیو تحت تأثیر است. راه‌حل: Full Tunnel + VPS، یا `.googlevideo.com` را به `passthrough_hosts` در کانفیگت اضافه کن (مرورگر مستقیم می‌رود اما روی ISP ایران throttle می‌خورد).

**ChatGPT / Claude / Grok کپچای Cloudflare نشان می‌دهد.** Cloudflare آی‌پی‌های دیتاسنتر گوگل را به‌عنوان bot شناسایی می‌کند. راه‌حل: یک **exit node** راه‌اندازی کن — یک handler کوچک TypeScript که روی یک host serverless (Deno Deploy، fly.io، VPS شخصی) deploy می‌کنی و پل می‌سازه از Apps Script به سایت Cloudflare. [`assets/exit_node/README.fa.md`](assets/exit_node/README.fa.md).

**تلگرام پایدار نیست.** تلگرام از MTProto استفاده می‌کند که Apps Script نمی‌فهمد. روی کامپیوترت با [xray](https://github.com/XTLS/Xray-core) جفتش کن — [بخش تلگرام در راهنمای کامل](docs/guide.fa.md#تلگرام-با-xray).

**ISP خود `script.google.com` را مسدود کرده.** mhrv-rs یک حالت `direct` دارد که فقط از تونل بازنویسی SNI استفاده می‌کند (بدون Apps Script). یک‌بار از این حالت استفاده کن تا به `script.google.com` برسی و اسکریپت را دیپلوی کنی، بعد به حالت apps_script سوئیچ کن. [حالت direct](docs/guide.fa.md#حالت-direct).

**می‌خواهم از mhrv-rs به‌عنوان پروکسی upstream برای Psiphon (یا xray) استفاده کنم.** mhrv-rs را در حالت `direct` اجرا کن و در تنظیمات Psiphon قسمت *upstream proxy* را روی host:port که زیر دکمهٔ Connect نمایش داده می‌شود تنظیم کن. هاست‌هایی که در لیست fronting قرار ندارند به‌صورت raw TCP عبور می‌کنند، پس ترافیک bootstrap سایفون به سرورهای سایفون دست‌نخورده می‌رسد. [docs/use-as-upstream.fa.md](docs/use-as-upstream.fa.md).

**جست‌وجوی گوگلم بدون JavaScript ظاهر می‌شود.** `User-Agent` Apps Script ثابت روی `Google-Apps-Script` است (گوگل نمی‌گذارد اسکریپت‌ها عوضش کنند)، پس بعضی سایت‌ها نسخهٔ بدون JS برمی‌گردانند. راه‌حل: دامنهٔ مورد نظر را به `hosts` اضافه کن تا از تونل بازنویسی SNI با User-Agent واقعی مرورگرت برود. `google.com`، `youtube.com`، `fonts.googleapis.com` به‌طور پیش‌فرض در این لیست‌اند.

**سؤالات بیشتر:** [FAQ کامل در راهنمای بلند](docs/guide.fa.md#سؤالات-رایج).

## کمک می‌خواهی؟

- در [issueهای rahgozar](https://github.com/dazzling-no-more/rahgozar/issues?q=is%3Aissue) جست‌وجو کن — و در [بایگانی بزرگ‌تر بالادست therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues?q=is%3Aissue) که بیشتر تاریخ پروژه آن‌جاست — احتمالاً مشکلت قبلاً جواب داده شده
- یک [issue جدید در rahgozar](https://github.com/dazzling-no-more/rahgozar/issues/new) باز کن با: کانفیگت (حتماً `auth_key` را پنهان کن!)، دقیقاً چه کاری کردی، دقیقاً چه دیدی در log

## اعتبار

این فورک روی سه پروژهٔ بالادست ایستاده — قبل از این که به این فورک فکر کنی، باید این سه را بشناسی و حمایتشان کنی:

- پروژهٔ اصلی پایتون **[@masterking32/MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN)** — همه‌چیز از این‌جا شروع شد. پروتکل Apps Script، معماری پروکسی، ایدهٔ استفاده از حساب گوگل خودت به‌عنوان رلهٔ رایگان — همه از اوست. بدون این، هیچ‌کدام از باقی وجود نداشت.
- پورت Rust به نام **[@therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST)** (`mhrv-rs`) — این فورک ادامهٔ همان است. therealaleph پروژهٔ پایتون را به Rust بازنویسی کرد تا کلاینت‌های تک‌فایلی منتشر کند، رابط دسکتاپ و اندروید را ساخت، و پروژه را از v1.x تا v1.9.25 پیش برد. تقریباً هر خط کد این فورک کار اوست؛ ما فقط چراغ را روشن نگه داشتیم.
- ایدهٔ گروه‌های fronting در **[@patterniha/MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting)** — مسیریابی دامنه‌های خاص از طریق edge های Vercel / Fastly / CloudFront با SNI، که به بستهٔ آمادهٔ fronting این پروژه تبدیل شد. پروژه‌ای مستقل؛ کانفیگ Xray آن الهام‌بخش ادغام ما بود. جزئیات در [`docs/fronting-groups.md`](docs/fronting-groups.md).

بیشتر کد Rust این پورت (شامل کار ادغام و rebrand این فورک) با کمک [Claude شرکت Anthropic](https://claude.com) نوشته شده و روی هر commit انسانی بازبینی شده است.

## حمایت از این پروژه‌ها

اگر از این نرم‌افزار سود برده‌ای، **حمایتت را به بالادست بفرست، نه به این فورک.** رهگذر هیچ کمک مالی‌ای نمی‌گیرد و فقط برای پوشش کاربران در دورانی که بالادست غیرفعال است وجود دارد. مهندسی اصلی در سه پروژهٔ بالا انجام شده؛ لطفاً مستقیماً از آن‌ها حمایت کن:

- در GitHub Sponsors از **[@masterking32](https://github.com/masterking32)** — نویسندهٔ پروژهٔ اصلی پایتون. یا از طریق روش‌های ذکر شده در پروفایل و ریپوی او.
- در **[sh1n.org/donate](https://sh1n.org/donate)** برای **[@therealaleph](https://github.com/therealaleph)** — نویسندهٔ پورت Rust. پوشش هزینهٔ هاستینگ / CI / سال‌ها نگه‌داری.
- در GitHub Sponsors از **[@patterniha](https://github.com/patterniha)** — نویسندهٔ MITM-DomainFronting. یا از طریق روش‌های ذکر شده در ریپوی او.

ستاره دادن به این سه ریپوی بالادست هم نشان می‌دهد کارشان ارزش ادامه دادن دارد. اگر mhrv-rs بالادست دوباره فعال شد، این فورک تغییرات را برمی‌گرداند و کنار می‌کشد — هدف فقط تداوم دسترسی برای کاربران پشت سانسور سنگین است، نه چیز دیگر.

</div>
