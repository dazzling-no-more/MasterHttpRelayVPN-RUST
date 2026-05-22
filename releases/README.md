# Prebuilt Binaries

This folder contains the prebuilt binaries from the latest release, committed directly to the repository for users who cannot reach the GitHub Releases page.

Current version: **v2.6.0**

> **Note:** The table below documents all artifacts produced by the release
> matrix. Several rows (Windows ARM64 CLI, Windows portable .exe, OpenWRT
> ARMv7 musl, OpenWRT MIPS big/little-endian) were added after v2.6.0.

**Note (v2.4):** the legacy egui desktop UI (`rahgozar-ui` /
`rahgozar-ui.exe`) and the launcher scripts (`run.sh`, `run.bat`,
`run.command`) have been retired. The desktop GUI is now distributed
as a platform-native installer built with Tauri (see the
`rahgozar-desktop-*` rows below). The CLI binary archives still ship
on every release for users who want to drive the proxy headless or
from another process.

| File | Platform | Contents |
|---|---|---|
| `rahgozar-android-universal-v2.6.0.apk` | Android 7.0+ (all ABIs), Android TV | Universal APK — arm64-v8a, armeabi-v7a, x86_64, x86 in one file. Also installable on Android TV (Shield, Mi Box, Chromecast with Google TV) |
| `rahgozar-portable-windows-amd64.exe` | Windows 10 (20H1+) / 11 x86_64 | **Portable** Tauri desktop UI — no install, double-click to run. Requires WebView2 (preinstalled on Win10 20H1+ / Win11) |
| `rahgozar-desktop-windows-amd64.msi` | Windows 10 / 11 x86_64 | Tauri-bundled desktop UI installer (MSI). Auto-updates via the in-app updater |
| `rahgozar-desktop-macos.dmg` | macOS 11+ (Intel + Apple Silicon) | Tauri-bundled desktop UI disk image |
| `rahgozar-desktop-linux-amd64.AppImage` | Linux x86_64 | Portable Tauri-bundled desktop UI |
| `rahgozar-desktop-linux-amd64.deb` | Debian / Ubuntu x86_64 | Tauri-bundled desktop UI package |
| `rahgozar-linux-amd64.tar.gz` | Linux x86_64 (glibc) | `rahgozar` CLI |
| `rahgozar-linux-arm64.tar.gz` | Linux aarch64 (glibc) | `rahgozar` CLI |
| `rahgozar-raspbian-armhf.tar.gz` | Raspberry Pi 2+ / ARMv6+v7 glibc | `rahgozar` CLI (glibc — for Raspbian/Debian on Pi, NOT OpenWRT) |
| `rahgozar-macos-amd64.tar.gz` | macOS Intel | `rahgozar` CLI |
| `rahgozar-macos-arm64.tar.gz` | macOS Apple Silicon | `rahgozar` CLI |
| `rahgozar-windows-amd64.zip` | Windows x86_64 | `rahgozar.exe` CLI |
| `rahgozar-windows-arm64.zip` | Windows ARM64 (Snapdragon X / Surface Pro X+11) | `rahgozar.exe` CLI (MSVC, native arm64) |
| `rahgozar-linux-musl-amd64.tar.gz` | OpenWRT / Alpine x86_64 | static `rahgozar` + `rahgozar.init` (procd) |
| `rahgozar-linux-musl-arm64.tar.gz` | OpenWRT / Alpine aarch64 | static `rahgozar` + `rahgozar.init` (procd) |
| `rahgozar-openwrt-armv7-musleabihf.tar.gz` | OpenWRT ARMv7 (Cortex-A7/A9: ipq40xx, mt7622, ipq806x) | static `rahgozar` + `rahgozar.init` (procd) |
| `rahgozar-openwrt-mipsel-softfloat.tar.gz` | OpenWRT MIPS little-endian (MT7621: Xiaomi 4A Gigabit, Redmi AC2100, GL.iNet B1300, etc.) | static `rahgozar` + `rahgozar.init` (procd) — Rust tier-3, best-effort |
| `rahgozar-openwrt-mips-softfloat.tar.gz` | OpenWRT MIPS big-endian (Atheros AR71XX/AR9XXX: TP-Link Archer C7, WDR4300, Ubiquiti EdgeRouter Lite) | static `rahgozar` + `rahgozar.init` (procd) — Rust tier-3, best-effort |
| `rahgozar-tunnel-node-linux-musl-amd64.tar.gz` | Any Linux x86_64 VPS | static `tunnel-node` (full-mode exit-node bridge) |
| `rahgozar-tunnel-node-linux-musl-arm64.tar.gz` | Any Linux aarch64 VPS | static `tunnel-node` (full-mode exit-node bridge) |

## Download via git clone

```
git clone https://github.com/dazzling-no-more/rahgozar.git
cd rahgozar/releases
```

## Download via ZIP

Go to [github.com/dazzling-no-more/rahgozar](https://github.com/dazzling-no-more/rahgozar), click the green **Code** button, then **Download ZIP**. Extract it — the archives are in the `releases/` folder.

## After download

### Linux / macOS

```sh
tar xzf rahgozar-macos-arm64.tar.gz
cd rahgozar-macos-arm64        # or wherever the archive extracted to
./run.sh                      # or ./run.command on macOS (double-click in Finder)
```

### Windows

- **Portable, no install:** download `rahgozar-portable-windows-amd64.exe` and double-click — that's it. Needs WebView2 (preinstalled on Win10 20H1+ / Win11; older Win10 users install Edge WebView2 Runtime once from microsoft.com).
- **Installer:** download `rahgozar-desktop-windows-amd64.msi` and run it. Adds rahgozar to the Start menu and enables in-app auto-updates.
- **CLI:** extract `rahgozar-windows-amd64.zip` (x86_64) or `rahgozar-windows-arm64.zip` (Snapdragon X / Surface Pro X+11) and run `rahgozar.exe` from a terminal.

### Android

Copy `rahgozar-android-universal-v2.6.0.apk` to your phone, tap it from the Files app, and allow "Install unknown apps" for whichever app is opening the APK (Files, Chrome, etc.). See [the Android guide](../docs/android.md) for the full walk-through of the first-run steps (Apps Script deployment, MITM CA install, VPN permission, SNI tester).

See the [main README](../README.md) for desktop setup (Apps Script deployment, config, browser proxy settings).

---

## فایل‌های اجرایی

این پوشه شامل فایل‌های آخرین نسخه است و مستقیماً در ریپو قرار گرفته برای کاربرانی که به صفحهٔ GitHub Releases دسترسی ندارند.

نسخهٔ فعلی: **v2.6.0**

### دانلود از طریق ZIP

به [github.com/dazzling-no-more/rahgozar](https://github.com/dazzling-no-more/rahgozar) بروید، روی دکمهٔ سبز **Code** کلیک و **Download ZIP** را بزنید. پس از extract، آرشیوها در پوشهٔ `releases/` هستند.

### بعد از دانلود

**لینوکس / مک:**

```sh
tar xzf rahgozar-macos-arm64.tar.gz
cd rahgozar-macos-arm64
./run.sh                      # در مک می‌توانید روی run.command هم از Finder دو بار کلیک کنید
```

**ویندوز:** ساده‌ترین راه — فایل `rahgozar-portable-windows-amd64.exe` را دانلود و دو بار کلیک کنید؛ بدون نصب اجرا می‌شود. اگر می‌خواهید نصب کامل با آپدیت خودکار داشته باشید، `rahgozar-desktop-windows-amd64.msi` را اجرا کنید. کاربران لپ‌تاپ‌های Snapdragon X / Surface Pro X+11 می‌توانند نسخهٔ `rahgozar-windows-arm64.zip` (CLI) را دانلود کنند.

**اندروید:** فایل `rahgozar-android-universal-v2.6.0.apk` را روی گوشی کپی کنید، از Files app روی آن tap کنید و اجازهٔ "نصب برنامه‌های ناشناس" را بدهید. راهنمای کامل شروع به کار (دیپلوی Apps Script، نصب CA، اجازهٔ VPN، تستر SNI) در [راهنمای اندروید](../docs/android.md) هست.

برای راه‌اندازی کامل دسکتاپ (دیپلوی Apps Script، config، تنظیم proxy مرورگر) به [README اصلی](../README.md) مراجعه کنید.
