# Prebuilt Binaries

This folder contains the prebuilt binaries from the latest release, committed directly to the repository for users who cannot reach the GitHub Releases page.

Current version: **v2.1.0**

| File | Platform | Contents |
|---|---|---|
| `rahgozar-android-universal-v2.1.0.apk` | Android 7.0+ (all ABIs) | Universal APK — arm64-v8a, armeabi-v7a, x86_64, x86 in one file |
| `rahgozar-linux-amd64.tar.gz` | Linux x86_64 | `rahgozar`, `rahgozar-ui`, `run.sh` |
| `rahgozar-linux-arm64.tar.gz` | Linux aarch64 | `rahgozar`, `run.sh` (CLI only) |
| `rahgozar-raspbian-armhf.tar.gz` | Raspberry Pi / ARMv7 hardfloat | `rahgozar`, `run.sh` (CLI only) |
| `rahgozar-macos-amd64.tar.gz` | macOS Intel | `rahgozar`, `rahgozar-ui`, `run.sh`, `run.command` |
| `rahgozar-macos-amd64-app.zip` | macOS Intel | `rahgozar.app` bundle (double-click from Finder) |
| `rahgozar-macos-arm64.tar.gz` | macOS Apple Silicon | `rahgozar`, `rahgozar-ui`, `run.sh`, `run.command` |
| `rahgozar-macos-arm64-app.zip` | macOS Apple Silicon | `rahgozar.app` bundle (double-click from Finder) |
| `rahgozar-windows-amd64.zip` | Windows x86_64 | `rahgozar.exe`, `rahgozar-ui.exe`, `run.bat` |
| `rahgozar-linux-musl-amd64.tar.gz` | OpenWRT / Alpine x86_64 | static `rahgozar` + `rahgozar.init` (procd) |
| `rahgozar-linux-musl-arm64.tar.gz` | OpenWRT / Alpine aarch64 | static `rahgozar` + `rahgozar.init` (procd) |

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

Extract `rahgozar-windows-amd64.zip`, then double-click `run.bat` inside the extracted folder (accept the UAC prompt so the MITM CA can be installed).

### Android

Copy `rahgozar-android-universal-v2.1.0.apk` to your phone, tap it from the Files app, and allow "Install unknown apps" for whichever app is opening the APK (Files, Chrome, etc.). See [the Android guide](../docs/android.md) for the full walk-through of the first-run steps (Apps Script deployment, MITM CA install, VPN permission, SNI tester).

See the [main README](../README.md) for desktop setup (Apps Script deployment, config, browser proxy settings).

---

## فایل‌های اجرایی

این پوشه شامل فایل‌های آخرین نسخه است و مستقیماً در ریپو قرار گرفته برای کاربرانی که به صفحهٔ GitHub Releases دسترسی ندارند.

نسخهٔ فعلی: **v2.1.0**

### دانلود از طریق ZIP

به [github.com/dazzling-no-more/rahgozar](https://github.com/dazzling-no-more/rahgozar) بروید، روی دکمهٔ سبز **Code** کلیک و **Download ZIP** را بزنید. پس از extract، آرشیوها در پوشهٔ `releases/` هستند.

### بعد از دانلود

**لینوکس / مک:**

```sh
tar xzf rahgozar-macos-arm64.tar.gz
cd rahgozar-macos-arm64
./run.sh                      # در مک می‌توانید روی run.command هم از Finder دو بار کلیک کنید
```

**ویندوز:** فایل `rahgozar-windows-amd64.zip` را extract کنید و داخل پوشه روی `run.bat` دو بار کلیک کنید (UAC را قبول کنید تا گواهی MITM نصب شود).

**اندروید:** فایل `rahgozar-android-universal-v2.1.0.apk` را روی گوشی کپی کنید، از Files app روی آن tap کنید و اجازهٔ "نصب برنامه‌های ناشناس" را بدهید. راهنمای کامل شروع به کار (دیپلوی Apps Script، نصب CA، اجازهٔ VPN، تستر SNI) در [راهنمای اندروید](../docs/android.md) هست.

برای راه‌اندازی کامل دسکتاپ (دیپلوی Apps Script، config، تنظیم proxy مرورگر) به [README اصلی](../README.md) مراجعه کنید.
