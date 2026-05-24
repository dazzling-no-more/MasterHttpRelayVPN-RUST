<!-- Per-paragraph rule: each Persian line/bullet must start with a Persian
     character so markdown's per-paragraph direction auto-detection renders
     RTL correctly, even inside the dir="rtl" wrapper. -->
<div dir="rtl">

# حالت درایو — راهنمای کامل راه‌اندازی

> *English: [drive_mode.md](./drive_mode.md)*

این تنها سندی است که برای راه‌اندازی حالت Drive از صفر نیاز داری. اگر VPS داری حدود ۲۰ دقیقه، با خرید VPS حدود ۳۰ دقیقه. در پایان، ترافیک TCP تو از یک پوشهٔ گوگل درایو که خودت مالکش هستی عبور می‌کند — ISP فقط TLS به `*.google.com` می‌بیند.

> **مدل راه‌اندازی:** حالت Drive **BYO OAuth** است — rahgozar هیچ OAuth client از پیش‌ساخته‌ای ندارد. قبل از گام ۵ در ادامه، خودت یک OAuth client در Google Cloud Console ثبت می‌کنی (حدود ۱۰ دقیقه، رایگان، یک‌بار): راهنمای گام‌به‌گام در [drive_oauth_setup.fa.md](./drive_oauth_setup.fa.md). دلیلش: یک OAuth client تأیید‌نشده روی scope `drive.file` سقف ۱۰۰ کاربری دارد؛ BYO این محدودیت را کلاً دور می‌زند چون هر کاربر سهمیهٔ ۱۰۰ کاربری خودش را دارد که هیچ‌وقت پر نمی‌شود.

سه قطعه را راه می‌اندازی:

```text
دستگاه تو (ایران)               Google                    VPS تو (خارج)
┌──────────┐  TLS به            ┌──────────┐  HTTPS      ┌──────────────────┐
│ rahgozar │ ─*.google.com────▶ │ Drive    │ ◀── poll ──│ rahgozar-drive-  │─▶ اینترنت
│ (client) │   (SNI rewrite)    │ API      │            │ relay (systemd)  │
└──────────┘                    └──────────┘            └──────────────────┘
   گام ۷                        پوشهٔ صندوق             گام‌های ۲–۶
                                مشترک تو
```

برای پس‌زمینه (چرا حالت Drive کنار Apps Script وجود دارد، چگونه با ماشین موجود SNI-rewrite و domain-fronting تعامل می‌کند) به [guide.fa.md](./guide.fa.md) مراجعه کن. این سند فقط راه‌اندازی را پوشش می‌دهد.

## چه زمانی حالت Drive به‌جای Apps Script

پیش‌فرض اکثر کاربران Apps Script است — به VPS نیاز ندارد و منطق ریلی روی زیرساخت گوگل به‌رایگان اجرا می‌شود. حالت Drive انتخاب درست است وقتی:

- سهمیه‌های Apps Script گیرت می‌کنند (استفادهٔ سنگین مداوم؛ چرخش چند حسابی هم کافی نیست).
- گوگل deployment Apps Script تو را علامت‌گذاری کرده (محدودسازی در سطح حساب روی کاربران ایرانی — گاهی پیش می‌آید).
- می‌خواهی یک مسیر کد جداگانه تحت اعمال محدودیت گوگل جداگانه داشته باشی.

چه چیزی نسبت به Apps Script از دست می‌دهی:
- یک **VPS خارج** (ماهی ۴–۶$) که باینری ریلی را اجرا می‌کند. به IP عمومی نیاز نداری — ریلی فقط connection بیرونی به Drive + مقصدهایی که forward می‌کند باز می‌کند.
- تأخیر بالاتر. درایو از long-polling پشتیبانی نمی‌کند، پس کلاینت + ریلی هر کدام هر ۱۰۰–۳۰۰ میلی‌ثانیه poll می‌کنند. تأخیر متوسط web حدود ۵۰۰ میلی‌ثانیه vs ۳۰۰ میلی‌ثانیه روی Apps Script.
- سهمیهٔ **۱۵ گیگابایت Drive**. فایل‌ها بعد از هر round-trip موفق حذف می‌شوند + یک orphan reaper بقیه را جارو می‌کند، اما یک flow ناهنجار می‌تواند آن را پر کند. استفادهٔ سنگین روزانه در عمل خیلی کمتر از ۱ گیگابایت peak می‌ماند.

## پیش‌نیازها

نیازمندی‌ها:

- یک **حساب گوگل** (یک Gmail). همین حساب هم در کلاینت و هم در ریلی sign in می‌شود — هر دو از طریق همان حساب پوشهٔ Drive را به اشتراک می‌گذارند. (دو حساب متفاوت هم می‌شود، اما باید پوشه را به‌صورت explicit share کنی؛ اینجا پوشش داده نشده.)
- یک **VPS** با اینترنت بیرونی نرمال. **IPv4 عمومی لازم نیست** — ریلی فقط connection بیرونی باز می‌کند. ارزان‌ترین tier کافی است — حدود ۵۰ مگابایت RAM، CPU baseline ندارد. پیشنهادها:
  - پیشنهاد **Hetzner CX22** (€۴–۵ در ماه، Falkenstein/Helsinki، ۲۰ ترابایت egress) — بهترین ارزش برای کاربران اروپا/خاورمیانه.
  - پیشنهاد **DigitalOcean basic droplet** (۶$ در ماه، NYC/SFO) — بهترین برای کاربران آمریکا.
  - برای **کاربران ایرانی**: IP خود VPS در حالت Drive بی‌اهمیت است — ترافیک Drive از edge گوگل عبور می‌کند، نه از VPS تو. هر جا که ارزان‌تر است را انتخاب کن.
- نصب **rahgozar** روی دستگاهی که می‌خواهی از طریقش تونل بزنی. اگر هنوز نصب نکرده‌ای، [README اصلی](../README.md) را ببین.

وقتی provider از تو OS image می‌خواهد، **Ubuntu 22.04 LTS** یا **Debian 12** انتخاب کن — دستورات زیر فرض می‌کنند یکی از این‌هاست.

## گام ۱ — SSH به VPS

از terminal لپ‌تاپ:

```bash
ssh root@<VPS_IP>
```

به‌جای `<VPS_IP>` آدرس IPv4ای که provider به تو داده را بگذار. اگر provider به‌جای root یک کاربر non-root داده، از همان استفاده کن و دستورات بعد را با `sudo` prefix بزن.

## گام ۲ — نصب باینری ریلی

ساخت Linux x86_64 را از [آخرین release](https://github.com/dazzling-no-more/rahgozar/releases/latest) انتخاب کن:

```bash
# باینری ریلی + اسکریپت نصب + systemd unit را دانلود کن.
# به‌جای VERSION، تگ release را بگذار (مثلاً v2.8.0).
VERSION=<آخرین تگ>
ARCH=$(uname -m)   # احتمالاً x86_64؛ arm64 هم هست

curl -fsSLo /tmp/rahgozar-drive-relay \
  https://github.com/dazzling-no-more/rahgozar/releases/download/${VERSION}/rahgozar-drive-relay-linux-${ARCH}
chmod +x /tmp/rahgozar-drive-relay

# اسکریپت نصب: کاربر system به نام `rahgozar-relay` می‌سازد،
# باینری را در /usr/local/bin می‌گذارد، systemd unit را نصب می‌کند،
# و یک config dir با mode 0700 در /etc/rahgozar-drive-relay می‌سازد.
curl -fsSLo /tmp/install-drive-relay.sh \
  https://raw.githubusercontent.com/dazzling-no-more/rahgozar/${VERSION}/drive-relay/scripts/install-drive-relay.sh
curl -fsSLo /tmp/rahgozar-drive-relay.service \
  https://raw.githubusercontent.com/dazzling-no-more/rahgozar/${VERSION}/drive-relay/systemd/rahgozar-drive-relay.service

sudo BINARY=/tmp/rahgozar-drive-relay \
  SERVICE_FILE=/tmp/rahgozar-drive-relay.service \
  sh /tmp/install-drive-relay.sh
```

نصب‌کننده سه دستور بعدی را چاپ می‌کند. همه به‌عنوان کاربر اختصاصی `rahgozar-relay` اجرا می‌شوند (نه root) — اجرای آن‌ها به‌عنوان root باعث می‌شود keypair + توکن OAuth با مالک اشتباه ذخیره شوند و daemon در startup نتواند آن‌ها را بخواند.

## گام ۳ — ساخت keypair X25519 ریلی

```bash
sudo -u rahgozar-relay rahgozar-drive-relay keygen \
  --out /etc/rahgozar-drive-relay/relay.key
```

این یک secret ۳۲-بایتی به `relay.key` می‌نویسد (با mode 0600) و کلید عمومی را در stdout چاپ می‌کند — یک رشتهٔ ۶۳-کاراکتری که با `rgdr1...` شروع می‌شود. **این را کپی کن.** در گام ۷ در اپ کلاینت paste می‌کنی.

اگر زمانی `relay.key` را گم کنی، باید دوباره `keygen` بزنی، pubkey جدید را در config هر کلاینت paste کنی، و restart کنی. recovery وجود ندارد — secret فقط روی دیسک است.

## گام ۴ — ورود به گوگل (device-code flow)

اگر هنوز انجام نداده‌ای، اول [drive_oauth_setup.fa.md](./drive_oauth_setup.fa.md) را دنبال کن تا OAuth clientهای شخصی‌ات را در Google Cloud Console ثبت کنی. برای دستور زیر، از client نوع **TVs and Limited Input devices** استفاده کن.

```bash
sudo -u rahgozar-relay rahgozar-drive-relay oauth device-code \
  --client-id     "<client_id خودت>" \
  --client-secret "<client_secret خودت>" \
  --out /etc/rahgozar-drive-relay/config.json
```

ریلی یک URL + یک user-code کوتاه چاپ می‌کند، سپس گوگل را poll می‌کند تا تو flow را کامل کنی:

```
==============================================================
  Open this URL in any browser and enter the code below:

    https://www.google.com/device
    code: ABCD-EFGH

  This flow expires in 1800 seconds.
==============================================================
```

روی لپ‌تاپ یا گوشی، URL را باز کن، کد را paste کن، با **همان حساب گوگلی** که اپ کلاینت استفاده خواهد کرد sign in کن، و approve کن. session SSH ریلی موفقیت را می‌گیرد و refresh token را در `/etc/rahgozar-drive-relay/config.json` می‌نویسد.

> **چه scopeای می‌خواهد؟** فقط `https://www.googleapis.com/auth/drive.file` — Drive Mode فقط فایل‌هایی را می‌بیند که همین app OAuth راهگذر در پوشهٔ mailbox ساخته یا باز کرده است. محتوای موجود Drive تو را نمی‌تواند بخواند.

## گام ۵ — پر کردن config

حالا `/etc/rahgozar-drive-relay/config.json` را داری که refresh token در آن تنظیم شده. باقی فیلدها باید پر شوند — با ویرایشگر دلخواه باز کن:

```bash
sudo -u rahgozar-relay nano /etc/rahgozar-drive-relay/config.json
```

فایل بعد از گام ۴ این شکلی است:

```json
{
  "oauth_client_id": "1234567890-xxxxxxxx.apps.googleusercontent.com",
  "oauth_client_secret": "GOCSPX-xxxxxxxxxxxxxxxx",
  "oauth_refresh_token": "1//04xxxxxxxxxx...",
  "folder_id": "",
  "x25519_secret_key_path": "/etc/rahgozar-drive-relay/relay.key",
  "poll_interval_ms": 300,
  "max_concurrent_dials": 8,
  "idle_timeout_secs": 120,
  "allow_destinations": [],
  "metrics_bind": null
}
```

فعلاً `folder_id` را خالی بگذار — در گام ۷ از اپ کلاینت پرش می‌کنی.

باقی default‌ها منطقی هستند:
- مقدار `poll_interval_ms: 300` — بازهٔ پایه‌ای که ریلی Drive را poll می‌کند. وفق‌پذیر است: سریع‌تر در ترافیک فعال، آهسته‌تر در حالت idle. بالا بردنش سهمیهٔ Drive را صرفه‌جویی می‌کند به قیمت تأخیر بیشتر.
- مقدار `max_concurrent_dials: 8` — سقف dial بیرونی. برای browsing تک‌نفره کافی است.
- مقدار `idle_timeout_secs: 120` — sessionهایی که این مدت ترافیک ندارند evict می‌شوند. tabهای idle مرورگر اینجا جارو می‌شوند.
- مقدار `allow_destinations: []` — خالی = هر مقصدی مجاز است. مثلاً به `["chatgpt.com", "x.com"]` ست کن اگر می‌خواهی ریلی به مقصدهای دیگر Connect frame نپذیرد.

## گام ۶ — ساخت پوشهٔ مشترک Drive (از اپ کلاینت)

شناسهٔ پوشه را در UI دسکتاپ یا اندروید گام ۷ می‌گیری. ID را ذخیره کن، سپس برگرد و config گام ۵ را ویرایش کن:

```bash
# بعد از اینکه گام ۷ به تو folder ID داد:
sudo -u rahgozar-relay nano /etc/rahgozar-drive-relay/config.json
# `"folder_id": "0AABBccDDeeFFgg..."` را با مقدار UI کلاینت ست کن.
```

سپس daemon را شروع کن:

```bash
sudo systemctl enable --now rahgozar-drive-relay
sudo systemctl status rahgozar-drive-relay     # باید `active (running)` باشد
sudo journalctl -u rahgozar-drive-relay -f      # دنبال کردن لاگ‌ها
```

اگر daemon شروع نکرد، خط log بهت می‌گوید چرا — معمولاً یک فیلد config گم‌شده یا مسیر اشتباه فایل کلید.

## گام ۷ — تنظیم اپ کلاینت

اپ دسکتاپ یا اندروید rahgozar را باز کن. در دسکتاپ تب Tunnel و در اندروید صفحهٔ اصلی setup جایی است که modeها را پیکربندی می‌کنی.

۱. مود را انتخاب کن: **«Drive (mailbox via Google Drive)»** را بزن. بخش جدید «Drive mailbox setup» ظاهر می‌شود.
۲. **کلاینت OAuth (BYO)**: در بالای بخش، **Client ID** و **Client secret** را از [drive_oauth_setup.fa.md](./drive_oauth_setup.fa.md) paste کن. روی دسکتاپ از client نوع **Desktop app** استفاده کن. روی اندروید از client نوع **TVs and Limited Input devices** استفاده کن. **Save** کن — تا این‌ها ذخیره نشوند، دکمهٔ Sign-in غیرفعال می‌ماند.
۳. روی **Sign in with Google** کلیک کن. روی دسکتاپ یک tab مرورگر باز می‌شود، صفحهٔ consent را approve می‌کنی، و tab خودش بسته می‌شود. روی اندروید یک dialog کد دستگاه می‌بینی؛ **Open** را بزن، کد نمایش‌داده‌شده را وارد کن، sign in کن، و به rahgozar برگرد. با **همان حساب گوگلی** که در گام ۴ روی ریلی استفاده کردی sign in کن.
۴. روی **Create new** کلیک کن، یک نام وارد کن (پیش‌فرض: `rahgozar mailbox`)، **Create** بزن. شناسهٔ پوشهٔ جدید در فیلد Folder ID paste می‌شود. **این ID را کپی کن** — باید در گام ۶ آن را در config ریلی paste کنی.
۵. کلید عمومی ریلی: رشتهٔ `rgdr1...` از گام ۳ را paste کن. فیلد به‌صورت زنده validate می‌شود — تیک سبز اگر checksum bech32m درست باشد.
۶. پیشرفته (اختیاری): اگر می‌دانی چه کار می‌کنی `poll_interval_ms` / `max_concurrent_uploads` را تغییر بده. defaultها خوب هستند.
۷. روی **Save** کلیک کن.

کلاینت OAuth دسکتاپ/اندروید و کلاینت OAuth ریلی VPS می‌توانند نوع‌های
متفاوتی داشته باشند، اما باید در **یک Google Cloud project و یک consent
screen** باشند. Drive Mode از `drive.file` استفاده می‌کند، و گوگل این
دسترسی را به app/projectی محدود می‌کند که فایل‌های mailbox را ساخته یا
باز کرده است؛ کلاینت‌های projectهای جدا ممکن است فایل‌های همدیگر را
نبینند، حتی اگر حساب گوگل و folder ID یکسان باشد.

حالا به گام ۶ روی VPS برگرد و folder ID را در `config.json` ریلی paste کن. اگر daemon از قبل running بود restart کن:

```bash
sudo systemctl restart rahgozar-drive-relay
```

## گام ۸ — تست

برگرد به UI کلاینت، با mode روی Drive و form ذخیره‌شده:

۱. روی **Test connection** زیر فیلد Folder ID کلیک کن. باید چیزی شبیه به *✓ OK — folder 0AABB...gg has 0 file(s).* گزارش بدهد.
۲. روی **Start** کلیک کن. روی دسکتاپ proxy روی `127.0.0.1:8085` (HTTP) و `:8086` (SOCKS5) بالا می‌آید. روی اندروید اگر Android prompt مربوط به VPN را نشان داد approve کن؛ اپ ترافیک دستگاه را از transport درایو عبور می‌دهد.
۳. روی دسکتاپ مرورگر را روی proxy تنظیم کن و یک سایت باز کن. روی اندروید مرورگر یا یک اپ را باز کن و IP عمومی‌ات را چک کن.

تست سریع بدون مرورگر:

```bash
# از لپ‌تاپی که rahgozar روی آن اجرا می‌شود:
curl -x http://127.0.0.1:8085 https://api.ipify.org
# انتظار: یک IP که متعلق به provider VPS توست (نه IP واقعی تو).
```

اگر IP provider VPS را دیدی، **Drive Mode کار می‌کند**. end-to-end.

## به‌روزرسانی ریلی بعداً

releaseها به‌طور منظم منتشر می‌شوند. برای به‌روزرسانی:

```bash
ssh root@<VPS_IP>
# daemon را متوقف کن، باینری جدید را دانلود کن، restart کن.
sudo systemctl stop rahgozar-drive-relay
VERSION=<تگ جدید>
curl -fsSLo /usr/local/bin/rahgozar-drive-relay \
  https://github.com/dazzling-no-more/rahgozar/releases/download/${VERSION}/rahgozar-drive-relay-linux-x86_64
sudo chmod +x /usr/local/bin/rahgozar-drive-relay
sudo systemctl start rahgozar-drive-relay
sudo journalctl -u rahgozar-drive-relay -f
```

keypair و OAuth token باقی می‌مانند — لازم نیست دوباره pair کنی یا sign in کنی.

## رفع اشکال

**اجرای `rahgozar-drive-relay run` با `oauth_refresh_token is empty` خطا می‌دهد.**
گام ۴ را skip کرده‌ای. دوباره `oauth device-code` بزن.

**daemon شروع می‌کند، log می‌گوید "OAuth refresh failed at startup".**
رفرش توکن تو revoke شده (از گوگل sign out کرده‌ای؟ پسورد حساب را عوض کرده‌ای؟ گوگل حساب را به‌خاطر sanction flag کرده؟). گام ۴ را دوباره اجرا کن.

**روی "Sign in with Google" خطای `invalid_client` می‌گیری.**
مقادیر `oauth_client_id` / `oauth_client_secret` در بخش راه‌اندازی Drive با نوع OAuth client مورد نیاز این مسیر تطبیق ندارند. دسکتاپ باید از OAuth client نوع **Desktop app** استفاده کند. اندروید و ریلی VPS باید از OAuth client نوع **TVs and Limited Input devices** استفاده کنند. دلایل رایج: غلط تایپی هنگام paste، کپی‌کردن فقط بخشی از secret، paste کردن نوع client اشتباه، یا حذف/چرخش OAuth client. هر دو مقدار را از [drive_oauth_setup.fa.md](./drive_oauth_setup.fa.md) دوباره paste کن، Save کن، دوباره Sign in را امتحان کن.

**Test connection گزارش "Folder not found" می‌دهد.**
یا `folder_id` در config دسکتاپ با چیزی که روی VPS است یکی نیست، یا در گام ۷ با حساب گوگل متفاوتی sign in کرده‌ای نسبت به گام ۴. هر دو سمت باید از یک حساب + یک پوشه استفاده کنند.

**`curl --proxy http://127.0.0.1:8085 ...` hang می‌کند.**
لاگ ریلی را چک کن (`journalctl -u rahgozar-drive-relay -f`) — اگر بعد از "OAuth refresh token verified" خط لاگی نیست، ریلی Hello frameها را از کلاینت نمی‌بیند. علل رایج:
- شناسهٔ پوشهٔ ناهماهنگ (اپ کلاینت + ریلی از پوشه‌های متفاوت استفاده می‌کنند).
- کلید عمومی ریلی اشتباه در config دسکتاپ (کلاینت با کلید اشتباه رمز می‌کند؛ ریلی نمی‌تواند رمزگشایی کند؛ frameها بی‌صدا dropped می‌شوند).

**فضای Drive پر می‌شود.**
پوشه را در UI وب Drive ببین. اگر هزاران فایل دارد، orphan reaper عقب مانده — `poll_interval_ms` را روی هر دو سمت بالا ببر تا نرخ upload کم شود، یا `idle_timeout_secs` ریلی را کم کن تا reaper فایل‌های stale را سریع‌تر جارو کند.

**چند دستگاه از یک پوشهٔ Drive مشترک استفاده کنند.**
پشتیبانی می‌شود. هر کلاینت لیست `r2c_*` را قبل از دانلود بر اساس مجموعهٔ session-idهای محلی خودش فیلتر می‌کند، پس فایل‌های متعلق به sessionهای کلاینت‌های دیگر را نادیده می‌گیرد (همه به یک پوشه می‌رسند ولی فقط `r2c_<sid>_*`های خودت با یک session فعال در جدول محلی‌ات match می‌شوند). می‌توانی desktop + Android + یک گوشی دوم را همزمان روی یک ریلی + یک پوشه اجرا کنی بدون تداخل؛ sessionهای هر دستگاه با `sid` ۱۲۸ بیتی‌اش جدا می‌مانند. ریلی نیاز ندارد بداند چند کلاینت با او صحبت می‌کنند — فقط به همان sidی که c2r فرستاده پاسخ r2c می‌نویسد.

## سؤالات متداول

**می‌توانم حالت Drive را روی اندروید استفاده کنم؟**
بله. اندروید از flow کد دستگاه استفاده می‌کند، پس در Google Cloud Console به یک OAuth client نوع **TVs and Limited Input devices** نیاز داری. اپ دسکتاپ همچنان از flow مرورگر loopback با OAuth client نوع **Desktop app** استفاده می‌کند.

**ریلی می‌تواند روی همان دستگاه کلاینت اجرا شود؟**
در تئوری بله — تنها نیاز ریلی «دسترسی به اینترنت آزاد» است. اما کل ایدهٔ حالت Drive این است که ریلی بیرون از شبکهٔ سانسورشده باشد، پس co-locate کردن هدف را خنثی می‌کند.

**اگر گوگل Drive API را برای IPهای ایرانی sanction-block کند چه؟**
ترانسپورت Drive از SNI-rewrite موجود `google_ip` rahgozar ارث می‌برد: فیلد `google_ip` در config دسکتاپ برای pin کردن endpointهای Drive به یک IP edge گوگل کارگر استفاده می‌شود. همان setup حالت Apps Script — ماشین موجود IP-discovery / SNI-pool بدون تغییر کار می‌کند.

**این از Apps Script سریع‌تر است یا کندتر؟**
کندتر، در حالت متوسط. Apps Script در ~۳۰۰–۵۰۰ میلی‌ثانیه fetch می‌کند؛ polling حالت Drive ۱۰۰–۳۰۰ میلی‌ثانیه به هر leg اضافه می‌کند، پس یک request HTTP معمولی ~۶۰۰–۸۰۰ میلی‌ثانیه است vs ~۴۰۰–۶۰۰ میلی‌ثانیه روی Apps Script. سقف throughput بالاتر است چون سهمیهٔ QPS Drive از cap ۳۰-همزمان Apps Script بزرگ‌تر است.

</div>
