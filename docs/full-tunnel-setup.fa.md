<!-- Per-paragraph rule: each Persian line/bullet must start with a Persian
     character so markdown's per-paragraph direction auto-detection renders
     RTL correctly, even inside the dir="rtl" wrapper. -->
<div dir="rtl">

# تونل کامل — راهنمای کامل راه‌اندازی

> *English: [full-tunnel-setup.md](./full-tunnel-setup.md)*

این تنها سندی است که برای راه‌اندازی حالت Full Tunnel از صفر نیاز داری. اگر VPS داری حدود ۱۵ دقیقه، با خرید VPS حدود ۲۵ دقیقه طول می‌کشد. در پایان، **همهٔ** ترافیک — تلگرام، یوتیوب، هر اپ — از داخل تونل رد می‌شود.

سه قطعه را راه می‌اندازی:

```
دستگاه تو                     Google                       VPS تو
┌──────────┐  TLS به گوگل    ┌──────────┐   HTTPS         ┌────────────┐
│ rahgozar │ ───────────────▶│ Apps     │ ───────────────▶│ tunnel-node│ ─▶ اینترنت
│ (client) │   (fronted)     │ Script   │  (CodeFull.gs)  │ (Docker)   │
└──────────┘                  └──────────┘                 └────────────┘
   گام ۴                        گام ۳                        گام ۲
```

برای پس‌زمینه (معماری، performance، scale با تعداد deployment) ببین [guide.fa.md → حالت تونل کامل](guide.fa.md#حالت-تونل-کامل). این سند فقط راه‌اندازی را پوشش می‌دهد.

## پیش‌نیازها

نیازمندی‌ها:

- یک **حساب گوگل** (یک Gmail). هر حساب = ۳۰ request همزمان از تونل. می‌توانی بعداً با اضافه کردن حساب‌های بیشتر مقیاس را بالا ببری (گام ۶).
- یک **VPS** با IPv4 عمومی. هر providerی کار می‌کند. ارزان‌ترین tier کافی است — حدود ۳۰ مگابایت RAM، CPU baseline ندارد. پیشنهادها:
  - پیشنهاد **Hetzner CX22** (€۴–۵ در ماه، Falkenstein/Helsinki، ۲۰ ترابایت egress) — بهترین ارزش برای کاربران اروپا/خاورمیانه.
  - پیشنهاد **DigitalOcean basic droplet** (۶$ در ماه، NYC/SFO) — بهترین برای کاربران آمریکا.
  - برای **کاربران ایرانی**: اگر ISP تو IP این VPS را فیلتر کرده (از خانه نمی‌توانی `ping` بگیری)، از [Google Cloud Run](../tunnel-node/README.fa.md#cloud-run-پیشنهاد-برای-کاربران-ایرانی-متأثر-از-فیلتر-313) استفاده کن — destination IP خود گوگل می‌شود و برای ISP نامرئی است. ببین [#313](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313). بقیهٔ این راهنما (بخش Apps Script + config کلاینت) همچنان مفید است.
- نصب **rahgozar** روی دستگاهی که می‌خواهی از طریقش تونل بزنی. اگر هنوز نصب نکرده‌ای، [README اصلی](../README.md) را ببین.

وقتی provider از تو OS image می‌خواهد، **Ubuntu 22.04 LTS** یا **Debian 12** انتخاب کن — دستورات زیر فرض می‌کنند یکی از این‌هاست.

## گام ۱ — SSH به VPS

از terminal لپ‌تاپ:

```bash
ssh root@<VPS_IP>
```

به‌جای `<VPS_IP>` آدرس IPv4ای که provider به تو داده را بگذار. اگر provider به‌جای root یک کاربر non-root داده، از همان استفاده کن و دستورات بعد را با `sudo` prefix بزن.

## گام ۲ — نصب Docker و اجرای tunnel-node

هنوز در shell VPS هستی. سه دستور:

```bash
# A. نصب Docker (تک‌خطی Ubuntu/Debian)
curl -fsSL https://get.docker.com | sh

# B. دو secret تصادفی بساز. خروجی را جایی امن ذخیره کن —
#    در گام ۳ هر دو را داخل Apps Script paste می‌کنی.
echo "CLIENT_SECRET = $(openssl rand -hex 24)"
echo "TUNNEL_SECRET = $(openssl rand -hex 24)"

# C. اجرای tunnel-node. مقدار TUNNEL_SECRET از قسمت B را
#    به‌جای <TUNNEL_SECRET> در زیر paste کن.
docker run -d \
  --name rahgozar-tunnel \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TUNNEL_AUTH_KEY="<TUNNEL_SECRET>" \
  ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
```

طرح tagها: `:latest` آخرین release را دنبال می‌کند، `:1.8` آخرین 1.8.x را، `:1.8.0` نسخهٔ دقیق را pin می‌کند. اگر می‌خواهی upgradeها قابل پیش‌بینی باشد، در production یک tag مشخص pin کن. نسخه‌ها: <https://github.com/dazzling-no-more/rahgozar/releases>.

> این دو secret برای چه چیزهایی هستند:
> - مقدار **`CLIENT_SECRET`** اعتبارسنجی *کلاینت rahgozar تو* به *Apps Script* است.
> - مقدار **`TUNNEL_SECRET`** اعتبارسنجی *Apps Script* به *tunnel-node روی VPS تو* است.
> دو secret متفاوت برای دو leg متفاوت از زنجیره. با هم قاطی نکن.

### باز کردن firewall

اگر روی VPS تو `ufw` فعال است (DigitalOcean فعال می‌کند، Hetzner پیش‌فرض نه):

```bash
ufw allow 22/tcp     # SSH را حتماً باز نگه دار!
ufw allow 8080/tcp   # tunnel-node
ufw reload
```

علاوه بر این، بسیاری از cloud providerها یک **firewall مجزا در کنسول وب** خود دارند (DO Cloud Firewall، AWS Security Group، GCP VPC firewall). اگر داری، TCP/8080 را آنجا هم باز کن.

### تأیید دسترسی‌پذیری

از لپ‌تاپ خودت (**نه** از VPS — یک terminal دوم باز کن):

```bash
curl http://<VPS_IP>:8080/health
# خروجی مورد انتظار: ok
```

اگر `ok` نمی‌بینی یعنی firewall هنوز بلاک می‌کند — قبل از ادامه حلش کن.

## گام ۳ — دیپلوی CodeFull.gs به‌عنوان Apps Script Web App

حالا به مرورگر لپ‌تاپت برو. مقادیر `CLIENT_SECRET` و `TUNNEL_SECRET` از گام ۲ را دم دست داشته باش.

۱. باز کن <https://script.google.com> و با حساب گوگلی که می‌خواهی استفاده کنی sign in کن.

۲. کلیک کن روی **+ New project** (بالا سمت چپ).

۳. ادیتور با یک فایل placeholder `Code.gs` باز می‌شود. همه را انتخاب کن (Ctrl+A) و حذف کن.

۴. محتوای [`CodeFull.gs`](../assets/apps_script/CodeFull.gs) را بگیر:
   - در یک tab دیگر باز کن <https://github.com/dazzling-no-more/rahgozar/blob/main/assets/apps_script/CodeFull.gs>
   - روی دکمهٔ **"Copy raw file"** کلیک کن (آیکن clipboard بالا سمت راست نمای فایل). این کل محتوای فایل را در clipboard می‌گذارد.
   - میان‌بر: اگر شبکه‌ات به `raw.githubusercontent.com` می‌رسد، می‌توانی مستقیماً <https://raw.githubusercontent.com/dazzling-no-more/rahgozar/main/assets/apps_script/CodeFull.gs> را باز کنی، همه را انتخاب و کپی کنی.

۵. در ادیتور خالی Apps Script paste کن (Ctrl+V).

۶. نزدیک بالای فایل این سه خط را پیدا کن:

   ```js
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   const TUNNEL_SERVER_URL = "https://YOUR_TUNNEL_NODE_URL";
   const TUNNEL_AUTH_KEY = "YOUR_TUNNEL_AUTH_KEY";
   ```

   تبدیلشان کن به:

   ```js
   const AUTH_KEY = "<CLIENT_SECRET از گام ۲>";
   const TUNNEL_SERVER_URL = "http://<VPS_IP>:8080";
   const TUNNEL_AUTH_KEY = "<TUNNEL_SECRET از گام ۲>";
   ```

۷. نام پروژه را عوض کن: روی **"Untitled project"** در بالای صفحه کلیک کن، تایپ کن `rahgozar` (یا هر اسمی)، Enter.

۸. ذخیره: **Ctrl+S** (یا روی آیکن floppy کلیک کن).

۹. کلیک کن **Deploy** (دکمهٔ آبی بالا سمت راست) → **New deployment**.

۱۰. روی **آیکن چرخ‌دنده** کنار "Select type" کلیک کن → **Web app** را انتخاب کن.

۱۱. پر کن:
    - مقدار **Description**: `rahgozar` (هر چی)
    - گزینهٔ **Execute as**: **Me** (ایمیل خودت)
    - گزینهٔ **Who has access**: **Anyone** ← مهم، باید "Anyone" باشد، نه "Anyone with a Google account"

۱۲. کلیک کن **Deploy**.

۱۳. گوگل از تو می‌خواهد **authorize** کنی. چون این یک اپ verified-نشده است، هشدارهای ترسناک می‌بینی:
    - کلیک کن **Authorize access** → حسابت را انتخاب کن
    - پیام "Google hasn't verified this app" → کلیک کن **Advanced** → **Go to rahgozar (unsafe)** → **Allow**

    این هشدار برای هر پروژهٔ شخصی Apps Script طبیعی است. کد فقط درون حساب خودت اجرا می‌شود.

۱۴. یک **Deployment ID** می‌بینی که شبیه `AKfycbz...` است (حدود ۵۰ کاراکتر). آن را **کپی کن.** در گام ۴ داخل config کلاینت paste می‌کنی.

این حساب تمام شد. *اگر فقط یک حساب می‌خواهی، برو گام ۴.* برای scale بعداً، [گام ۶](#گام-۶--اضافه-کردن-حسابهای-بیشتر-اختیاری) را ببین.

## گام ۴ — تنظیم کلاینت rahgozar

روی دستگاهی که می‌خواهی از طریقش تونل بزنی، فایل `config.json` rahgozar را ویرایش کن. حداقل config (دسکتاپ):

```json
{
  "mode": "full",
  "script_id": "<Deployment ID از گام ۳>",
  "auth_key": "<CLIENT_SECRET از گام ۲>",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086
}
```

سه خط `listen_host`/`listen_port`/`socks5_port` لازم نیستند — مقادیر پیش‌فرض `0.0.0.0:8085` (HTTP) و `8086` (SOCKS5) هستند. بستن به `127.0.0.1` proxy را فقط روی localhost قابل دسترسی می‌کند تا دستگاه‌های دیگر روی LAN تو اتفاقی از آن استفاده نکنند. اگر *می‌خواهی* روی LAN share شود (مثلاً تونل را از دسکتاپ به گوشی share کنی)، `0.0.0.0` را نگه دار و این سه خط را skip کن — ببین [اشتراک‌گذاری از طریق هات‌اسپات](guide.fa.md#اشتراک‌گذاری-هات‌اسپات).

نگاشت کلیدها:

| مکان | نام متغیر | مقدار |
|---|---|---|
| روی VPS (`docker run -e ...`) | `TUNNEL_AUTH_KEY` | TUNNEL_SECRET |
| فایل CodeFull.gs خط ۱۷ | `TUNNEL_AUTH_KEY` | TUNNEL_SECRET (همان) |
| فایل CodeFull.gs خط ۱۵ | `AUTH_KEY` | CLIENT_SECRET |
| فایل config.json rahgozar | `auth_key` | CLIENT_SECRET (همان) |
| فایل CodeFull.gs خط ۱۶ | `TUNNEL_SERVER_URL` | `http://<VPS_IP>:8080` |
| فایل config.json rahgozar | `script_id` | Apps Script Deployment ID |

محل فایل config بسته به پلتفرم متفاوت است:

- روی **Linux/macOS/Windows دسکتاپ**: با `--config /path/to/config.json` در خط فرمان بده، یا کنار باینری بگذار.
- روی **اندروید**: اپ را باز کن و فیلدهای GUI را پر کن (Mode = Full، Script ID، Auth Key). فیلدهای listen-host/port بالا روی اندروید کاربرد ندارند — VpnService بدون proxy port محلی ترافیک را route می‌کند.

schema کامل و همهٔ فیلدها در [`config.full.example.json`](../config.full.example.json) موجود است.

## گام ۵ — تست کن

rahgozar را start کن. لاگ باید چیزی شبیه این نشان دهد:

```
INFO mode=full script_ids=1
INFO Apps Script reachable, deployment_id=AKfycbz...
INFO HTTP proxy : 127.0.0.1:8085
INFO SOCKS5 proxy: 127.0.0.1:8086
```

سپس مرورگر را به proxy rahgozar وصل کن (HTTP `127.0.0.1:8085` یا SOCKS5 `127.0.0.1:8086`) و هر سایتی باز کن. اولین request حدود ۲ ثانیه طول می‌کشد (مسیر سرد Apps Script)؛ بعدی‌ها سریع‌ترند.

تست سریع بدون مرورگر:

```bash
# از لپ‌تاپ:
curl -x http://127.0.0.1:8085 https://api.ipify.org
# انتظار: یک IP که متعلق به provider VPS تو است (نه IP واقعی تو)
```

اگر IP provider VPS را دیدی، **تونل کار می‌کند**. end-to-end.

## گام ۶ — اضافه کردن حساب‌های بیشتر (اختیاری)

یک حساب گوگل = ۳۰ request همزمان. برای استفادهٔ سنگین، حساب‌های بیشتر اضافه کن:

۱. از گوگل sign out کن، با یک حساب دوم sign in کن (یا از یک browser profile جدا استفاده کن).

۲. کل **گام ۳** را تکرار کن (همان CodeFull.gs، همان `CLIENT_SECRET`، همان `TUNNEL_SERVER_URL`، همان `TUNNEL_SECRET` را paste کن). سه constant در همهٔ حساب‌ها یکسان می‌مانند؛ فقط Deployment ID عوض می‌شود.

۳. Deployment ID جدید را کپی کن.

۴. در `config.json` به‌روز کن — `script_id` به array تبدیل می‌شود:

   ```json
   {
     "mode": "full",
     "script_id": ["AKfyc...1", "AKfyc...2", "AKfyc...3"],
     "auth_key": "<CLIENT_SECRET>"
   }
   ```

برآورد ابعاد: ۱-۲ حساب برای استفادهٔ تنها / browsing، ۳-۶ حساب برای اشتراکی یا استفادهٔ سنگین، تا ۱۲ برای power user. ببین [guide.fa.md → تأثیر تعداد Deployment](guide.fa.md#تأثیر-تعداد-deployment).

## به‌روزرسانی tunnel-node بعداً

روی VPS:

```bash
docker pull ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
docker rm -f rahgozar-tunnel
docker run -d --name rahgozar-tunnel --restart unless-stopped \
  -p 8080:8080 -e TUNNEL_AUTH_KEY="<TUNNEL_SECRET>" \
  ghcr.io/dazzling-no-more/rahgozar-tunnel-node:latest
```

اگر می‌خواهی upgrade پایدار داشته باشی، به‌جای `:latest` یک tag مشخص (مثل `:1.8.0`) pin کن. نسخه‌ها: <https://github.com/dazzling-no-more/rahgozar/releases>.

## رفع اشکال

| علامت | علت / رفع |
|---|---|
| دستور `curl http://<VPS_IP>:8080/health` معلق می‌ماند | firewall سمت provider پورت ۸۰۸۰ را بلاک کرده — در کنسول وب provider بازش کن (فقط `ufw` کافی نیست) |
| پاسخ `curl /health` → `Connection refused` | کانتینر بالا نیست. روی VPS: `docker ps` (باید `rahgozar-tunnel` را نشان دهد)؛ برای خطاها `docker logs rahgozar-tunnel` |
| کلاینت وصل می‌شود اما همهٔ requestها با `unauthorized` / `502` خطا می‌دهند | یکی از دو secret match نمی‌کند. چک کن: `CLIENT_SECRET` بین `auth_key` در config.json و `AUTH_KEY` در CodeFull.gs یکسان است؛ `TUNNEL_SECRET` بین `docker run -e TUNNEL_AUTH_KEY=` و `TUNNEL_AUTH_KEY` در CodeFull.gs یکسان است |
| کلاینت گزارش می‌دهد `script_id ... not deployed` | بعد از ویرایش CodeFull.gs publish را فراموش کردی. **Deploy → Manage deployments → ✏️ edit → New version → Deploy** |
| تونل کار می‌کند اما ChatGPT / Claude / Grok / x.com چالش CAPTCHA می‌دهند | طبیعی است — این سایت‌ها IPهای دیتاسنتر گوگل را block می‌کنند. یک [exit node](../assets/exit_node/README.fa.md) دیپلوی کن (۵ دقیقه، free tier) |
| دستور `curl /health` از لپ‌تاپ تو کار می‌کند، اما rahgozar هنوز به Apps Script نمی‌رسد | ISP تو کل Google Apps Script را فیلتر کرده. برای ترافیک گوگل از [direct mode](guide.fa.md#حالت-direct) استفاده کن، یا tunnel-node را به [Cloud Run](../tunnel-node/README.fa.md#cloud-run-پیشنهاد-برای-کاربران-ایرانی-متأثر-از-فیلتر-313) منتقل کن |
| می‌خواهی به‌جای decoy 404 خطای صریح ببینی | روی env کانتینر **موقتاً** `MHRV_DIAGNOSTIC=1` بگذار (`-e MHRV_DIAGNOSTIC=1`). قبل از share عمومی خاموش کن |

## HTTP در برابر HTTPS برای tunnel-node

روش `http://<VPS_IP>:8080` بالا مسیر ساده است و اکثر کاربران با همین شروع می‌کنند — اما یک trade-off واقعی دارد که قبل از تصمیم خوب است بدانی.

چیزی که HTTP افشا می‌کند: leg بین Apps Script و tunnel-node به‌صورت plaintext از روی اینترنت عمومی عبور می‌کند. هر کسی که روی این مسیر دید دارد (زیرساخت outbound گوگل، ISPهای transit، شبکهٔ provider VPS تو، هر کسی با packet capture روی VPS) می‌تواند ببیند:

- مقدار `TUNNEL_AUTH_KEY` (که در body هر request می‌رود)
- نام‌های host و payload requestها که تونل به نیابت از تو fetch می‌کند

leg سمت کاربر (دستگاه تو → Apps Script) همچنان TLS-به-گوگل است و domain-fronted می‌ماند. ویژگی دور زدن سانسور بی‌تأثیر است. آنچه در معرض ریسک است **سرّی بودن tunnel auth key و محتوای requestها** در برابر ناظرهای مسیر شبکه است.

برای اکثر کاربران (استفادهٔ شخصی، browsing کم-اهمیت) plaintext قابل قبول است. برای deployهای اشتراکی، ترافیک حساس، یا هر کس که سرّی بودن قوی‌تر end-to-end می‌خواهد، HTTPS را جلوی tunnel-node اجرا کن.

### اضافه کردن HTTPS با Caddy

اگر دامنه‌ای داری که به VPS اشاره می‌کند، [Caddy](https://caddyserver.com/) ساده‌ترین گزینه است — خودکار گواهی Let's Encrypt می‌گیرد:

```caddy
tunnel.your-domain.com {
    reverse_proxy localhost:8080
}
```

سپس:

۱. مقدار `TUNNEL_SERVER_URL` در CodeFull.gs را به `https://tunnel.your-domain.com` تغییر بده (و script را re-deploy کن).

۲. tunnel-node را فقط روی localhost bind کن تا مستقیماً قابل دسترسی نباشد: flag `-p 8080:8080` را به `-p 127.0.0.1:8080:8080` تغییر بده و کانتینر را recreate کن.

۳. روی firewall public پورت ۸۰۸۰ را ببند — فقط ۸۰/۴۴۳ برای Caddy باز بمانند.

## مرجع

- مرجع [tunnel-node/README.fa.md](../tunnel-node/README.fa.md) — جزئیات پروتکل، دیپلوی Cloud Run، docker-compose، بیلد از سورس
- راهنمای [guide.fa.md → حالت تونل کامل](guide.fa.md#حالت-تونل-کامل) — معماری، ویژگی‌های performance، ریاضی scale با deployment
- مرجع [assets/apps_script/README.md](../assets/apps_script/README.md) — دربارهٔ سه variant از .gs (Code.gs vs CodeFull.gs vs Code.cfw.gs)

</div>
