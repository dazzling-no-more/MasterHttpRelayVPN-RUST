<!-- Per-paragraph rule: each Persian line/bullet must start with a Persian
     character so markdown's per-paragraph direction auto-detection renders
     RTL correctly, even inside the dir="rtl" wrapper. -->
<div dir="rtl">

# حالت Drive — راه‌اندازی کلاینت OAuth شخصی (BYO)

> *English: [drive_oauth_setup.md](./drive_oauth_setup.md)*

حالت Drive از طرف تو با گوگل درایو ارتباط می‌گیرد. گوگل برای این نوع
دسترسی، یک **OAuth client** می‌خواهد که خودت (کاربر) در Google Cloud
Console خودت ثبتش کنی.

rahgozar **هیچ OAuth client از پیش‌ساخته‌ای** درون باینری ندارد. هر کاربر
کلاینت خودش را می‌سازد و دو مقدار حاصل — `client_id` و `client_secret` —
را در صفحهٔ راه‌اندازی Drive چسبانده می‌گذارد.

این یک کار یک‌بار، حدود ۱۰‌دقیقه‌ای است. وقتی انجام شد، حالت Drive برای
تو و افرادی که آن OAuth client را با آن‌ها به‌اشتراک می‌گذاری برای همیشه
کار می‌کند (تا ۱۰۰ کاربر، [چرا BYO؟](#چرا-byo) را در پایین ببین).

---

## گام ۰ — چه چیزی لازم داری

- یک حساب گوگل. همان حسابی که قرار است پوشهٔ صندوق پستی رمز‌شده روی
  درایوش بنشیند راحت‌ترین گزینه است.
- یک مرورگر وب که با همان حساب گوگل وارد شده باشی.
- پنج تا ده دقیقه.

این‌ها لازم **نیست**:

- حساب پولی Google Cloud. هر چه در این سند هست در free-tier است.
- دامنه یا صفحهٔ اصلی. scope OAuth حالت Drive یعنی `drive.file` — فرآیند
  بررسی گوگل تا زمان verification کامل (که اکثر کاربران لازمش ندارند)
  از تو URL سیاست حریم‌خصوصی نمی‌خواهد.
- هیچ تغییر در کد. credentialها در زمان اجرا در صفحهٔ راه‌اندازی
  rahgozar چسبانده می‌شوند.

---

## گام ۱ — ساخت پروژهٔ Google Cloud

۱. باز کن: <https://console.cloud.google.com/>.
۲. در نوار بالا روی picker پروژه کلیک کن (پروژهٔ فعلی یا «Select a
   project» را نشان می‌دهد).
۳. در دیالوگ روی **New project** کلیک کن.
۴. نام پروژه: هر چیزی (مثلاً `rahgozar-drive`). Organization / location
   را روی پیش‌فرض رها کن.
۵. روی **Create** بزن و حدود ۱۰ ثانیه صبر کن. picker باید خودکار به
   پروژهٔ جدید بپرد؛ اگر نپرید دستی انتخاب کن.

---

## گام ۲ — فعال‌سازی Drive API

۱. با پروژهٔ تازه‌ساخته انتخاب‌شده، باز کن:
   <https://console.cloud.google.com/apis/library/drive.googleapis.com>.
۲. روی **Enable** کلیک کن.
۳. منتظر تأیید "API enabled" بمان. اینجا چیز دیگری برای کلیک‌کردن
   نیست.

---

## گام ۳ — تنظیم OAuth consent screen

این صفحه‌ای است که کاربر هنگام اولین ورود می‌بیند.

۱. باز کن: <https://console.cloud.google.com/auth/branding>.
۲. **External** را انتخاب کن (Internal مخصوص سازمان‌های Google
   Workspace است).
۳. فیلدهای الزامی را پر کن:
   - **App name**: هر چیز (مثلاً `rahgozar-drive` یا اسم کوتاهی — این
     فقط به *خودت* در ورود نشان داده می‌شود، باید قابل‌تشخیص باشد).
   - **User support email**: ایمیل Gmail خودت.
   - **Developer contact information**: ایمیل Gmail خودت.
۴. ذخیره و ادامه. مرحلهٔ "Scopes" را رد کن — `drive.file` یک scope
   غیرحساس است که هنگام ساخت client در گام ۴ خودکار اضافه می‌شود.
۵. در مرحلهٔ "Test users"، **ایمیل Gmail خودت را به‌عنوان test user
   اضافه کن**. بدون این، ورود خودت با خطای «Access blocked — this app
   is being tested» مسدود می‌شود. اگر می‌خواهی به دیگران هم اجازه دهی
   از این client استفاده کنند، ایمیل‌شان را هم اینجا اضافه کن (مجموعاً
   تا ۱۰۰ نفر).
۶. ذخیره و ادامه، بعد **Back to dashboard**.
۷. داشبورد می‌گوید **Publishing status: Testing**. این درست است.
   تفاوت Testing و Production در [چرا BYO؟](#چرا-byo) توضیح داده شده
   است.

---

## گام ۴ — ساخت OAuth client

۱. باز کن: <https://console.cloud.google.com/apis/credentials>.
۲. نوار بالا: **+ Create credentials** → **OAuth client ID**.
۳. **Application type**:
   - برای دسکتاپ: **Desktop app**.
   - برای اندروید یا ریلی VPS با device-code: **TVs and Limited Input devices**.
۴. نام: هر چیز واضح (مثلاً `rahgozar-desktop` یا `rahgozar-device-code`).
۵. **Create** را بزن.
۶. یک دیالوگ با دو مقدار باز می‌شود. **هر دو را کپی کن.** این‌ها همان
   چیزی است که در rahgozar می‌چسبانی:
   - **Client ID** — به `.apps.googleusercontent.com` ختم می‌شود
   - **Client secret** — با `GOCSPX-` شروع می‌شود

   این دو را هر وقت بخواهی می‌توانی از فهرست Credentials دوباره ببینی،
   پس نگران بستن دیالوگ نباش. دکمهٔ download-JSON اختیاری است؛ همان
   دو رشته تنها چیزی است که rahgozar نیاز دارد.

---

## گام ۵ — چسباندن در rahgozar

### دسکتاپ (Tauri UI)

۱. rahgozar را باز کن، مد را روی **Drive** بگذار.
۲. به بخش راه‌اندازی Drive اسکرول کن.
۳. در بالای بخش، OAuth client نوع **Desktop app** را بچسبان:
   - **Client ID** — همان مقدار `…apps.googleusercontent.com`.
   - **Client secret** — همان مقدار `GOCSPX-…`.
۴. کانفیگ را **Save** کن. تا قبل از Save، دکمهٔ «Sign in with Google»
   غیرفعال می‌ماند.
۵. حالا روی **Sign in with Google** کلیک کن. مرورگر باز می‌شود،
   حسابت را انتخاب می‌کنی، اگر گوگل اخطار «Google hasn't verified this
   app» نشان داد روی Continue بزن ([چرا BYO؟](#چرا-byo) را ببین)، و
   rahgozar «Signed in» را نمایش می‌دهد.

### اندروید

۱. همان صفحهٔ راه‌اندازی Drive، همان دو فیلد بالا. OAuth client نوع
   **TVs and Limited Input devices** را بچسبان، نه Desktop app.
۲. کانفیگ را Save کن (دکمهٔ Save در نوار ابزار).
۳. روی **Sign in with Google** بزن. rahgozar یک device code و URL
   تأیید گوگل نشان می‌دهد.
۴. URL را در مرورگر باز کن، code را وارد کن و دسترسی را تأیید کن.
   rahgozar در پس‌زمینه poll می‌کند و بعد «Signed in» را نشان می‌دهد.

### ریلی VPS (`rahgozar-drive-relay`)

ریلی هم از device-code استفاده می‌کند؛ پس credentialهای OAuth client
نوع **TVs and Limited Input devices** را به subcommand `device-code` بده:

```bash
rahgozar-drive-relay oauth device-code \
  --client-id     "<client_id خودت>" \
  --client-secret "<client_secret خودت>" \
  --out /etc/rahgozar-drive-relay/config.json
```

یا قبل از اجرا environment variable ست کن:

```bash
export RAHGOZAR_OAUTH_CLIENT_ID="<client_id خودت>"
export RAHGOZAR_OAUTH_CLIENT_SECRET="<client_secret خودت>"
rahgozar-drive-relay oauth device-code --out /etc/rahgozar-drive-relay/config.json
```

ریلی سپس یک `user_code` و یک URL چاپ می‌کند. URL را در هر مرورگری باز
کن، کد را وارد کن، و `config.json` ریلی با هر سه مقدار به‌روز می‌شود
(`oauth_client_id` + `oauth_client_secret` + `oauth_refresh_token`).

همهٔ این clientها را داخل همان Google Cloud project و همان consent screen
بساز تا فهرست test userها، فعال بودن Drive API، و هویت app برای
`drive.file` مشترک بماند. کلاینت دسکتاپ را در یک project و کلاینت
اندروید/ریلی را در project دیگری نساز: دسترسی `drive.file` به همان
app/projectی محدود است که فایل‌ها را ساخته یا باز کرده، و جدا کردن
projectها می‌تواند باعث شود ریلی و کلاینت فایل‌های mailbox همدیگر را
نبینند؛ حتی اگر حساب گوگل و folder ID یکی باشد.

---

## چرا BYO؟

گوگل OAuth client در حالت **Testing** را به **۱۰۰ test user
دستی‌اضافه‌شده** محدود می‌کند. اپ‌هایی که به **Production** منتشر می‌شوند
بدون عبور از verification، اخطار زرد «Google hasn't verified this app»
را نشان می‌دهند و روی scopeهای حساس مثل `drive.file` به **۱۰۰ کاربر
authorise‌شده در طول حیات** محدود می‌شوند.

verification کامل هر دو را برمی‌دارد، اما یک فرآیند بررسی چندهفته‌ای است
که گوگل اخیراً برای اپ‌های شبیه proxy/tunnel سخت‌گیرتر شده است.

اگر rahgozar یک OAuth client مشترک می‌فرستاد، آن client خیلی زود به ۱۰۰
کاربر می‌رسید و برای همه از کار می‌افتاد. BYO کاملاً این را حل می‌کند:
هر کاربر سهمیهٔ ۱۰۰ کاربری خودش را دارد که احتمالاً هیچ‌وقت پر نمی‌شود.

«client secret» که گوگل به تو می‌دهد برای اپ‌های installed **در واقع
سری نیست** — RFC 8252 §8.6 این را تأیید می‌کند. زوج client_id +
client_secret را مثل یک شناسهٔ پوشهٔ شخصی Drive ببین: عمومی نیست، اما
لو رفتنش هم فاجعه نیست. این زوج فقط دسترسی به **فایل‌هایی که این
OAuth client مشخص در Drive تو ساخته** را می‌دهد (scope `drive.file`) —
نه به کل Drive، نه ایمیل، نه عکس‌ها.

---

## مشکلات رایج

«Access blocked — this app is being tested» هنگام ورود.

گام ۳.۵ را رد کرده‌ای — اضافه‌کردن Gmail خودت به‌عنوان test user. باز
کن <https://console.cloud.google.com/auth/audience>، به "Test users"
اسکرول کن، روی **+ Add users** بزن، ایمیلی که در صفحهٔ مسدودشده نشان
می‌دهد را بچسبان، ذخیره کن. دوباره ورود را امتحان کن.

اخطار «Google hasn't verified this app» هنگام ورود.

برای یک client تأیید‌نشده در وضعیت Production انتظار می‌رود، یا اگر
client تو از تنظیمات consent-screen به Production منتشر شده باشد. روی
**Advanced → Go to \<app name\> (unsafe)** کلیک کن. این اخطار در هر
ورود تکرار می‌شود — برای یک اپ تأیید‌نشده طبیعی است و روی کارکرد
تأثیری ندارد.

خطای `invalid_client` بعد از تلاش ورود.

client_id یا client_secret که در rahgozar چسبانده‌ای با چیزی که در
Google Cloud Console هست مطابقت ندارد. دوباره کنترل کن که هر دو را
کامل کپی کرده‌ای (client secretها بلندند) و در ابتدا یا انتها فاصلهٔ
سفید نباشد. نوع client را هم چک کن: دسکتاپ به **Desktop app** نیاز
دارد، اما اندروید و `rahgozar-drive-relay oauth device-code` به
**TVs and Limited Input devices** نیاز دارند. کانفیگ rahgozar را ذخیره
کن و دوباره امتحان کن.

خطای `access_denied`.

روی "Cancel" زده‌ای یا پنجرهٔ مرورگر را در حین ورود بسته‌ای. کافی است
دوباره «Sign in with Google» را بزنی.

«This app is blocked» — `disallowed_useragent`.

روی بعضی WebViewهای embedded اتفاق می‌افتد. rahgozar از مرورگر سیستم
استفاده می‌کند، نه WebView، پس نباید این را ببینی. اگر دیدی bug را
گزارش کن.

---

## چرخش credentialها

اگر زمانی `client_secret` تو لو رفت (مثلاً در یک اسکرین‌شات عمومی
گذاشتی)، باز کن
<https://console.cloud.google.com/apis/credentials>، روی client کلیک
کن، **Reset secret** بزن، secret جدید را در صفحهٔ راه‌اندازی rahgozar
بچسبان، ذخیره کن، و Drive را دوباره link کن (دوباره Sign in بزن —
refresh tokenی که با secret قدیمی صادر شده تا revoke نشود کار می‌کند،
اما چرخش هر دو نیمه تمیزترین کار است).

می‌توانی client را به‌طور کلی از صفحهٔ Credentials حذف کنی اگر
می‌خواهی استفاده از حالت Drive را متوقف کنی و سهمیهٔ ۱۰۰ کاربری را
آزاد کنی.

</div>
