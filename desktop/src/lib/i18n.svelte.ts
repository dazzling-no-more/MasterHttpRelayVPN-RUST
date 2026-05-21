// Internationalization for the desktop UI.
//
// Two responsibilities:
//   1. Hold the current language as a Svelte 5 rune so every consumer
//      of `t(...)` automatically re-renders on a language switch.
//   2. Look up keys in an English / Persian dictionary; English is
//      authoritative + complete, Persian fills in progressively. A
//      missing Persian entry transparently falls back to the English
//      string (graceful degradation while the table is being filled).
//
// File suffix `.svelte.ts` opts into Svelte 5's rune compilation at
// module scope — without it, `$state` outside a component triggers a
// build error.

export type Lang = "en" | "fa";

const STORAGE_KEY = "rahgozar:lang";

function loadInitialLang(): Lang {
  // Tauri webviews persist localStorage between launches, so a once-
  // set preference survives across app starts.
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "fa" || stored === "en") return stored;
  } catch {
    // localStorage can throw in sandboxed contexts — fall through to
    // the English default.
  }
  return "en";
}

// Module-scope rune. Components that read `i18n.lang` re-render on
// change; we expose it through a getter rather than as a bare export
// so consumers always see the live value.
let _lang = $state<Lang>(loadInitialLang());

export const i18n = {
  get lang(): Lang {
    return _lang;
  },
  set(next: Lang): void {
    _lang = next;
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* swallow — preference just won't persist this session */
    }
  },
  /** True for languages that render right-to-left. */
  get isRtl(): boolean {
    return _lang === "fa";
  },
};

/**
 * Translate a key. English values come from `EN`; Persian from `FA`.
 * Unknown key returns the key itself so missing translations are loud
 * during development. Persian key with no entry falls back to English.
 */
export function t(key: string): string {
  if (_lang === "fa") {
    const v = FA[key];
    if (v != null) return v;
  }
  return EN[key] ?? key;
}

// ── Dictionaries ────────────────────────────────────────────────────
//
// One source-of-truth list of keys, kept in EN. Adding a key: add to EN
// first, then mirror to FA (or leave it out — the fallback handles it).
// Keys are dotted paths grouped by surface area for grep-ability.

const EN: Record<string, string> = {
  // ── App chrome ────────────────────────────────────────────────────
  "app.name": "rahgozar",
  "app.tagline": "DPI bypass via Google Apps Script relay with domain fronting.",
  "header.lang.en": "EN",
  "header.lang.fa": "FA",
  "header.theme.light": "Light",
  "header.theme.dark": "Dark",
  "header.theme.toggle_to_light": "Switch to light theme",
  "header.theme.toggle_to_dark": "Switch to dark theme",

  // ── Tabs ──────────────────────────────────────────────────────────
  "tab.status": "Status",
  "tab.tunnel": "Tunnel",
  "tab.logs": "Logs",
  "tab.advanced": "Advanced",
  "tab.about": "About",

  // ── Status tab ────────────────────────────────────────────────────
  "status.running": "Running",
  "status.stopped": "Stopped",
  "status.loading": "Loading…",
  "status.uptime": "Uptime",
  "status.start": "Start",
  "status.stop": "Stop",
  "status.action_failed": "Action failed:",
  "status.last_run_ended": "Last run ended with:",
  "status.test_relay": "Test relay",
  "status.test_relay_hover":
    "Send one request through the Apps Script relay and check the response — see Logs for details.",
  "status.test_running": "Testing relay…",
  "status.test_passed": "Relay test passed",
  "status.test_failed": "Relay test failed — check Logs",
  "status.scan_ips": "Scan Google IPs",
  "status.scan_ips_hover":
    "Probe known Google frontend IPs and report which are reachable — results stream to the Logs tab.",
  "status.scan_running": "Scanning Google IPs…",
  "status.scan_done": "Scan complete — see Logs",
  "status.scan_failed": "Scan failed — check Logs",

  // ── Usage Today card ──────────────────────────────────────────────
  "usage.heading": "Usage today (estimated)",
  "usage.help":
    "Apps Script relay calls counted against today's Pacific Time day. Resets at 00:00 PT — Google's free-tier quota cadence.",
  "usage.calls": "{calls} / {quota} calls",
  "usage.bytes": "{bytes} relayed",
  "usage.day_key": "Day: {date}",
  "usage.reset_in": "Resets in {duration}",
  "usage.dashboard_link": "View on Google",
  "usage.unavailable_direct":
    "Direct mode doesn't use the Apps Script relay — no quota to track.",

  // ── MITM CA card (Status tab) ─────────────────────────────────────
  "ca.heading": "MITM certificate",
  "ca.help":
    "rahgozar minted a local CA so it can decrypt + re-encrypt HTTPS on the way through the proxy. Install it into your OS trust store to avoid certificate warnings.",
  "ca.state.trusted": "Trusted",
  "ca.state.not_trusted": "Not installed",
  "ca.state.not_yet_minted": "Will be created on first Start",
  "ca.install": "Install CA",
  "ca.remove": "Remove CA",
  "ca.installing": "Installing…",
  "ca.removing": "Removing…",
  "ca.install_confirm_title": "Install MITM certificate?",
  "ca.install_confirm_body":
    "Click Install to trust the following CA system-wide. Your OS will likely prompt for admin / sudo. The fingerprint below is what you're agreeing to trust — verify before continuing.",
  "ca.confirm_cancel": "Cancel",
  "ca.confirm_install": "Install",
  "ca.subject_label": "Subject:",
  "ca.fingerprint_label": "SHA-256:",
  "ca.toast.installed": "CA installed.",
  "ca.toast.install_failed": "CA install failed: {error}",
  "ca.toast.removed": "{summary}",
  "ca.toast.remove_failed": "CA remove failed: {error}",

  // ── Updater ───────────────────────────────────────────────────────
  "update.available_title": "Update available",
  "update.available_body": "v{version} is ready to install.",
  "update.install": "Install & restart",
  "update.dismiss": "Later",
  "update.checking": "Checking for updates…",
  "update.up_to_date": "You're on the latest version.",
  "update.error": "Update check failed: {error}",
  "update.downloading": "Downloading v{version}…",
  "update.installed": "Installed v{version} — restarting…",
  "update.check_now": "Check for updates",
  "status.current_config": "Current config",
  "status.read_only_hint": "read-only · edit in Tunnel",
  "status.config_field.mode": "Mode",
  "status.config_field.listen": "Listen",
  "status.config_field.front_domain": "Front domain",
  "status.config_field.google_ip": "Google IP",
  "status.config_field.deployment_ids": "Deployment IDs",
  "status.config_field.log_level": "Log level",
  "status.deployment_ids.none": "(none)",
  "status.deployment_ids.count": "{n} configured",
  "status.socks5_chip": "(socks5 :{port})",
  "status.read_config_error": "Couldn't read config: {error}",

  // ── Tunnel tab ────────────────────────────────────────────────────
  "tunnel.loading_config": "Loading config…",
  "tunnel.section.mode": "Mode",
  "tunnel.mode.apps_script.label": "Apps Script relay",
  "tunnel.mode.apps_script.help":
    "DPI bypass via Apps Script relay (deployment IDs + auth key required).",
  "tunnel.mode.full.label": "Full tunnel (no cert)",
  "tunnel.mode.full.help":
    "All traffic end-to-end through Apps Script + a remote tunnel node. No MITM CA.",
  "tunnel.mode.direct.label": "Direct (SNI rewrite only)",
  "tunnel.mode.direct.help":
    "No relay — SNI-rewrite tunnel only (Google edge + any fronting groups). Useful as a bootstrap.",
  "tunnel.section.fronting_groups": "Fronting groups (CDN edges)",
  "tunnel.fronting.help":
    "Route specific domains through a CDN edge instead of the Apps Script relay. Pick a hostname known to live on the CDN (e.g. python.org → Fastly, react.dev → Vercel) and click Discover — we'll resolve it and pick the best IP.",
  "tunnel.fronting.discover_label": "Discover front",
  "tunnel.fronting.discover_placeholder": "hostname (e.g. python.org)",
  "tunnel.fronting.discover_btn": "Discover",
  "tunnel.fronting.discovering": "Discovering…",
  "tunnel.fronting.no_groups": "No fronting groups configured.",
  "tunnel.fronting.group_name": "Group name",
  "tunnel.fronting.group_ip": "Edge IP",
  "tunnel.fronting.group_sni": "SNI",
  "tunnel.fronting.group_domains": "Domains",
  "tunnel.fronting.domain_placeholder": "domain (e.g. python.org)",
  "tunnel.fronting.add_group": "+ Add group",
  "tunnel.fronting.add_domain": "+ Add domain",
  "tunnel.fronting.remove_group_aria": "Remove group {name}",
  "tunnel.fronting.remove_domain_aria": "Remove domain {n} from group {name}",
  "tunnel.fronting.save": "Save fronting groups",
  "tunnel.fronting.saving": "Saving…",
  "tunnel.fronting.saved": "Fronting groups saved",
  "tunnel.fronting.discover_failed": "Discover failed: {error}",
  "tunnel.fronting.discover_found":
    "Best IP {ip} ({n} reachable) — added new group",
  "tunnel.fronting.discover_none_reachable":
    "Resolved {hostname} but no IP probed reachable — try a different hostname",
  "tunnel.section.apps_script": "Apps Script relay",
  "tunnel.deployment_ids.label": "Deployment IDs",
  "tunnel.deployment_ids.help":
    "One ID per row. The proxy round-robins between them and sidelines any ID that hits its daily quota for 10 minutes before retrying.",
  "tunnel.deployment_ids.remove_aria": "Remove deployment ID {n}",
  "tunnel.deployment_ids.placeholder":
    "paste one or more IDs (newline / comma / space separated)",
  "tunnel.add": "+ Add",
  "tunnel.deployment_ids.tip_more": "Tip: add more IDs for round-robin with auto-failover.",
  "tunnel.deployment_ids.one_configured":
    "1 ID configured · add more for round-robin failover.",
  "tunnel.deployment_ids.many_configured":
    "{n} IDs — round-robin with auto-failover on quota.",
  "tunnel.auth_key.label": "Auth key",
  "tunnel.auth_key.help": "Same value as AUTH_KEY inside your Code.gs.",
  "tunnel.section.network": "Network",
  "tunnel.network.listen_host": "Listen host",
  "tunnel.network.http_port": "HTTP port",
  "tunnel.network.socks5_port": "SOCKS5 port",
  "tunnel.network.socks5_optional": "(optional)",
  "tunnel.network.log_level": "Log level",
  "tunnel.network.front_domain": "Front domain",
  "tunnel.network.google_ip": "Google IP",
  "tunnel.network.sni_pool_btn": "SNI pool ({active}/{total})",
  "sni.title": "SNI pool",
  "sni.help":
    "Outbound TLS handshakes to the Google edge rotate through this list of host names. Disabling a host removes it from the rotation; the proxy uses the remaining hosts.",
  "sni.col_enabled": "In rotation",
  "sni.col_host": "Host",
  "sni.col_probe": "Reachability",
  "sni.probe": "Probe",
  "sni.probing": "Probing…",
  "sni.probe_ok": "Reachable",
  "sni.probe_fail": "Unreachable",
  "sni.probe_idle": "Not probed",
  "sni.add_placeholder": "host (e.g. drive.google.com)",
  "sni.add": "+ Add",
  "sni.save": "Save",
  "sni.saving": "Saving…",
  "sni.saved": "SNI pool saved",
  "sni.remove_aria": "Remove host {host}",
  "sni.close": "Close",
  "tunnel.dirty": "Unsaved changes",
  "tunnel.saved": "Saved · changes take effect on next Start",
  "tunnel.in_sync": "In sync with config.json",
  "tunnel.save": "Save config",
  "tunnel.saving": "Saving…",
  "tunnel.revert": "Revert",

  // ── Logs tab ──────────────────────────────────────────────────────
  "logs.filter": "filter:",
  "logs.level.info": "INFO",
  "logs.level.warn": "WARN",
  "logs.level.error": "ERROR",
  "logs.level.other": "other",
  "logs.auto_scroll": "auto-scroll",
  "logs.copy": "Copy",
  "logs.clear": "Clear",
  "logs.copy_success": "Copied {n} lines",
  "logs.copy_failed": "Copy failed",
  "logs.empty":
    "(empty — start the proxy or wait for some tracing to come through)",
  "logs.all_filtered": "(all lines hidden by filter chips — toggle one back on above)",
  "logs.count": "{shown} / {total} lines",

  // ── Advanced tab ──────────────────────────────────────────────────
  "advanced.heading": "Raw config",
  "advanced.help":
    "Direct editor for config.json. Use this for fields the Tunnel form doesn't expose (fronting_groups, sni_hosts, custom tuning knobs, log colors). Changes take effect on next Start.",
  "advanced.loading": "Loading config.json…",
  "advanced.save": "Save",
  "advanced.saved": "config.json saved",
  "advanced.reset": "Reload from disk",

  // ── About tab ─────────────────────────────────────────────────────
  "about.heading_project": "Project",
  "about.link.source": "Source code",
  "about.link.releases": "Releases & changelog",
  "about.link.report_bug": "Report a bug",
  "about.link.suffix_github": "github",
  "about.license": "Licensed under MIT.",
  "about.font_credit": "Bundled font: Vazirmatn (SIL OFL).",
};

const FA: Record<string, string> = {
  // ── App chrome ────────────────────────────────────────────────────
  "app.name": "رهگذر",
  "app.tagline": "دور زدن سانسور با ریلی Google Apps Script و دامین فرانتینگ.",

  // ── Tabs ──────────────────────────────────────────────────────────
  "tab.status": "وضعیت",
  "tab.tunnel": "تونل",
  "tab.logs": "گزارش‌ها",
  "tab.advanced": "پیشرفته",
  "tab.about": "درباره",

  // ── Status tab ────────────────────────────────────────────────────
  "status.running": "در حال اجرا",
  "status.stopped": "متوقف",
  "status.loading": "در حال بارگذاری…",
  "status.uptime": "زمان فعالیت",
  "status.start": "شروع",
  "status.stop": "توقف",
  "status.action_failed": "اقدام ناموفق:",
  "status.last_run_ended": "اجرای قبلی پایان یافت با:",
  "status.test_relay": "آزمایش ریلی",
  "status.test_relay_hover":
    "یک درخواست از طریق ریلی Apps Script ارسال و پاسخ بررسی می‌شود — جزئیات در تب گزارش‌ها.",
  "status.test_running": "در حال آزمایش ریلی…",
  "status.test_passed": "آزمایش ریلی موفق بود",
  "status.test_failed": "آزمایش ریلی ناموفق بود — تب گزارش‌ها را ببینید",
  "status.scan_ips": "پویش آی‌پی‌های گوگل",
  "status.scan_ips_hover":
    "آی‌پی‌های شناخته‌شده فرانت‌اند گوگل را بررسی می‌کند و دسترسی هرکدام را گزارش می‌دهد — نتایج در تب گزارش‌ها.",
  "status.scan_running": "در حال پویش آی‌پی‌های گوگل…",
  "status.scan_done": "پویش کامل شد — تب گزارش‌ها را ببینید",
  "status.scan_failed": "پویش ناموفق بود — تب گزارش‌ها را ببینید",

  "usage.heading": "مصرف امروز (تقریبی)",
  "usage.help":
    "تعداد فراخوانی‌های ریلی Apps Script که در روز جاری (به وقت اقیانوس آرام) محاسبه شده‌اند. در ساعت ۰۰:۰۰ PT صفر می‌شود — هم‌گام با ریست سهمیه گوگل.",
  "usage.calls": "{calls} / {quota} فراخوانی",
  "usage.bytes": "{bytes} منتقل‌شده",
  "usage.day_key": "روز: {date}",
  "usage.reset_in": "صفر می‌شود در {duration}",
  "usage.dashboard_link": "مشاهده در گوگل",
  "usage.unavailable_direct":
    "حالت مستقیم از ریلی Apps Script استفاده نمی‌کند — سهمیه‌ای برای ردیابی وجود ندارد.",

  "ca.heading": "گواهی MITM",
  "ca.help":
    "رهگذر یک CA محلی ساخته تا بتواند HTTPS را در مسیر پراکسی رمزگشایی و دوباره رمزگذاری کند. برای جلوگیری از هشدارهای گواهی، آن را در trust store سیستم نصب کنید.",
  "ca.state.trusted": "نصب‌شده",
  "ca.state.not_trusted": "نصب نشده",
  "ca.state.not_yet_minted": "در اولین شروع ساخته خواهد شد",
  "ca.install": "نصب CA",
  "ca.remove": "حذف CA",
  "ca.installing": "در حال نصب…",
  "ca.removing": "در حال حذف…",
  "ca.install_confirm_title": "نصب گواهی MITM؟",
  "ca.install_confirm_body":
    "با کلیک روی نصب، گواهی زیر در سطح سیستم مورد اعتماد قرار می‌گیرد. سیستم‌عامل احتمالاً درخواست مجوز admin / sudo می‌کند. فینگرپرینت زیر همان چیزی است که می‌پذیرید — قبل از ادامه بررسی کنید.",
  "ca.confirm_cancel": "لغو",
  "ca.confirm_install": "نصب",
  "ca.subject_label": "موضوع:",
  "ca.fingerprint_label": "SHA-256:",
  "ca.toast.installed": "گواهی CA نصب شد.",
  "ca.toast.install_failed": "نصب CA ناموفق: {error}",
  "ca.toast.removed": "{summary}",
  "ca.toast.remove_failed": "حذف CA ناموفق: {error}",

  "update.available_title": "به‌روزرسانی موجود است",
  "update.available_body": "نسخه v{version} آماده نصب است.",
  "update.install": "نصب و راه‌اندازی مجدد",
  "update.dismiss": "بعداً",
  "update.checking": "در حال بررسی به‌روزرسانی…",
  "update.up_to_date": "شما در آخرین نسخه هستید.",
  "update.error": "بررسی به‌روزرسانی ناموفق: {error}",
  "update.downloading": "در حال دانلود v{version}…",
  "update.installed": "v{version} نصب شد — در حال راه‌اندازی مجدد…",
  "update.check_now": "بررسی به‌روزرسانی",
  "status.current_config": "تنظیمات فعلی",
  "status.read_only_hint": "فقط خواندنی · ویرایش در تب «تونل»",
  "status.config_field.mode": "حالت",
  "status.config_field.listen": "گوش‌دهنده",
  "status.config_field.front_domain": "دامنه فرانت",
  "status.config_field.google_ip": "آی‌پی گوگل",
  "status.config_field.deployment_ids": "شناسه‌های Deployment",
  "status.config_field.log_level": "سطح گزارش",
  "status.deployment_ids.none": "(هیچ‌کدام)",
  "status.deployment_ids.count": "{n} پیکربندی‌شده",
  "status.socks5_chip": "(SOCKS5 :{port})",
  "status.read_config_error": "خواندن تنظیمات ممکن نشد: {error}",

  // ── Tunnel tab ────────────────────────────────────────────────────
  "tunnel.loading_config": "در حال بارگذاری تنظیمات…",
  "tunnel.section.mode": "حالت",
  "tunnel.mode.apps_script.label": "ریلی Apps Script",
  "tunnel.mode.apps_script.help":
    "دور زدن DPI از طریق ریلی Apps Script (نیازمند شناسه‌های Deployment و کلید احراز).",
  "tunnel.mode.full.label": "تونل کامل (بدون گواهی)",
  "tunnel.mode.full.help":
    "تمام ترافیک از طریق Apps Script و یک گره تونل از راه دور. بدون نیاز به گواهی MITM.",
  "tunnel.mode.direct.label": "مستقیم (فقط بازنویسی SNI)",
  "tunnel.mode.direct.help":
    "بدون ریلی — فقط تونل بازنویسی SNI (لبه گوگل و گروه‌های فرانتینگ). برای راه‌اندازی اولیه مفید است.",
  "tunnel.section.fronting_groups": "گروه‌های فرانتینگ (لبه‌های CDN)",
  "tunnel.fronting.help":
    "هدایت دامنه‌های مشخص از طریق یک لبه CDN به جای ریلی Apps Script. یک hostname شناخته‌شده روی CDN انتخاب کنید (مثلاً python.org → Fastly، react.dev → Vercel) و روی کشف کلیک کنید — DNS resolve و انتخاب بهترین IP خودکار انجام می‌شود.",
  "tunnel.fronting.discover_label": "کشف فرانت",
  "tunnel.fronting.discover_placeholder": "hostname (مثلاً python.org)",
  "tunnel.fronting.discover_btn": "کشف",
  "tunnel.fronting.discovering": "در حال کشف…",
  "tunnel.fronting.no_groups": "هیچ گروه فرانتینگی پیکربندی نشده.",
  "tunnel.fronting.group_name": "نام گروه",
  "tunnel.fronting.group_ip": "IP لبه",
  "tunnel.fronting.group_sni": "SNI",
  "tunnel.fronting.group_domains": "دامنه‌ها",
  "tunnel.fronting.domain_placeholder": "دامنه (مثلاً python.org)",
  "tunnel.fronting.add_group": "+ افزودن گروه",
  "tunnel.fronting.add_domain": "+ افزودن دامنه",
  "tunnel.fronting.remove_group_aria": "حذف گروه {name}",
  "tunnel.fronting.remove_domain_aria": "حذف دامنه {n} از گروه {name}",
  "tunnel.fronting.save": "ذخیره گروه‌ها",
  "tunnel.fronting.saving": "در حال ذخیره…",
  "tunnel.fronting.saved": "گروه‌های فرانتینگ ذخیره شد",
  "tunnel.fronting.discover_failed": "کشف ناموفق: {error}",
  "tunnel.fronting.discover_found":
    "بهترین IP: {ip} ({n} قابل دسترس) — گروه جدید افزوده شد",
  "tunnel.fronting.discover_none_reachable":
    "{hostname} resolve شد اما هیچ IP قابل دسترسی نبود — یک hostname دیگر امتحان کنید",
  "tunnel.section.apps_script": "ریلی Apps Script",
  "tunnel.deployment_ids.label": "شناسه‌های Deployment",
  "tunnel.deployment_ids.help":
    "هر شناسه در یک ردیف. پراکسی بین آن‌ها چرخشی توزیع می‌کند و هر شناسه‌ای که به سقف سهمیه روزانه برسد ۱۰ دقیقه کنار گذاشته می‌شود.",
  "tunnel.deployment_ids.remove_aria": "حذف شناسه شماره {n}",
  "tunnel.deployment_ids.placeholder":
    "یک یا چند شناسه را وارد کنید (با خط جدید / کاما / فاصله)",
  "tunnel.add": "+ افزودن",
  "tunnel.deployment_ids.tip_more":
    "نکته: برای چرخش با تعویض خودکار، شناسه‌های بیشتری اضافه کنید.",
  "tunnel.deployment_ids.one_configured":
    "۱ شناسه پیکربندی شده · برای چرخش، تعداد بیشتری اضافه کنید.",
  "tunnel.deployment_ids.many_configured":
    "{n} شناسه — چرخش با تعویض خودکار در صورت اتمام سهمیه.",
  "tunnel.auth_key.label": "کلید احراز هویت",
  "tunnel.auth_key.help": "همان مقدار AUTH_KEY در Code.gs شما.",
  "tunnel.section.network": "شبکه",
  "tunnel.network.listen_host": "میزبان گوش‌دهنده",
  "tunnel.network.http_port": "پورت HTTP",
  "tunnel.network.socks5_port": "پورت SOCKS5",
  "tunnel.network.socks5_optional": "(اختیاری)",
  "tunnel.network.log_level": "سطح گزارش",
  "tunnel.network.front_domain": "دامنه فرانت",
  "tunnel.network.google_ip": "آی‌پی گوگل",
  "tunnel.network.sni_pool_btn": "استخر SNI ({active}/{total})",
  "sni.title": "استخر SNI",
  "sni.help":
    "ارتباطات TLS خروجی به لبه گوگل در این لیست از hostname‌ها چرخش می‌کند. غیرفعال کردن یک host آن را از چرخش حذف می‌کند؛ پراکسی از hostهای باقی‌مانده استفاده می‌کند.",
  "sni.col_enabled": "در چرخش",
  "sni.col_host": "Host",
  "sni.col_probe": "قابل دسترس بودن",
  "sni.probe": "بررسی",
  "sni.probing": "در حال بررسی…",
  "sni.probe_ok": "قابل دسترس",
  "sni.probe_fail": "غیرقابل دسترس",
  "sni.probe_idle": "بررسی نشده",
  "sni.add_placeholder": "host (مثلاً drive.google.com)",
  "sni.add": "+ افزودن",
  "sni.save": "ذخیره",
  "sni.saving": "در حال ذخیره…",
  "sni.saved": "استخر SNI ذخیره شد",
  "sni.remove_aria": "حذف host {host}",
  "sni.close": "بستن",
  "tunnel.dirty": "تغییرات ذخیره‌نشده",
  "tunnel.saved": "ذخیره شد · با شروع بعدی اعمال می‌شود",
  "tunnel.in_sync": "هماهنگ با config.json",
  "tunnel.save": "ذخیره تنظیمات",
  "tunnel.saving": "در حال ذخیره…",
  "tunnel.revert": "بازگرداندن",

  // ── Logs tab ──────────────────────────────────────────────────────
  "logs.filter": "فیلتر:",
  "logs.level.info": "INFO",
  "logs.level.warn": "WARN",
  "logs.level.error": "ERROR",
  "logs.level.other": "سایر",
  "logs.auto_scroll": "پیمایش خودکار",
  "logs.copy": "کپی",
  "logs.clear": "پاک‌سازی",
  "logs.copy_success": "{n} سطر کپی شد",
  "logs.copy_failed": "کپی ناموفق",
  "logs.empty": "(خالی — پراکسی را شروع کنید یا منتظر گزارش‌ها بمانید)",
  "logs.all_filtered":
    "(تمام سطرها با فیلترها پنهان شده‌اند — یکی از چیپ‌های بالا را روشن کنید)",
  "logs.count": "{shown} / {total} سطر",

  // ── Advanced tab ──────────────────────────────────────────────────
  "advanced.heading": "تنظیمات خام",
  "advanced.help":
    "ویرایشگر مستقیم config.json. برای فیلدهایی که فرم تونل پشتیبانی نمی‌کند (fronting_groups، sni_hosts، تنظیمات پیشرفته، رنگ‌های گزارش). تغییرات با شروع بعدی اعمال می‌شود.",
  "advanced.loading": "در حال بارگذاری config.json…",
  "advanced.save": "ذخیره",
  "advanced.saved": "config.json ذخیره شد",
  "advanced.reset": "بارگذاری مجدد از دیسک",

  // ── About tab ─────────────────────────────────────────────────────
  "about.heading_project": "پروژه",
  "about.link.source": "کد منبع",
  "about.link.releases": "نسخه‌ها و تغییرات",
  "about.link.report_bug": "گزارش اشکال",
  "about.link.suffix_github": "گیت‌هاب",
  "about.license": "تحت مجوز MIT منتشر شده.",
  "about.font_credit": "فونت یکپارچه: وزیرمتن (SIL OFL).",
};

/**
 * Substitute `{name}` placeholders in a translated string. Keeps the
 * substitution out of every call site (`t("foo.bar").replace(...)`)
 * and gives a single place to extend with pluralization rules later
 * if we need them.
 */
export function tn(key: string, params: Record<string, string | number>): string {
  let out = t(key);
  for (const [k, v] of Object.entries(params)) {
    out = out.replaceAll(`{${k}}`, String(v));
  }
  return out;
}
