// Interface text in English and Persian, and number formatting for each.
// Persian lines never start with a Latin word; names and codes are wrapped LTR by the views.

const en = {
  dash: "Dashboard", overview: "Overview", tunnels: "Tunnels", servers: "Servers", conntest: "Connection test",
  alerts: "Alerts", health: "Health check", maintenance: "Maintenance", settings: "Settings", login: "Sign in",
  phase: "Phase", ovSub: "Status of this server and its tunnels", tunSub: "Every tunnel on this server, its route and its traffic",
  demo: "Demo with sample data. Nothing on this page is real.",
  thisServer: "This server", cpu: "CPU", ram: "Memory", disk: "Disk", up: "Upload", down: "Download", uptime: "Uptime", days: "days",
  attn: (n) => (n === 1 ? "1 thing needs attention" : `${n} things need attention`),
  healthy: "All tunnels are healthy", noTunnelsHero: "No tunnels to watch yet",
  issue: {
    failed: "stopped with an error",
    not_connected: "is not connected to the other server",
    silent: "is connected, but nothing comes back from the other server. A filter may be blocking this transport.",
    no_traffic: "is connected, but its heartbeats get no answer",
    quota: "has used its traffic limit and is paused until the period ends",
    loss: (x) => `is losing ${x} of its heartbeats`,
  },
  note: {
    failed: "This tunnel stopped with an error.",
    not_connected: "Not connected to the other server.",
    silent: "Connected, but nothing comes back from the other server. A filter may be blocking this transport.",
    no_traffic: "Connected, but heartbeats get no answer.",
    quota: "The traffic limit is used up. The tunnel is paused until the period ends.",
  },
  openTunnels: "Open tunnels", kTunnels: "Tunnels running", of: "of", kRate: "Traffic now", kPing: "Average ping",
  traffic: "Traffic", trafficSub: "All tunnels on this server", recv: "Received", sent: "Sent",
  live: "Live", h24: "24 hours", d7: "7 days", d30: "30 days", rangeLabel: "Time range",
  peak: "Peak", low: "Low", avg: "Average", totalR: "Total", busiest: "Busiest day", dailyAvg: "Daily average",
  historyFrom: (date) => `History starts on ${date}.`, kToday: "Traffic today",
  upLine: (p) => `Up ${p} of the last 24 hours`, historyLoading: "Loading history…",
  historyError: "Could not load the history.", retry: "Try again", noHistory: "No history for this range yet",
  pause: "Pause", resume: "Resume", chartWait: "The chart fills in as data arrives",
  tunnelsList: "Tunnels", viewAll: "View all tunnels", name: "Tunnel", route: "Route", ping: "Ping", loss: "Loss",
  total: "Since start", state: "State",
  st: { running: "Running", starting: "Starting", stopped: "Stopped", failed: "Failed", none: "Not installed", unstable: "Unstable" },
  reverse: "Reverse", direct: "Direct", iran: "Iran end", foreign: "Foreign end", ports: "Ports", sessions: "Sessions",
  exits: "Exits to", socks: "SOCKS5", tun: "TUN",
  limit: "Traffic limit", left: "left", lastDrop: "Last disconnect:", unreadable: "Its settings file cannot be read:",
  loadingT: "Loading data from this server…",
  lostT: "Lost the connection to the dashboard", lostText: (time) => `Showing data from ${time}. Reconnecting…`,
  emptyT: "No tunnels on this server yet",
  emptyText: "Create a tunnel with the manager on this server. It shows up here within seconds.",
  soonT: "Coming in phase", backOv: "Back to overview",
  soonText: {
    servers: ["Connect other servers and manage their tunnels here.", "Easy connect: one command on the other server", "Server cards with load, version and tunnels", "Adding a server over SSH comes in phase 4"],
    conntest: ["Find which transports work between two servers, before you create a tunnel.", "Live results table with ping, speed, stability and packet loss", "A recommendation with the reason", "Create the tunnel straight from a result"],
    alerts: ["See what needs attention now, and what happened before.", "Active alerts and history, grouped by day", "Alert rules per tunnel and server", "Telegram alerts"],
    health: ["Check this server and every tunnel, with suggested fixes.", "System checks: time, congestion control, buffers, file limits", "Dashboard checks: port, certificate, firewall", "Per-tunnel checks: service, listeners, reachability, MTU"],
    maintenance: ["Keep every server up to date and backed up.", "Update and roll back each server", "Staged updates across servers", "Backup download, restore and weekly automatic backup"],
    settings: ["Manage access to this dashboard.", "Port, certificate and password", "Signed-in sessions", "Telegram and backup settings"],
  },
  pw: "Password", signin: "Sign in",
  pwNote: "The password was shown once when the dashboard was set up. To make a new one, run this on the server:",
  pwErr: "Enter the password", wrongPw: "That password is not correct",
  locked: (wait) => `Too many wrong passwords. Try again in ${wait}.`, signinFail: "Sign-in failed. Try again.",
  signout: "Sign out", lang: "فارسی", langName: "Language", theme: "Theme", dark: "Dark", light: "Light",
  menu: "Menu", closeMenu: "Close menu",
  minutes: (n) => (n === 1 ? "1 minute" : `${n} minutes`), seconds: (n) => (n === 1 ? "1 second" : `${n} seconds`),
  dur: (d, h, m) => (d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`),
};

const fa = {
  dash: "داشبورد", overview: "نمای کلی", tunnels: "تونل‌ها", servers: "سرورها", conntest: "تست اتصال",
  alerts: "هشدارها", health: "بررسی سلامت", maintenance: "نگهداری", settings: "تنظیمات", login: "ورود",
  phase: "فاز", ovSub: "وضعیت این سرور و تونل‌هایش", tunSub: "همه‌ی تونل‌های این سرور، مسیر و ترافیکشان",
  demo: "نسخه‌ی نمایشی با داده‌ی نمونه. هیچ‌چیز در این صفحه واقعی نیست.",
  thisServer: "همین سرور", cpu: "پردازنده", ram: "حافظه", disk: "دیسک", up: "ارسال", down: "دریافت", uptime: "زمان کارکرد", days: "روز",
  attn: (n) => `${num(n)} مورد نیاز به توجه دارد`,
  healthy: "همه‌ی تونل‌ها سالم‌اند", noTunnelsHero: "هنوز تونلی برای پایش نیست",
  issue: {
    failed: "با خطا متوقف شده است",
    not_connected: "به سرور مقابل وصل نیست",
    silent: "وصل است، اما از سرور مقابل چیزی برنمی‌گردد. ممکن است فیلترینگ جلوی این روش انتقال را گرفته باشد.",
    no_traffic: "وصل است، اما پیام‌های بررسی اتصالش بی‌پاسخ می‌مانند",
    quota: "سقف ترافیکش تمام شده است و تا پایان دوره متوقف می‌ماند",
    loss: (x) => `${x} از پیام‌های بررسی اتصالش را از دست می‌دهد`,
  },
  note: {
    failed: "این تونل با خطا متوقف شده است.",
    not_connected: "به سرور مقابل وصل نیست.",
    silent: "وصل است، اما از سرور مقابل چیزی برنمی‌گردد. ممکن است فیلترینگ جلوی این روش انتقال را گرفته باشد.",
    no_traffic: "وصل است، اما پیام‌های بررسی اتصال بی‌پاسخ می‌مانند.",
    quota: "سقف ترافیک تمام شده است و تونل تا پایان دوره متوقف می‌ماند.",
  },
  openTunnels: "باز کردن تونل‌ها", kTunnels: "تونل‌های فعال", of: "از", kRate: "ترافیک لحظه‌ای", kPing: "میانگین پینگ",
  traffic: "ترافیک", trafficSub: "همه‌ی تونل‌های این سرور", recv: "دریافت", sent: "ارسال",
  live: "زنده", h24: "۲۴ ساعت", d7: "۷ روز", d30: "۳۰ روز", rangeLabel: "بازه‌ی زمانی",
  peak: "بیشینه", low: "کمینه", avg: "میانگین", totalR: "مجموع", busiest: "پرترافیک‌ترین روز", dailyAvg: "میانگین روزانه",
  historyFrom: (date) => `تاریخچه از ${date} آغاز می‌شود.`, kToday: "ترافیک امروز",
  upLine: (p) => `در ۲۴ ساعت گذشته ${p} از زمان فعال بوده است`, historyLoading: "در حال دریافت تاریخچه…",
  historyError: "تاریخچه دریافت نشد.", retry: "تلاش دوباره", noHistory: "هنوز برای این بازه تاریخچه‌ای نیست",
  pause: "توقف نمایش", resume: "ادامه‌ی نمایش", chartWait: "نمودار با رسیدن داده‌ها کامل می‌شود",
  tunnelsList: "تونل‌ها", viewAll: "همه‌ی تونل‌ها", name: "تونل", route: "مسیر", ping: "پینگ", loss: "افت بسته",
  total: "از زمان شروع", state: "وضعیت",
  st: { running: "فعال", starting: "در حال شروع", stopped: "متوقف", failed: "خطا", none: "نصب‌نشده", unstable: "ناپایدار" },
  reverse: "معکوس", direct: "مستقیم", iran: "سمت ایران", foreign: "سمت خارج", ports: "پورت‌ها", sessions: "نشست‌ها",
  exits: "خروج به", socks: "پروکسی SOCKS5", tun: "شبکه‌ی TUN",
  limit: "سقف ترافیک", left: "باقی‌مانده", lastDrop: "آخرین قطعی:", unreadable: "فایل تنظیماتش خوانده نمی‌شود:",
  loadingT: "در حال دریافت اطلاعات این سرور…",
  lostT: "ارتباط با داشبورد قطع شده است", lostText: (time) => `اطلاعات ساعت ${time} نمایش داده می‌شود. در حال اتصال دوباره…`,
  emptyT: "هنوز تونلی روی این سرور نیست",
  emptyText: "با مدیر تونل روی همین سرور یک تونل بسازید. چند ثانیه بعد این‌جا دیده می‌شود.",
  soonT: "در فاز", backOv: "بازگشت به نمای کلی",
  soonText: {
    servers: ["سرورهای دیگر را وصل کنید و تونل‌هایشان را همین‌جا مدیریت کنید.", "اتصال آسان: یک دستور روی سرور دیگر", "کارت هر سرور با بار، نسخه و تونل‌ها", "افزودن سرور با SSH در فاز ۴"],
    conntest: ["پیش از ساخت تونل ببینید کدام روش‌ها بین دو سرور کار می‌کنند.", "جدول زنده‌ی نتایج با پینگ، سرعت، پایداری و افت بسته", "پیشنهاد بهترین روش به‌همراه دلیل", "ساخت تونل مستقیم از روی نتیجه"],
    alerts: ["ببینید الان چه چیزی نیاز به توجه دارد و پیش‌تر چه اتفاقی افتاده.", "هشدارهای فعال و تاریخچه، به تفکیک روز", "قانون‌های هشدار برای هر تونل و سرور", "هشدار در تلگرام"],
    health: ["این سرور و همه‌ی تونل‌ها را بررسی کنید و راه‌حل پیشنهادی بگیرید.", "بررسی سیستم: ساعت، کنترل ازدحام، بافرها، محدودیت فایل‌ها", "بررسی داشبورد: پورت، گواهی، فایروال", "بررسی هر تونل: سرویس، شنونده‌ها، دسترس‌پذیری، MTU"],
    maintenance: ["همه‌ی سرورها را به‌روز نگه دارید و از آن‌ها پشتیبان بگیرید.", "به‌روزرسانی و بازگشت نسخه برای هر سرور", "به‌روزرسانی مرحله‌ای سرورها", "دانلود و بازیابی پشتیبان و پشتیبان‌گیری خودکار هفتگی"],
    settings: ["دسترسی به این داشبورد را مدیریت کنید.", "پورت، گواهی و رمز عبور", "نشست‌های فعال ورود", "تنظیمات تلگرام و پشتیبان‌گیری"],
  },
  pw: "رمز عبور", signin: "ورود",
  pwNote: "رمز عبور هنگام راه‌اندازی داشبورد یک بار نمایش داده شد. برای ساختن رمز تازه، این دستور را روی سرور اجرا کنید:",
  pwErr: "رمز عبور را وارد کنید", wrongPw: "رمز عبور درست نیست",
  locked: (wait) => `تلاش‌های نادرست زیاد بود. ${wait} دیگر دوباره امتحان کنید.`, signinFail: "ورود انجام نشد. دوباره تلاش کنید.",
  signout: "خروج", lang: "English", langName: "زبان", theme: "پوسته", dark: "تیره", light: "روشن",
  menu: "منو", closeMenu: "بستن منو",
  minutes: (n) => `${num(n)} دقیقه`, seconds: (n) => `${num(n)} ثانیه`,
  // Only the largest unit, so the figure fits on one line in the tunnel cards.
  dur: (d, h, m) => (d ? `${num(d)} روز` : h ? `${num(h)} ساعت` : `${num(m)} دقیقه`),
};

const T = { en, fa };

function stored(key, allowed, fallback) {
  try {
    const value = localStorage.getItem(key);
    return allowed.includes(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

export const ui = $state({
  lang: stored("ezl", ["en", "fa"], "en"),
  theme: stored("ezt", ["dark", "light"], "dark"),
});

export function applyDocument() {
  const root = document.documentElement;
  root.lang = ui.lang;
  root.dir = ui.lang === "fa" ? "rtl" : "ltr";
  root.dataset.theme = ui.theme;
}

export function setLang(lang) {
  ui.lang = lang;
  try { localStorage.setItem("ezl", lang); } catch { /* private window */ }
  applyDocument();
}

export function setTheme(theme) {
  ui.theme = theme;
  try { localStorage.setItem("ezt", theme); } catch { /* private window */ }
  applyDocument();
}

/** The text for `key`; functions are called with `args`. */
export function t(key, ...args) {
  const value = T[ui.lang][key] ?? T.en[key] ?? key;
  return typeof value === "function" ? value(...args) : value;
}

export function num(n, digits = 0) {
  return new Intl.NumberFormat(ui.lang === "fa" ? "fa-IR" : "en-US", {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  }).format(n);
}

export function pct(n, digits = 1) {
  return ui.lang === "fa" ? `${num(n, digits)}٪` : `${num(n, digits)}%`;
}

/** Megabits per second from bytes per second. */
export function rate(bps) {
  const mbit = (bps * 8) / 1e6;
  return num(mbit, mbit >= 10 ? 0 : 1);
}

/** [value, unit] for a byte count, decimal units like the terminal manager. */
export function amount(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return [num(value, unit === 0 ? 0 : 1), units[unit]];
}

export function duration(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor(seconds / 3600) % 24;
  const m = Math.floor(seconds / 60) % 60;
  return t("dur", d, h, m);
}

export function wait(seconds) {
  return seconds >= 60 ? t("minutes", Math.ceil(seconds / 60)) : t("seconds", seconds);
}

export function clock(ms) {
  return new Intl.DateTimeFormat(ui.lang === "fa" ? "fa-IR" : "en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(ms));
}

export function dateText(ms) {
  return new Intl.DateTimeFormat(ui.lang === "fa" ? "fa-IR" : "en-GB", { day: "numeric", month: "long", year: "numeric" }).format(new Date(ms));
}
