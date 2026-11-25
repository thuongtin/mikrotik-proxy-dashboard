// Proxy Gateway dashboard client.
// All DOM is built with createElement/textContent: data from the API is never
// parsed as HTML. The page runs under a strict CSP (script-src 'self').
(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Small DOM helpers
  // ---------------------------------------------------------------------------

  const $ = (id) => document.getElementById(id);
  const t = (key, params) => window.I18N.t(key, params);
  const SVG_NS = "http://www.w3.org/2000/svg";
  const PROPS = new Set(["value", "checked", "disabled", "selected", "hidden", "tabIndex"]);

  function h(tag, attrs) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        const v = attrs[key];
        if (v === null || v === undefined || v === false) continue;
        if (key === "class") el.className = v;
        else if (key === "text") el.textContent = v;
        else if (key === "dataset") Object.assign(el.dataset, v);
        else if (key.startsWith("on") && typeof v === "function") el.addEventListener(key.slice(2), v);
        else if (PROPS.has(key)) el[key] = v;
        else el.setAttribute(key, v === true ? "" : String(v));
      }
    }
    for (let i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }

  function add(el, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach((c) => add(el, c)); return; }
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }

  function icon(name, extra) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "ic" + (extra ? " " + extra : ""));
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(SVG_NS, "use");
    use.setAttribute("href", "#i-" + name);
    svg.append(use);
    return svg;
  }

  function setIcon(svg, name) {
    const use = svg && svg.querySelector("use");
    if (use) use.setAttribute("href", "#i-" + name);
  }

  function setTone(el, tone) {
    el.classList.remove("tone-ok", "tone-warn", "tone-bad", "tone-idle", "tone-info");
    el.classList.add("tone-" + tone);
  }

  function clear(el) { el.replaceChildren(); return el; }

  function pill(tone, text, iconName, small) {
    return h("span", { class: "pill tone-" + tone + (small ? " pill-sm" : "") },
      h("span", { class: "dot" }), iconName ? icon(iconName, "ic-sm") : null, h("span", { class: "pill-text", text: text }));
  }

  function setBusy(btn, busy, label) {
    if (!btn) return;
    if (busy) {
      btn.setAttribute("aria-busy", "true");
      btn.disabled = true;
      if (label !== undefined) {
        btn.classList.add("has-progress");
        const l = btn.querySelector(".btn-label");
        if (l) { if (!btn.dataset.label) btn.dataset.label = l.textContent; l.textContent = label; }
      }
    } else {
      btn.removeAttribute("aria-busy");
      btn.disabled = false;
      btn.classList.remove("has-progress");
      const l = btn.querySelector(".btn-label");
      if (l && btn.dataset.label) { l.textContent = l.dataset.i18n ? t(l.dataset.i18n) : btn.dataset.label; delete btn.dataset.label; }
    }
  }

  // ---------------------------------------------------------------------------
  // Formatting
  // ---------------------------------------------------------------------------

  // Locale-dependent formatters are rebuilt when the language changes.
  let locale = window.I18N.locale;
  let nf = new Intl.NumberFormat(locale);
  let rtf = makeRelativeFormat(locale);
  const fmtNum = (n) => nf.format(Number(n) || 0);

  function makeRelativeFormat(loc) {
    try { return new Intl.RelativeTimeFormat(loc, { numeric: "auto" }); } catch (e) { return null; }
  }

  function refreshLocale() {
    locale = window.I18N.locale;
    nf = new Intl.NumberFormat(locale);
    rtf = makeRelativeFormat(locale);
    regionNames = makeRegionNames(locale);
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? fmtNum(n) : n.toLocaleString(locale, { maximumFractionDigits: n < 10 ? 1 : 0 })) + " " + units[i];
  }

  function parseTime(v) {
    if (!v) return null;
    const d = new Date(v);
    if (isNaN(d.getTime()) || d.getFullYear() < 2000) return null;
    return d;
  }

  function fmtClock(d) {
    return d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  }

  function fmtDateTime(v) {
    const d = parseTime(v);
    if (!d) return t("time.never");
    const today = new Date();
    const sameDay = d.toDateString() === today.toDateString();
    return sameDay ? t("time.todayAt", { time: fmtClock(d) }) : d.toLocaleString(locale, { hour12: false });
  }

  function fmtAgo(v) {
    const d = parseTime(v);
    if (!d) return t("time.notTested");
    const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    if (s < 45) return t("time.justNow");
    let value = Math.round(s / 86400), unit = "day";
    if (s < 3600) { value = Math.round(s / 60); unit = "minute"; }
    else if (s < 86400) { value = Math.round(s / 3600); unit = "hour"; }
    if (rtf) return rtf.format(-value, unit);
    return t("time.ago." + unit, { count: value });
  }

  function ipKey(ip) {
    const parts = String(ip).split(".");
    if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;
    return parts.reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
  }

  function latencyTone(ms) {
    if (!ms && ms !== 0) return "idle";
    if (ms < 300) return "ok";
    if (ms < 800) return "warn";
    return "bad";
  }

  // A locally administered MAC (second hex digit 2, 6, A or E) is how phones
  // and laptops randomize their address per network.
  function isRandomMac(mac) {
    if (!mac || mac.length < 2) return false;
    return "26AE".includes(mac.charAt(1).toUpperCase());
  }

  const PROTO_LABEL = {
    http: "HTTP", https: "HTTPS", socks5: "SOCKS5", shadowsocks: "SS",
    trojan: "Trojan", vless: "VLESS", vmess: "VMess",
  };

  // ---------------------------------------------------------------------------
  // API
  // ---------------------------------------------------------------------------

  class ApiError extends Error {
    constructor(message, status, data) {
      super(message);
      this.status = status;
      this.data = data || null;
    }
  }

  async function api(method, url, body) {
    const opts = { method: method, credentials: "same-origin", headers: { Accept: "application/json" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(url, opts);
    } catch (e) {
      throw new ApiError(t("error.network"), 0);
    }
    let data = null;
    const text = await res.text();
    if (text) {
      try { data = JSON.parse(text); } catch (e) { data = null; }
    }
    if (res.status === 401 && url.indexOf("/api/auth/") !== 0) {
      onSessionExpired();
      throw new ApiError((data && data.error) || t("error.sessionExpired"), 401, data);
    }
    if (!res.ok) {
      throw new ApiError((data && data.error) || t("error.http", { status: String(res.status) }), res.status, data);
    }
    return data;
  }

  // Describes a multi-step error ({error, step, applied}) in plain words.
  function errorText(err) {
    const d = err && err.data;
    let msg = (err && err.message) || t("error.generic");
    if (d && d.step) {
      msg += "\n" + t(d.applied ? "error.stepApplied" : "error.stepNotApplied", { step: d.step });
    }
    return msg;
  }

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  const VIEWS = ["overview", "proxies", "leakguard", "logs"];
  const REFRESH_MS = 15000;

  const state = {
    view: "overview",
    status: null,
    devices: [],
    proxies: [],
    logs: [],
    loaded: { status: false, devices: false, proxies: false, logs: false },
    loadError: { status: null, devices: null, proxies: null, logs: null },
    search: "",
    showOffline: false,  // offline devices without a proxy are collapsed by default
    proxySearch: "",
    logFilter: "",
    busyIps: new Set(),   // devices with a request in flight
    testing: new Set(),   // proxy ids being tested
    lastUpdated: null,
    timer: null,
    refreshing: false,
    refreshQueued: false,
  };

  const proxyById = (id) => state.proxies.find((p) => p.id === id) || null;

  function deviceName(d) {
    return d.nickname || d.hostname || d.comment || d.ip;
  }

  function devicesUsing(proxyId) {
    return state.devices.filter((d) => d.proxyId === proxyId);
  }

  // Country helpers. countryCode is sanitized server side to ISO alpha-2.
  function makeRegionNames(loc) {
    try { return new Intl.DisplayNames([loc], { type: "region" }); } catch (e) { return null; }
  }
  let regionNames = makeRegionNames(locale);

  function validCC(cc) {
    return typeof cc === "string" && /^[A-Z]{2}$/.test(cc) ? cc : "";
  }

  // Builds the flag emoji from regional indicator symbols.
  function flagEmoji(cc) {
    cc = validCC(cc);
    if (!cc) return "";
    return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
  }

  function countryName(lt) {
    if (!lt) return "";
    const cc = validCC(lt.countryCode);
    if (cc && regionNames) {
      try { const n = regionNames.of(cc); if (n && n !== cc) return n; } catch (e) { /* fall through */ }
    }
    return lt.country || cc || "";
  }

  // Flag badge: emoji plus the two-letter code, so systems without flag
  // emoji (Windows) still show something readable.
  function flagEl(lt, big) {
    const cc = validCC(lt && lt.countryCode);
    if (!cc) return h("span", { class: "flag flag-none" + (big ? " flag-lg" : ""), "aria-hidden": "true" }, icon("globe", "ic-sm"));
    return h("span", { class: "flag" + (big ? " flag-lg" : ""), title: countryName(lt), "aria-hidden": "true" },
      h("span", { class: "flag-emoji", text: flagEmoji(cc) }),
      h("span", { class: "flag-cc", text: cc }));
  }

  function proxyOk(p) {
    return !!(p && p.lastTest && p.lastTest.status === "ok");
  }

  function proxyLabel(p) {
    const f = proxyOk(p) ? flagEmoji(p.lastTest.countryCode) : "";
    let label = (f ? f + " " : "") + (p.name || p.host + ":" + p.port);
    const lt = p.lastTest;
    if (lt && lt.status === "ok" && lt.latencyMs) label += " · " + fmtNum(lt.latencyMs) + " ms";
    else if (lt && lt.status && lt.status !== "ok") label = t("proxy.labelFailed", { label: label });
    return label;
  }

  // ---------------------------------------------------------------------------
  // Toasts
  // ---------------------------------------------------------------------------

  const TOAST_ICON = { ok: "check-circle", bad: "alert-circle", warn: "alert", info: "info", idle: "info" };

  function toast(tone, title, text, opts) {
    opts = opts || {};
    const box = $("toasts");
    const actions = (opts.actions || []).map((a) =>
      h("button", { class: "btn btn-sm btn-secondary", type: "button", text: a.label, onclick: () => { dismiss(); a.run(); } }));
    const el = h("div", { class: "toast tone-" + tone, role: tone === "bad" ? "alert" : "status" },
      icon(TOAST_ICON[tone] || "info"),
      h("div", null,
        h("div", { class: "toast-title", text: title }),
        text ? h("div", { class: "toast-text", text: text }) : null,
        actions.length ? h("div", { class: "toast-actions" }, actions) : null),
      h("button", { class: "toast-close", type: "button", "aria-label": t("toast.close"), onclick: () => dismiss() }, icon("x", "ic-sm")));
    let gone = false;
    function dismiss() {
      if (gone) return;
      gone = true;
      el.classList.add("leaving");
      setTimeout(() => el.remove(), 200);
    }
    box.append(el);
    while (box.children.length > 4) box.firstElementChild.remove();
    const ttl = opts.ttl || (tone === "bad" ? 8000 : actions.length ? 9000 : 4000);
    let timer = setTimeout(dismiss, ttl);
    el.addEventListener("mouseenter", () => clearTimeout(timer));
    el.addEventListener("mouseleave", () => { timer = setTimeout(dismiss, 2500); });
    return dismiss;
  }

  const toastError = (title, err) => toast("bad", title, errorText(err));

  // ---------------------------------------------------------------------------
  // Dialogs
  // ---------------------------------------------------------------------------

  function openDialog(dlg) {
    if (!dlg.open) dlg.showModal();
  }

  function closeDialog(dlg) {
    if (dlg.open) dlg.close();
  }

  function anyDialogOpen() {
    return !!document.querySelector("dialog[open]");
  }

  document.addEventListener("click", (e) => {
    const closer = e.target.closest("[data-close]");
    if (closer) {
      const dlg = closer.closest("dialog");
      if (dlg) closeDialog(dlg);
    }
  });

  // Click on the backdrop closes the dialog (the dialog element itself is the
  // target only when the click lands outside its content box).
  document.querySelectorAll("dialog").forEach((dlg) => {
    dlg.addEventListener("mousedown", (e) => { dlg._downOnBackdrop = e.target === dlg; });
    dlg.addEventListener("click", (e) => {
      if (e.target === dlg && dlg._downOnBackdrop && dlg.id !== "dlg-confirm") closeDialog(dlg);
    });
  });

  // Confirm dialog returning a Promise<boolean>.
  let confirmResolve = null;
  function confirmAction(opts) {
    const dlg = $("dlg-confirm");
    const tone = opts.tone || "warn";
    setTone($("dlg-confirm-icon"), tone);
    setIcon($("dlg-confirm-icon").querySelector("svg"), opts.icon || (tone === "bad" ? "alert-circle" : "alert"));
    $("dlg-confirm-title").textContent = opts.title;
    $("dlg-confirm-text").textContent = opts.text || "";
    const ok = $("dlg-confirm-ok");
    ok.textContent = opts.ok || t("common.ok");
    ok.className = "btn " + (tone === "bad" ? "btn-danger" : "btn-primary");
    $("dlg-confirm-cancel").textContent = opts.cancel || t("common.cancel");
    if (confirmResolve) confirmResolve(false);
    return new Promise((resolve) => {
      confirmResolve = resolve;
      openDialog(dlg);
      (tone === "bad" ? $("dlg-confirm-cancel") : ok).focus();
    });
  }

  function settleConfirm(value) {
    const r = confirmResolve;
    confirmResolve = null;
    closeDialog($("dlg-confirm"));
    if (r) r(value);
  }

  $("dlg-confirm-ok").addEventListener("click", () => settleConfirm(true));
  $("dlg-confirm-cancel").addEventListener("click", () => settleConfirm(false));
  $("dlg-confirm").addEventListener("close", () => { if (confirmResolve) settleConfirm(false); });

  // Password reveal buttons.
  // Labels are catalog keys resolved at use time, so a language switch applies.
  const revealButtons = [];
  function revealLabel(btn) {
    const shown = btn.getAttribute("aria-pressed") === "true";
    return t(shown ? btn.dataset.labelHide : btn.dataset.labelShow);
  }
  function bindReveal(btn, input, showKey, hideKey) {
    btn.dataset.labelShow = showKey;
    btn.dataset.labelHide = hideKey;
    btn.removeAttribute("data-i18n-attr");
    revealButtons.push(btn);
    btn.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", String(show));
      btn.setAttribute("aria-label", revealLabel(btn));
      setIcon(btn.querySelector("svg"), show ? "eye-off" : "eye");
      input.focus();
    });
  }
  function syncRevealLabels() {
    revealButtons.forEach((btn) => btn.setAttribute("aria-label", revealLabel(btn)));
  }
  bindReveal($("login-reveal"), $("login-password"), "reveal.showPassword", "reveal.hidePassword");
  document.querySelectorAll("[data-reveal]").forEach((btn) => {
    const isUuid = btn.dataset.reveal === "pf-uuid";
    bindReveal(btn, $(btn.dataset.reveal),
      isUuid ? "reveal.showUuid" : "reveal.showPassword",
      isUuid ? "reveal.hideUuid" : "reveal.hidePassword");
  });
  syncRevealLabels();

  function resetReveal(input) {
    input.type = "password";
    const btn = document.querySelector('[data-reveal="' + input.id + '"]') || (input.id === "login-password" ? $("login-reveal") : null);
    if (btn) {
      btn.setAttribute("aria-pressed", "false");
      btn.setAttribute("aria-label", revealLabel(btn));
      setIcon(btn.querySelector("svg"), "eye");
    }
  }

  // ---------------------------------------------------------------------------
  // Theme
  // ---------------------------------------------------------------------------

  const darkQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function currentTheme() {
    const theme = document.documentElement.getAttribute("data-theme");
    if (theme === "light" || theme === "dark") return theme;
    return darkQuery && darkQuery.matches ? "dark" : "light";
  }

  function syncThemeButton() {
    const dark = currentTheme() === "dark";
    const btn = $("btn-theme");
    setIcon(btn.querySelector("svg"), dark ? "sun" : "moon");
    btn.removeAttribute("data-i18n-attr");
    btn.setAttribute("aria-label", t(dark ? "theme.toLight" : "theme.toDark"));
    btn.title = btn.getAttribute("aria-label");
  }

  $("btn-theme").addEventListener("click", () => {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("pgw-theme", next); } catch (e) { /* storage blocked */ }
    syncThemeButton();
  });
  if (darkQuery && darkQuery.addEventListener) darkQuery.addEventListener("change", syncThemeButton);
  syncThemeButton();

  // ---------------------------------------------------------------------------
  // Auth
  // ---------------------------------------------------------------------------

  // The login error is kept as {key} for client messages (re-translated on a
  // language switch) or {text} for messages that came from the server.
  let loginMessage = null;
  function renderLoginError() {
    const err = $("login-error");
    if (loginMessage) {
      const text = loginMessage.key ? t(loginMessage.key) : loginMessage.text;
      clear(err).append(icon("alert-circle"), h("span", { text: text }));
      err.hidden = false;
    } else {
      err.hidden = true;
    }
  }

  function showLogin(message) {
    stopRefresh();
    document.querySelectorAll("dialog[open]").forEach((d) => d.close());
    $("boot").hidden = true;
    $("app-view").hidden = true;
    $("login-view").hidden = false;
    loginMessage = message || null;
    renderLoginError();
    const pw = $("login-password");
    pw.value = "";
    setTimeout(() => pw.focus(), 30);
  }

  let expiredShown = false;
  function onSessionExpired() {
    if (expiredShown) return;
    expiredShown = true;
    showLogin({ key: "auth.sessionExpired" });
  }

  function showApp() {
    expiredShown = false;
    $("boot").hidden = true;
    $("login-view").hidden = true;
    $("app-view").hidden = false;
    route(false);
    refreshAll(true);
    startRefresh();
  }

  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $("login-password");
    const btn = $("login-submit");
    if (!pw.value) {
      loginMessage = { key: "auth.passwordRequired" };
      renderLoginError();
      pw.focus();
      return;
    }
    loginMessage = null;
    renderLoginError();
    setBusy(btn, true);
    try {
      const data = await api("POST", "/api/auth/login", { password: pw.value });
      if (data && data.success) {
        pw.value = "";
        resetReveal(pw);
        showApp();
      } else {
        throw new ApiError((data && data.error) || t("auth.loginFailed"), 400);
      }
    } catch (ex) {
      loginMessage = ex.message ? { text: ex.message } : { key: ex.status === 429 ? "auth.tooManyAttempts" : "auth.loginFailed" };
      renderLoginError();
      pw.select();
    } finally {
      setBusy(btn, false);
    }
  });

  $("btn-logout").addEventListener("click", async () => {
    try { await api("POST", "/api/auth/logout"); } catch (e) { /* ignore */ }
    showLogin();
  });

  // ---------------------------------------------------------------------------
  // Routing
  // ---------------------------------------------------------------------------

  function route(focusHeading) {
    const name = (location.hash || "").replace(/^#/, "");
    const view = VIEWS.includes(name) ? name : "overview";
    const changed = view !== state.view;
    state.view = view;
    document.querySelectorAll("section.view").forEach((s) => { s.hidden = s.dataset.view !== view; });
    document.querySelectorAll(".nav-item").forEach((a) => {
      if (a.dataset.view === view) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    document.title = t("app.documentTitle", { page: t("nav." + view) });
    if (focusHeading && changed) {
      const hd = $("h-" + view);
      if (hd) hd.focus({ preventScroll: true });
      window.scrollTo(0, 0);
    }
    if (view === "logs" && !$("app-view").hidden) loadLogs(false);
  }

  window.addEventListener("hashchange", () => {
    if (location.hash === "#main") return;
    route(true);
  });

  // ---------------------------------------------------------------------------
  // Loading
  // ---------------------------------------------------------------------------

  async function load(key, url) {
    try {
      const data = await api("GET", url);
      state[key] = data == null ? (key === "status" ? null : []) : data;
      state.loaded[key] = true;
      state.loadError[key] = null;
      return true;
    } catch (e) {
      if (e.status === 401) throw e;
      state.loadError[key] = e;
      return false;
    }
  }

  async function refreshAll(initial, userInitiated) {
    if (state.refreshing) return;
    state.refreshing = true;
    const btn = $("btn-refresh");
    btn.classList.add("is-spinning");
    if (userInitiated) setBusy(btn, true);
    try {
      const jobs = [load("status", "/api/system/status"), load("devices", "/api/devices"), load("proxies", "/api/proxies")];
      if (state.view === "logs") jobs.push(load("logs", "/api/system/logs"));
      const results = await Promise.all(jobs);
      if (results.every(Boolean)) state.lastUpdated = new Date();
      renderAll();
      if (userInitiated) {
        if (results.every(Boolean)) toast("ok", t("refresh.done"));
        else toast("bad", t("refresh.partial"), firstLoadError());
      }
    } catch (e) {
      // 401 already switched to the login screen.
    } finally {
      state.refreshing = false;
      btn.classList.remove("is-spinning");
      if (userInitiated) setBusy(btn, false);
    }
    // A language switch during this refresh asked for data in the new language.
    if (state.refreshQueued) {
      state.refreshQueued = false;
      if (!$("app-view").hidden) refreshAll(false);
    }
  }

  function firstLoadError() {
    for (const k of Object.keys(state.loadError)) if (state.loadError[k]) return state.loadError[k].message;
    return "";
  }

  async function loadLogs(userInitiated) {
    const btn = $("btn-logs-refresh");
    if (userInitiated) setBusy(btn, true);
    try {
      await Promise.all([load("logs", "/api/system/logs"), load("status", "/api/system/status")]);
      renderLogs();
      renderSingbox();
      renderChrome();
    } catch (e) { /* 401 handled */ }
    finally { if (userInitiated) setBusy(btn, false); }
  }

  function canAutoRefresh() {
    if (document.hidden) return false;
    if (anyDialogOpen()) return false;
    if (state.busyIps.size > 0 || state.testing.size > 0) return false;
    const a = document.activeElement;
    if (a && a.closest && a.closest("tbody, #devices-body") && (a.tagName === "SELECT" || a.tagName === "BUTTON")) return false;
    return true;
  }

  function startRefresh() {
    stopRefresh();
    state.timer = setInterval(() => {
      if (canAutoRefresh()) refreshAll(false);
      else renderUpdated();
    }, REFRESH_MS);
  }

  function stopRefresh() {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !$("app-view").hidden && state.lastUpdated && Date.now() - state.lastUpdated.getTime() > REFRESH_MS && canAutoRefresh()) {
      refreshAll(false);
    }
  });

  $("btn-refresh").addEventListener("click", () => refreshAll(false, true));

  // ---------------------------------------------------------------------------
  // Derived status
  // ---------------------------------------------------------------------------

  const OVERALL = {
    protected: { tone: "ok", icon: "shield-check" },
    degraded: { tone: "warn", icon: "shield-alert" },
    unprotected: { tone: "bad", icon: "shield-off" },
    unknown: { tone: "idle", icon: "shield-question" },
  };
  const OVERALL_TEXT = {
    protected: ["overall.protected.title", "overall.protected.text"],
    degraded: ["overall.degraded.title", "overall.degraded.text"],
    unprotected: ["overall.unprotected.title", "overall.unprotected.text"],
    unknown: ["overall.unknown.title", "overall.unknown.text"],
  };

  const LAYER_TONE = { ok: "ok", warning: "warn", error: "bad", unknown: "idle" };
  const LAYER_STATUS_KEY = { ok: "layer.status.ok", warning: "layer.status.warning", error: "layer.status.error", unknown: "layer.status.unknown" };
  // The server reports layer names as stable English identifiers
  // ("Layer 3: RouterOS Kill-Switch"); the UI maps the number to a localized title.
  const LAYER_COUNT = 6;

  function layerInfo(layer, index) {
    const m = /^Layer\s*(\d+)\s*:?\s*(.*)$/i.exec(layer.name || "");
    const num = m ? parseInt(m[1], 10) : index + 1;
    const raw = m ? m[2] : layer.name || "";
    const titleKey = "layer.title." + num;
    const known = num >= 1 && num <= LAYER_COUNT && window.I18N.has(titleKey);
    return {
      num: num,
      title: known ? t(titleKey) : raw || t("layer.fallback", { num: String(num) }),
      raw: raw,
      tone: LAYER_TONE[layer.status] || "idle",
      statusText: t(LAYER_STATUS_KEY[layer.status] || "layer.status.unknown"),
    };
  }

  function overall() {
    const lg = state.status && state.status.leakGuard;
    const key = lg && OVERALL[lg.overallStatus] ? lg.overallStatus : "unknown";
    const keys = OVERALL_TEXT[key];
    return Object.assign({ key: key, title: t(keys[0]), text: t(keys[1]) }, OVERALL[key]);
  }

  function proxyStats() {
    const s = { total: state.proxies.length, ok: 0, bad: 0, untested: 0 };
    state.proxies.forEach((p) => {
      const lt = p.lastTest;
      if (!lt || !lt.status) s.untested++;
      else if (lt.status === "ok") s.ok++;
      else s.bad++;
    });
    return s;
  }

  function attentionItems() {
    const items = [];
    const st = state.status;
    if (!st) {
      if (state.loadError.status) items.push({ tone: "bad", icon: "alert-circle", title: t("attention.statusUnreadable"), text: state.loadError.status.message });
      return items;
    }
    const lg = st.leakGuard || {};
    const sb = st.singbox || {};
    if (lg.routerReachable === false) {
      items.push({ tone: "bad", icon: "router", title: t("attention.routerDown.title"), text: t("attention.routerDown.text"), action: { label: t("attention.resync"), run: () => reconcile() } });
    }
    if (!sb.running) {
      items.push({ tone: "bad", icon: "cpu", title: t("attention.singboxDown.title"), text: sb.lastError || t("attention.singboxDown.text"), action: { label: t("attention.viewLogs"), run: () => { location.hash = "#logs"; } } });
    } else if (sb.lastError) {
      items.push({ tone: "warn", icon: "cpu", title: t("attention.singboxError.title"), text: sb.lastError, action: { label: t("attention.viewLogs"), run: () => { location.hash = "#logs"; } } });
    }
    (lg.layers || []).forEach((layer, i) => {
      const info = layerInfo(layer, i);
      if (info.tone === "bad" || info.tone === "warn") {
        items.push({ tone: info.tone, icon: "shield-alert", title: t(info.tone === "bad" ? "attention.layerError" : "attention.layerWarning", { num: String(info.num), title: info.title }), text: layer.details || layer.description || "", action: { label: t("attention.details"), run: () => { location.hash = "#leakguard"; } } });
      }
    });
    const badProxies = state.proxies.filter((p) => p.lastTest && p.lastTest.status && p.lastTest.status !== "ok" && devicesUsing(p.id).length > 0);
    badProxies.forEach((p) => {
      const n = devicesUsing(p.id).length;
      items.push({ tone: "warn", icon: "globe", title: t("attention.proxyFailed.title", { name: p.name || p.host }), text: (t("attention.proxyFailed.text", { count: n }) + " " + (p.lastTest.error || "")).trim(), action: { label: t("attention.retest"), run: () => testProxy(p.id) } });
    });
    return items;
  }

  // ---------------------------------------------------------------------------
  // Rendering: chrome (topbar, sidebar, badges)
  // ---------------------------------------------------------------------------

  function renderAll() {
    renderChrome();
    renderOverview();
    renderProxies();
    renderLeakGuard();
    renderSingbox();
    if (state.view === "logs") renderLogs();
  }

  function renderUpdated() {
    const el = $("updated-at");
    el.removeAttribute("data-i18n");
    if (!state.lastUpdated) { el.textContent = state.loaded.status ? "" : t("common.loading"); return; }
    el.textContent = t("updated.at", { time: fmtClock(state.lastUpdated) });
    el.title = t("updated.autoRefresh");
  }

  function renderChrome() {
    renderUpdated();
    const st = state.status;
    const lg = st && st.leakGuard;
    const sb = st && st.singbox;

    const pr = $("pill-router");
    const routerTone = !lg ? "idle" : lg.routerReachable ? "ok" : "bad";
    setTone(pr, routerTone);
    pr.removeAttribute("data-i18n-attr");
    pr.title = t(!lg ? "chrome.router.unknown" : lg.routerReachable ? "chrome.router.connected" : "chrome.router.disconnected");
    pr.setAttribute("aria-label", pr.title);

    const ps = $("pill-singbox");
    const sbTone = !sb ? "idle" : sb.running ? (sb.lastError ? "warn" : "ok") : "bad";
    setTone(ps, sbTone);
    ps.removeAttribute("data-i18n-attr");
    ps.title = !sb ? t("chrome.singbox.unknown")
      : sb.running ? (sb.version ? t("chrome.singbox.runningVersion", { version: sb.version }) : t("chrome.singbox.running"))
      : t("chrome.singbox.stopped");
    ps.setAttribute("aria-label", ps.title);

    const o = overall();
    const card = $("sidebar-card");
    setTone(card, o.tone);
    $("sidebar-title").textContent = o.title;
    const assigned = lg ? lg.assignedDeviceCount || 0 : 0;
    $("sidebar-text").textContent = lg
      ? t("sidebar.devices", { count: assigned }) + " " + t("sidebar.blocked", { count: Number(lg.killSwitchPackets) || 0 })
      : t("sidebar.loading");

    const items = attentionItems();
    const ps2 = proxyStats();
    setBadge("nav-badge-proxies", ps2.bad, "warn");
    const badLayers = lg ? (lg.layers || []).filter((l) => l.status === "error" || l.status === "warning").length : 0;
    setBadge("nav-badge-leakguard", badLayers, lg && lg.overallStatus === "unprotected" ? "bad" : "warn");
    setBadge("nav-badge-logs", sb && !sb.running ? 1 : 0, "bad", "!");
    return items;
  }

  function setBadge(id, count, tone, text) {
    const b = $(id);
    if (!count) { b.hidden = true; return; }
    b.hidden = false;
    b.className = "badge tone-" + tone;
    b.textContent = text || String(count);
  }

  // ---------------------------------------------------------------------------
  // Rendering: overview
  // ---------------------------------------------------------------------------

  function renderOverview() {
    renderHero();
    renderAttention();
    renderMetrics();
    renderDevices();
  }

  function renderHero() {
    const o = overall();
    const hero = $("hero");
    setTone(hero, o.tone);
    setIcon(hero.querySelector(".hero-icon svg"), o.icon);
    $("hero-title").textContent = state.loaded.status ? o.title : t("hero.checking");
    const lg = state.status && state.status.leakGuard;
    const layers = (lg && lg.layers) || [];
    let text = o.text;
    if (lg && layers.length) {
      const okCount = layers.filter((l) => l.status === "ok").length;
      text = t("hero.layersActive", { ok: okCount, total: layers.length, text: o.text });
    }
    $("hero-text").textContent = state.loaded.status ? text : t("hero.loading");
    const ul = clear($("hero-layers"));
    layers.forEach((layer, i) => {
      const info = layerInfo(layer, i);
      ul.append(h("li", { class: "layer-chip tone-" + info.tone, title: t("layer.chipTitle", { status: info.statusText, description: layer.description || info.raw }) },
        h("span", { class: "dot" }), h("b", { text: "L" + info.num }), info.title,
        h("span", { class: "sr-only", text: ", " + info.statusText })));
    });
  }

  function renderAttention() {
    const items = attentionItems();
    const box = $("attention");
    const ul = clear($("attention-list"));
    box.hidden = items.length === 0;
    items.forEach((it) => {
      ul.append(h("li", { class: "attention-item tone-" + it.tone },
        h("div", { class: "attention-icon" }, icon(it.icon)),
        h("div", { style: "min-width:0" },
          h("div", { class: "attention-title", text: it.title }),
          it.text ? h("div", { class: "attention-text", text: it.text }) : null),
        it.action ? h("button", { class: "btn btn-sm btn-secondary", type: "button", text: it.action.label, onclick: it.action.run }) : h("span")));
    });
  }

  function metric(opts) {
    return h("div", { class: "metric" + (opts.tone ? " tone-" + opts.tone : "") },
      h("div", { class: "metric-head" }, h("span", { class: "metric-icon" }, icon(opts.icon)), opts.label),
      h("div", { class: "metric-value" }, opts.value, opts.unit ? h("small", { text: opts.unit }) : null),
      opts.meter !== undefined ? h("div", { class: "meter", role: "presentation" }, h("span", { style: "width:" + Math.round(Math.min(1, Math.max(0, opts.meter)) * 100) + "%" })) : null,
      opts.sub ? h("div", { class: "metric-sub", text: opts.sub }) : null);
  }

  function skeletonMetrics(n) {
    const out = [];
    for (let i = 0; i < n; i++) {
      out.push(h("div", { class: "metric", "aria-hidden": "true" },
        h("span", { class: "skel", style: "width:45%" }), h("span", { class: "skel", style: "width:35%;height:24px;margin-top:4px" }), h("span", { class: "skel", style: "width:60%" })));
    }
    return out;
  }

  function renderMetrics() {
    const box = clear($("metrics"));
    if (!state.loaded.status && !state.loaded.devices) { box.append(skeletonMetrics(4)); return; }
    const lg = (state.status && state.status.leakGuard) || {};
    const total = state.devices.length;
    const assigned = lg.assignedDeviceCount != null ? lg.assignedDeviceCount : state.devices.filter((d) => d.proxyId).length;
    const online = state.devices.filter((d) => d.online).length;
    const ps = proxyStats();
    box.append(
      metric({ icon: "route", label: t("metric.devicesProxied.label"), value: fmtNum(assigned), unit: "/ " + fmtNum(total), meter: total ? assigned / total : 0, sub: t("metric.devicesProxied.sub", { count: online }), tone: "info" }),
      metric({ icon: "ban", label: t("metric.killSwitch.label"), value: fmtNum(lg.killSwitchPackets), unit: t("metric.unit.packets", { count: Number(lg.killSwitchPackets) || 0 }), sub: t("metric.killSwitch.sub", { bytes: fmtBytes(lg.killSwitchBytes) }), tone: lg.killSwitchPackets > 0 ? "warn" : "ok" }),
      metric({ icon: "dna", label: t("metric.ipv6.label"), value: fmtNum(lg.ipv6BlockedPackets), unit: t("metric.unit.packets", { count: Number(lg.ipv6BlockedPackets) || 0 }), sub: t("metric.ipv6.sub", { bytes: fmtBytes(lg.ipv6BlockedBytes) }), tone: "idle" }),
      metric({ icon: "globe", label: t("metric.proxies.label"), value: fmtNum(ps.ok), unit: "/ " + fmtNum(ps.total), meter: ps.total ? ps.ok / ps.total : 0, sub: ps.total === 0 ? t("metric.proxies.none") : t("metric.proxies.sub", { bad: ps.bad, untested: ps.untested }), tone: ps.bad > 0 ? "warn" : "ok" }));
  }

  function matchesDevice(d, q) {
    if (!q) return true;
    const p = d.proxyId ? proxyById(d.proxyId) : null;
    const lt = p && p.lastTest;
    const hay = [d.ip, d.mac, d.hostname, d.nickname, d.comment, p && p.name, lt && lt.status === "ok" ? countryName(lt) : "", lt && lt.city].join(" ").toLowerCase();
    return hay.indexOf(q) !== -1;
  }

  function skeletonRows(cols, n) {
    const rows = [];
    for (let i = 0; i < n; i++) {
      const tds = [];
      for (let c = 0; c < cols; c++) tds.push(h("td", { class: c === 0 ? "cell-main" : "cell-full" }, h("span", { class: "skel", style: "width:" + (40 + ((i * 7 + c * 13) % 45)) + "%" })));
      rows.push(h("tr", { "aria-hidden": "true" }, tds));
    }
    return rows;
  }

  function emptyBox(opts) {
    return h("div", { class: "empty" },
      h("div", { class: "empty-icon" }, icon(opts.icon)),
      h("div", { class: "empty-title", text: opts.title }),
      opts.text ? h("div", { class: "empty-text", text: opts.text }) : null,
      opts.action ? h("button", { class: "btn btn-secondary btn-sm", type: "button", text: opts.action.label, onclick: opts.action.run }) : null);
  }

  function emptyRow(cols, opts) {
    return h("tr", { class: "empty-row" }, h("td", { class: "empty-cell", colspan: cols }, emptyBox(opts)));
  }

  // Device kind guessed from the names the device reports, so the list shows
  // a recognizable picture instead of the same icon for every row. Order
  // matters: watches and tablets before phones, consoles before routers.
  const DEVICE_KINDS = [
    ["watch", /watch/],
    ["tablet", /ipad|tablet|\btab\b|\bpad\b|25079rpdcg|sm-[tx]\d/],
    ["phone", /iphone|android|pixel|galaxy|\bsm-|redmi|xiaomi|\bpoco|oppo|vivo|realme|oneplus|huawei|honor|nokia|motorola|phone/],
    ["laptop", /macbook|laptop|notebook|thinkpad|surface|zenbook|vivobook|ideapad|chromebook|\bmbp\b|\bmba\b/],
    ["tv", /\btv\b|chromecast|roku|fire-?tv|apple-?tv|bravia|webos|tizen|android-?tv|mibox|shield/],
    ["gamepad", /\bps[345]\b|playstation|xbox|nintendo|switch/],
    ["speaker", /homepod|\becho\b|sonos|nest-?(mini|audio|hub)|google-?home|speaker/],
    ["camera", /camera|cam\b|ipcam|hikvision|dahua|ezviz|imou|doorbell/],
    ["printer", /printer|epson|canon|brother|laserjet|deskjet|officejet/],
    ["router", /mikrotik|router|\bap\b|access-?point|unifi|tp-?link|\bdeco\b|eero|orbi|mesh/],
    ["cpu", /\besp|tuya|shelly|sonoff|tasmota|raspberry|\brpi\b|arduino|\biot\b|zigbee|smart-?plug|bulb/],
    ["monitor", /desktop|\bpc\b|imac|mac-?mini|mac-?studio|workstation|windows/],
  ];

  function deviceKind(d) {
    const text = [d.nickname, d.hostname, d.comment].filter(Boolean).join(" ").toLowerCase();
    if (!text) return "monitor";
    const hit = DEVICE_KINDS.find((k) => k[1].test(text));
    return hit ? hit[0] : null;
  }

  function deviceAvatar(d, big) {
    const kind = deviceKind(d);
    const first = Array.from(deviceName(d).trim())[0] || "?";
    return h("span", { class: "dev-avatar tone-" + (d.online ? "ok" : "idle") + (big ? " dev-avatar-lg" : ""), "aria-hidden": "true" },
      kind ? icon(kind) : h("span", { class: "dev-initial", text: first.toLocaleUpperCase(locale) }),
      h("span", { class: "dot" }));
  }

  // One line that answers "how does this device reach the Internet right now".
  function routeSummary(d) {
    const spin = h("span", { class: "spinner", "aria-hidden": "true" });
    if (state.busyIps.has(d.ip)) return { tone: "info", lead: spin, main: t("route.applying"), sub: "" };
    if (!d.proxyId) return { tone: "idle", direct: true, lead: icon("router", "ic-sm"), main: t("route.direct"), sub: "" };
    const p = proxyById(d.proxyId);
    if (!p) return { tone: "warn", lead: icon("alert", "ic-sm"), main: t("exit.proxyDeleted"), sub: t("route.pickAgain") };
    const pname = p.name || p.host;
    if (state.testing.has(p.id)) return { tone: "info", lead: spin, main: pname, sub: t("route.testing") };
    const lt = p.lastTest;
    if (!lt || !lt.status) return { tone: "info", lead: flagEl(null), main: pname, sub: t("route.notTested") };
    if (lt.status !== "ok") return { tone: "bad", lead: icon("alert-circle", "ic-sm"), main: pname, sub: t("route.failed") };
    const place = [countryName(lt), lt.city].filter(Boolean).join(", ") || t("exit.unknownPlace");
    return {
      tone: "ok", lead: flagEl(lt), main: place,
      sub: lt.latencyMs ? t("route.via", { name: pname, ms: fmtNum(lt.latencyMs) }) : t("exit.via", { name: pname }),
    };
  }

  const byOnlineThenIp = (a, b) => (Number(!!b.online) - Number(!!a.online)) || (ipKey(a.ip) - ipKey(b.ip));

  function renderDevices() {
    const body = $("devices-body");
    body.setAttribute("aria-busy", String(!state.loaded.devices && !state.loadError.devices));
    if (!state.loaded.devices) {
      if (state.loadError.devices) {
        body.replaceChildren(emptyBox({ icon: "alert-circle", title: t("devices.loadFailed"), text: state.loadError.devices.message, action: { label: t("common.retry"), run: () => refreshAll(false, true) } }));
      } else {
        body.replaceChildren(skeletonList(4));
      }
      return;
    }
    const assigned = state.devices.filter((d) => d.proxyId).length;
    $("devices-sub").textContent = state.devices.length
      ? t("devices.summary", { count: state.devices.length, assigned: assigned })
      : t("devices.sub");

    if (state.devices.length === 0) {
      body.replaceChildren(emptyBox({ icon: "monitor", title: t("devices.empty.title"), text: t("devices.empty.text") }));
      return;
    }
    const q = state.search.trim().toLowerCase();
    const list = state.devices.filter((d) => matchesDevice(d, q)).sort(byOnlineThenIp);
    if (list.length === 0) {
      body.replaceChildren(emptyBox({ icon: "search", title: t("devices.noMatch.title"), text: t("devices.noMatch.text"), action: { label: t("devices.clearSearch"), run: () => { state.search = ""; $("device-search").value = ""; renderDevices(); } } }));
      return;
    }
    const proxied = list.filter((d) => d.proxyId);
    const direct = list.filter((d) => !d.proxyId && d.online);
    const offline = list.filter((d) => !d.proxyId && !d.online);
    const groups = [];
    if (proxied.length || !q) {
      groups.push(devGroup({ key: "proxy", title: t("devices.group.proxy"), sub: t("devices.group.proxySub"), rows: proxied,
        empty: t("devices.group.proxyEmpty") }));
    }
    if (direct.length) groups.push(devGroup({ key: "direct", title: t("devices.group.direct"), sub: t("devices.group.directSub"), rows: direct }));
    if (offline.length) {
      groups.push(devGroup({ key: "offline", title: t("devices.group.offline"), sub: t("devices.group.offlineSub"), rows: offline,
        collapsible: true, open: !!q || state.showOffline }));
    }
    body.replaceChildren.apply(body, groups);
    if ($("dlg-device").open) renderDeviceDetails(false);
  }

  function skeletonList(n) {
    const rows = [];
    for (let i = 0; i < n; i++) {
      rows.push(h("li", { class: "dev-row is-skel", "aria-hidden": "true" },
        h("span", { class: "dev-open" }, h("span", { class: "dev-avatar" }),
          h("span", { class: "dev-text" }, h("span", { class: "skel", style: "width:" + (45 + (i * 17) % 35) + "%" }), h("span", { class: "skel skel-sm", style: "width:30%" }))),
        h("span", { class: "route-btn tone-idle" }, h("span", { class: "skel", style: "width:70%" }))));
    }
    return h("section", { class: "dev-group" }, h("ul", { class: "dev-rows" }, rows));
  }

  function devGroup(o) {
    const count = h("span", { class: "dev-group-count", text: fmtNum(o.rows.length) });
    let title;
    if (o.collapsible) {
      title = h("h3", { class: "dev-group-title" },
        h("button", { class: "dev-group-toggle", type: "button", "aria-expanded": String(o.open),
          onclick: () => { state.showOffline = !o.open; renderDevices(); } },
          icon("chevron-down", "ic-sm dev-group-chev"), o.title, count));
    } else {
      title = h("h3", { class: "dev-group-title" }, o.title, count);
    }
    const head = h("div", { class: "dev-group-head" }, title, h("p", { class: "dev-group-sub", text: o.sub }));
    let content = null;
    if (!o.rows.length) content = h("p", { class: "dev-group-empty" }, icon("info", "ic-sm"), h("span", { text: o.empty }));
    else if (!o.collapsible || o.open) content = h("ul", { class: "dev-rows" }, o.rows.map(deviceRow));
    return h("section", { class: "dev-group", dataset: { group: o.key } }, head, content);
  }

  function deviceRow(d) {
    const busy = state.busyIps.has(d.ip);
    const name = deviceName(d);
    const secondary = d.nickname && d.hostname && d.hostname !== d.nickname ? d.hostname
      : d.comment && d.comment !== name ? d.comment : "";
    const rs = routeSummary(d);
    const routeText = [rs.main, rs.sub].filter(Boolean).join(", ");
    return h("li", { class: "dev-row" + (busy ? " is-busy" : "") + (d.online ? "" : " is-offline"), dataset: { ip: d.ip }, "aria-busy": busy ? "true" : null },
      h("button", { class: "dev-open", type: "button", "aria-haspopup": "dialog", title: t("device.details"), onclick: () => openDeviceDetails(d) },
        deviceAvatar(d),
        h("span", { class: "dev-text" },
          h("span", { class: "dev-title", text: name }),
          h("span", { class: "dev-meta" },
            // Unnamed devices already show the IP as the title, so show the MAC instead.
            h("span", { class: "mono", text: name === d.ip ? (d.mac || "").toUpperCase() || null : d.ip }),
            secondary ? h("span", { text: secondary }) : null,
            d.online ? null : h("span", { class: "dev-off", text: t("device.offline") })))),
      h("button", {
        class: "route-btn tone-" + rs.tone + (rs.direct ? " is-direct" : ""), type: "button", disabled: busy,
        "aria-haspopup": "dialog", "aria-label": t("route.changeAria", { name: name, route: routeText }), title: t("route.change"),
        onclick: () => openRoutePicker(d),
      },
        h("span", { class: "route-lead" }, rs.lead),
        h("span", { class: "route-text" },
          h("span", { class: "route-main", text: rs.main }),
          rs.sub ? h("span", { class: "route-sub", text: rs.sub }) : null),
        icon("chevron-down", "ic-sm route-chev")),
      h("button", { class: "btn btn-icon btn-sm btn-ghost dev-more", type: "button", tabindex: "-1", "aria-hidden": "true", title: t("device.details"), onclick: () => openDeviceDetails(d) }, icon("more", "ic-sm")));
  }

  // Re-renders a single device row in place.
  function rerenderDevice(ip) {
    const body = $("devices-body");
    const old = body.querySelector('li[data-ip="' + CSS.escape(ip) + '"]');
    const d = state.devices.find((x) => x.ip === ip);
    if (!old || !d) { renderDevices(); return; }
    old.replaceWith(deviceRow(d));
  }

  $("device-search").addEventListener("input", (e) => { state.search = e.target.value; renderDevices(); });

  // Where the device appears on the Internet: the proxy exit (from the
  // proxy's last test) or the home connection when routed directly.
  function exitCell(d) {
    if (!d.proxyId) {
      return h("div", { class: "exit" },
        h("div", { class: "exit-line" }, h("span", { class: "flag flag-none flag-home", "aria-hidden": "true" }, icon("router", "ic-sm")), h("span", { class: "exit-main", text: t("exit.home") })),
        h("div", { class: "px-sub", text: t("exit.direct") }));
    }
    const p = proxyById(d.proxyId);
    if (!p) {
      return h("div", { class: "exit" },
        h("div", { class: "exit-line" }, pill("warn", t("exit.proxyDeleted"), null, true)),
        h("div", { class: "px-sub", text: t("exit.pickAgain") }));
    }
    const pname = p.name || p.host;
    if (state.testing.has(p.id)) {
      return h("div", { class: "exit" }, h("div", { class: "exit-line" }, h("span", { class: "spinner", "aria-hidden": "true" }), h("span", { class: "px-sub", text: t("exit.testing", { name: pname }) })));
    }
    const lt = p.lastTest;
    if (!lt || !lt.status) {
      return h("div", { class: "exit" },
        h("div", { class: "exit-line" }, flagEl(null), h("span", { class: "exit-main muted", text: t("exit.unknownCountry") })),
        h("div", { class: "px-sub" }, t("exit.notTested", { name: pname }) + " ",
          h("button", { class: "link-btn", type: "button", onclick: () => testProxy(p.id) }, t("exit.testNow"))));
    }
    if (lt.status !== "ok") {
      return h("div", { class: "exit" },
        h("div", { class: "exit-line" }, pill("bad", t("exit.proxyFailed"), null, true), h("span", { class: "px-sub", text: fmtAgo(lt.testedAt), title: fmtDateTime(lt.testedAt) })),
        h("div", { class: "px-sub tone-bad-text", text: t("exit.blocked") }));
    }
    const place = [countryName(lt), lt.city].filter(Boolean).join(", ") || t("exit.unknownPlace");
    return h("div", { class: "exit", title: t("exit.basis", { name: pname, time: fmtDateTime(lt.testedAt) }) },
      h("div", { class: "exit-line" }, flagEl(lt), h("span", { class: "exit-main", text: place })),
      h("div", { class: "exit-ip" }, lt.exitIp ? h("span", { class: "mono", text: lt.exitIp }) : null, h("span", { class: "px-sub", text: t("exit.via", { name: pname }) })));
  }

  // ---------------------------------------------------------------------------
  // Route picker
  // ---------------------------------------------------------------------------

  let routeIp = null;
  const routeDevice = () => state.devices.find((x) => x.ip === routeIp) || null;

  function selectedRoute() {
    const c = $("route-options").querySelector("input:checked");
    return c ? c.value : null;
  }

  // Working proxies first, then untested, then failing; by name within each.
  function proxyRank(p) {
    const lt = p.lastTest;
    if (lt && lt.status === "ok") return 0;
    if (!lt || !lt.status) return 1;
    return 2;
  }

  function routeOption(o) {
    const input = h("input", { type: "radio", name: "route", value: o.value, checked: o.checked, disabled: o.disabled, onchange: updateRouteNote });
    return h("label", { class: "route-opt" + (o.tone ? " tone-" + o.tone : "") },
      input,
      h("span", { class: "route-opt-lead" }, o.lead),
      h("span", { class: "route-opt-text" },
        h("span", { class: "route-opt-title" }, h("span", { class: "route-opt-name", text: o.title }), o.tags || null),
        o.sub ? h("span", { class: "route-opt-sub" }, o.sub) : null),
      o.right ? h("span", { class: "route-opt-right" }, o.right) : null);
  }

  function renderRoutePicker(reset) {
    const d = routeDevice();
    if (!d) return;
    const current = d.proxyId || "";
    const prev = reset ? current : selectedRoute();
    const want = prev === null ? current : prev;
    const inUse = h("span", { class: "tag tone-info", text: t("route.inUse") });
    const opts = [routeOption({
      value: "", checked: want === "", lead: h("span", { class: "flag flag-none flag-lg flag-home", "aria-hidden": "true" }, icon("router")),
      title: t("route.direct"), tags: current === "" ? inUse : null, sub: t("route.directSub"),
    })];
    const sorted = state.proxies.slice().sort((a, b) => (proxyRank(a) - proxyRank(b)) || (a.name || "").localeCompare(b.name || "", locale));
    sorted.forEach((p) => {
      const lt = p.lastTest;
      const ok = lt && lt.status === "ok";
      const failed = lt && lt.status && !ok;
      const users = devicesUsing(p.id).length;
      let sub;
      if (state.testing.has(p.id)) sub = t("route.testing");
      else if (ok) sub = [[countryName(lt), lt.city].filter(Boolean).join(", ") || t("exit.unknownPlace"), lt.exitIp ? h("span", { class: "mono", text: lt.exitIp }) : null];
      else if (failed) sub = t("route.optFailed");
      else sub = t("route.optNotTested");
      if (Array.isArray(sub)) sub = sub.filter(Boolean).reduce((acc, part, i) => acc.concat(i ? [" · ", part] : [part]), []);
      opts.push(routeOption({
        value: p.id, checked: want === p.id, disabled: !d.mac && p.id !== current, tone: failed ? "bad" : null,
        lead: flagEl(ok ? lt : null, true),
        title: p.name || p.host + ":" + p.port,
        tags: [h("span", { class: "tag tag-proto", text: PROTO_LABEL[p.protocol] || p.protocol }), p.id === current ? inUse : null],
        sub: sub,
        right: [
          ok && lt.latencyMs ? h("span", { class: "latency tone-" + latencyTone(lt.latencyMs), text: fmtNum(lt.latencyMs) + " ms" }) : null,
          users ? h("span", { class: "route-opt-users", text: t("route.users", { count: users }) }) : null,
        ],
      }));
    });
    if (current && !proxyById(current)) {
      opts.push(routeOption({ value: current, checked: want === current, tone: "warn", lead: h("span", { class: "flag flag-none flag-lg", "aria-hidden": "true" }, icon("alert")),
        title: t("exit.proxyDeleted"), tags: inUse, sub: t("route.pickAgain") }));
    }
    $("route-target").textContent = deviceName(d) + " · " + d.ip;
    const box = $("route-options");
    box.replaceChildren.apply(box, opts);
    if (!state.proxies.length) {
      box.append(h("div", { class: "route-empty" },
        h("span", { text: t("route.noProxies") }),
        h("button", { class: "btn btn-secondary btn-sm", type: "button", onclick: () => { closeDialog($("dlg-route")); location.hash = "#proxies"; } }, icon("plus", "ic-sm"), t("route.addProxy"))));
    }
    updateRouteNote();
  }

  function noteEl(tone, iconName, text) {
    return h("div", { class: "inline-alert tone-" + tone }, icon(iconName, "ic-sm"), h("span", { text: text }));
  }

  function updateRouteNote() {
    const d = routeDevice();
    if (!d) return;
    const sel = selectedRoute();
    const current = d.proxyId || "";
    const changed = sel !== null && sel !== current;
    $("btn-route-apply").disabled = !changed || state.busyIps.has(d.ip);
    const notes = [];
    if (!d.mac) notes.push(noteEl("warn", "alert", t("route.noMac")));
    if (changed) {
      const p = sel ? proxyById(sel) : null;
      const lt = p && p.lastTest;
      if (!sel) notes.push(noteEl("warn", "alert", t("route.note.direct")));
      else if (lt && lt.status && lt.status !== "ok") notes.push(noteEl("bad", "alert-circle", t("route.note.failed", { name: p.name || p.host })));
      else if (!lt || !lt.status) notes.push(noteEl("info", "info", t("route.note.untested")));
      notes.push(h("p", { class: "route-restart" }, icon("refresh", "ic-sm"), h("span", { text: t("route.note.restart") })));
    }
    const box = $("route-note");
    box.replaceChildren.apply(box, notes);
    box.className = notes.length ? "stack route-notes" : "";
  }

  function openRoutePicker(d) {
    if ($("dlg-device").open) closeDialog($("dlg-device"));
    routeIp = d.ip;
    renderRoutePicker(true);
    openDialog($("dlg-route"));
    const c = $("route-options").querySelector("input:checked") || $("route-options").querySelector("input:not(:disabled)");
    if (c) c.focus();
  }

  $("form-route").addEventListener("submit", (e) => {
    e.preventDefault();
    const d = routeDevice();
    const sel = selectedRoute();
    if (!d || sel === null || sel === (d.proxyId || "")) return;
    closeDialog($("dlg-route"));
    applyRoute(d, sel);
  });

  async function applyRoute(d, proxyId) {
    const name = deviceName(d);
    state.busyIps.add(d.ip);
    rerenderDevice(d.ip);
    try {
      await api("PUT", "/api/devices/" + encodeURIComponent(d.ip) + "/assignment", { mac: d.mac, proxyId: proxyId });
      d.proxyId = proxyId;
      d.assigned = !!proxyId;
      const p = proxyById(proxyId);
      if (proxyId) toast("ok", t("assign.done.proxy.title", { name: name }), t("assign.done.proxy.text", { proxy: (p && p.name) || t("common.proxyGeneric") }));
      else toast("ok", t("assign.done.direct.title", { name: name }), t("assign.done.direct.text"));
    } catch (e) {
      if (e.status === 401) return;
      if (e.data && e.data.applied) {
        d.proxyId = proxyId;
        toast("warn", t("assign.partial"), errorText(e));
      } else {
        toastError(t("assign.failed", { name: name }), e);
      }
    } finally {
      state.busyIps.delete(d.ip);
    }
    await refreshAll(false);
  }

  // ---------------------------------------------------------------------------
  // Device details
  // ---------------------------------------------------------------------------

  let detailIp = null;
  const detailDevice = () => state.devices.find((x) => x.ip === detailIp) || null;

  function infoRow(label, value, note) {
    return [h("dt", { text: label }), h("dd", null, value, note ? h("span", { class: "dd-note", text: note }) : null)];
  }

  function renderDeviceDetails(resetInput) {
    const d = detailDevice();
    if (!d) return;
    const busy = state.busyIps.has(d.ip);
    $("dd-avatar").replaceChildren(deviceAvatar(d, true));
    $("dlg-device-title").textContent = deviceName(d);
    const subId = deviceName(d) === d.ip ? (d.mac || "").toUpperCase() : d.ip;
    $("dd-sub").textContent = [subId, t(d.online ? "device.online" : "device.offline")].filter(Boolean).join(" · ");
    $("dd-exit").replaceChildren(exitCell(d));
    $("btn-device-route").disabled = busy;

    const random = isRandomMac(d.mac);
    const status = t(d.online ? "device.online" : "device.offline") + (d.dhcpStatus ? " · DHCP " + d.dhcpStatus : "");
    const info = $("dd-info");
    info.replaceChildren.apply(info, [].concat(
      infoRow(t("dd.ip"), h("span", { class: "mono", text: d.ip })),
      infoRow(t("dd.mac"), h("span", { class: "dd-val" }, h("span", { class: "mono", text: d.mac || t("device.macUnknown") }), random ? h("span", { class: "tag tone-warn", text: t("device.randomMac.label") }) : null),
        random ? t("device.randomMac.title") : null),
      infoRow(t("dd.hostname"), d.hostname ? h("span", { text: d.hostname }) : h("span", { class: "muted", text: t("dd.none") })),
      d.comment ? infoRow(t("dd.comment"), h("span", { text: d.comment })) : [],
      infoRow(t("dd.lease"), h("span", { text: t(!d.dhcpStatus ? "dd.lease.none" : d.dynamic ? "dd.lease.dynamic" : "dd.lease.static") }),
        t(!d.dhcpStatus ? "dd.lease.noneNote" : d.dynamic ? "dd.lease.dynamicNote" : "dd.lease.staticNote")),
      infoRow(t("dd.status"), h("span", { text: status }))));

    const p = d.proxyId ? proxyById(d.proxyId) : null;
    const pname = p && (p.name || p.host);
    $("dd-flush-text").textContent = [
      !d.proxyId ? t("flush.device.what.direct") : pname ? t("flush.device.what.proxy", { proxy: pname }) : t("flush.device.what.proxyUnknown"),
      t("flush.device.safe"),
    ].join("\n\n");
    $("btn-device-flush").disabled = busy;

    if (resetInput) {
      const input = $("nick-input");
      input.value = d.nickname || "";
      input.removeAttribute("data-i18n-attr");
      input.placeholder = d.hostname || t("nick.placeholder");
    }
  }

  function openDeviceDetails(d) {
    detailIp = d.ip;
    renderDeviceDetails(true);
    openDialog($("dlg-device"));
  }

  $("btn-device-route").addEventListener("click", () => {
    const d = detailDevice();
    if (d) openRoutePicker(d);
  });

  $("btn-device-flush").addEventListener("click", async () => {
    const d = detailDevice();
    if (!d) return;
    const name = deviceName(d);
    const btn = $("btn-device-flush");
    setBusy(btn, true);
    state.busyIps.add(d.ip);
    rerenderDevice(d.ip);
    try {
      await api("POST", "/api/devices/" + encodeURIComponent(d.ip) + "/flush");
      toast("ok", t("flush.device.done.title", { name: name }), t("flush.device.done.text"));
    } catch (e) {
      if (e.status !== 401) toastError(t("flush.device.failed", { name: name }), e);
    } finally {
      state.busyIps.delete(d.ip);
      setBusy(btn, false);
      rerenderDevice(d.ip);
      if ($("dlg-device").open) renderDeviceDetails(false);
    }
  });

  $("form-nickname").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = detailDevice();
    if (!d) return;
    const nickname = $("nick-input").value.trim();
    if (nickname === (d.nickname || "")) return;
    const btn = $("btn-nick-submit");
    setBusy(btn, true);
    try {
      await api("PUT", "/api/devices/" + encodeURIComponent(d.ip) + "/nickname", { nickname: nickname });
      d.nickname = nickname;
      toast("ok", nickname ? t("nick.renamed", { name: nickname }) : t("nick.cleared"));
      renderDeviceDetails(false);
      renderDevices();
    } catch (ex) {
      if (ex.status !== 401) toastError(t("nick.saveFailed"), ex);
    } finally {
      setBusy(btn, false);
    }
  });

  // ---------------------------------------------------------------------------
  // Rendering: proxies
  // ---------------------------------------------------------------------------

  function renderProxies() {
    const ps = proxyStats();
    const sum = clear($("proxy-summary"));
    if (state.loaded.proxies) {
      // Element.append() turns null into the text "null", so drop empty pills.
      sum.append(...[
        pill("idle", t("proxies.count", { count: ps.total }), "globe"),
        pill("ok", t("proxies.countOk", { count: ps.ok }), "check-circle"),
        ps.bad ? pill("bad", t("proxies.countBad", { count: ps.bad }), "alert-circle") : null,
        ps.untested ? pill("idle", t("proxies.countUntested", { count: ps.untested }), "info") : null,
      ].filter(Boolean));
    }
    $("btn-test-all").disabled = ps.total === 0 || state.testing.size > 0;

    const body = $("proxies-body");
    if (!state.loaded.proxies) {
      if (state.loadError.proxies) body.replaceChildren(emptyRow(5, { icon: "alert-circle", title: t("proxies.loadFailed"), text: state.loadError.proxies.message, action: { label: t("common.retry"), run: () => refreshAll(false, true) } }));
      else body.replaceChildren.apply(body, skeletonRows(5, 3));
      return;
    }
    if (state.proxies.length === 0) {
      body.replaceChildren(emptyRow(5, { icon: "globe", title: t("proxies.empty.title"), text: t("proxies.empty.text"), action: { label: t("proxies.empty.action"), run: () => openProxyDialog(null) } }));
      return;
    }
    const q = state.proxySearch.trim().toLowerCase();
    const list = state.proxies.filter((p) => {
      if (!q) return true;
      const lt = p.lastTest || {};
      return [p.name, p.host, p.port, p.protocol, lt.exitIp, lt.country, lt.city, lt.isp].join(" ").toLowerCase().indexOf(q) !== -1;
    }).sort((a, b) => (a.name || "").localeCompare(b.name || "", locale));
    if (list.length === 0) {
      body.replaceChildren(emptyRow(5, { icon: "search", title: t("proxies.noMatch.title"), text: t("proxies.noMatch.text"), action: { label: t("proxies.clearSearch"), run: () => { state.proxySearch = ""; $("proxy-search").value = ""; renderProxies(); } } }));
      return;
    }
    body.replaceChildren.apply(body, list.map(proxyRow));
  }

  // Connection details worth knowing at a glance. Secrets are never shown.
  function proxyDetails(p) {
    const out = [];
    const item = (label, value, title) => {
      if (!value) return;
      out.push(h("span", { class: "px-detail", title: title || label + ": " + value },
        h("span", { class: "px-detail-k", text: label }), h("span", { class: "px-detail-v", text: value })));
    };
    const tr = (p.transport || "").toLowerCase();
    if (tr === "ws") item("Transport", "WebSocket" + (p.wsPath ? " " + p.wsPath : ""));
    else if (tr === "grpc") item("Transport", "gRPC" + (p.grpcServiceName ? " " + p.grpcServiceName : ""));
    else if (tr && tr !== "tcp") item("Transport", tr.toUpperCase());
    item("SNI", p.sni, t("detail.sni.title", { sni: p.sni }));
    item("Flow", p.flow);
    item(t("detail.fingerprint"), p.fingerprint, t("detail.fingerprint.title", { fingerprint: p.fingerprint }));
    if (p.protocol === "shadowsocks") item(t("detail.cipher"), p.method);
    if (p.username || p.hasPassword || p.hasUuid) {
      item(t("detail.auth"), p.username ? t("detail.auth.user", { user: p.username }) : t("detail.auth.key"), t("detail.auth.title"));
    }
    out.push(p.udp
      ? h("span", { class: "px-detail tone-ok", title: t("detail.udp.title") }, h("span", { class: "px-detail-v", text: t("detail.udp") }))
      : h("span", { class: "px-detail", title: t("detail.tcpOnly.title") }, h("span", { class: "px-detail-v", text: t("detail.tcpOnly") })));
    return out;
  }

  // Devices routed through a proxy, as clickable chips (online first).
  function usersCell(users) {
    if (!users.length) return h("span", { class: "muted px-sub", text: t("users.none") });
    const MAX = 4;
    const sorted = users.slice().sort((a, b) => (Number(!!b.online) - Number(!!a.online)) || (ipKey(a.ip) - ipKey(b.ip)));
    const chips = sorted.slice(0, MAX).map((d) => h("button", {
      class: "dev-chip tone-" + (d.online ? "ok" : "idle"), type: "button",
      title: t("users.chipTitle", { name: deviceName(d), ip: d.ip, status: t(d.online ? "device.online" : "device.offline") }),
      onclick: () => jumpToDevice(d),
    }, h("span", { class: "dot" }), h("span", { class: "dev-chip-name", text: deviceName(d) })));
    if (sorted.length > MAX) {
      chips.push(h("span", { class: "tag", title: sorted.slice(MAX).map(deviceName).join(", "), text: "+" + fmtNum(sorted.length - MAX) }));
    }
    const online = users.filter((d) => d.online).length;
    return h("div", { class: "dev-chips-wrap" },
      h("div", { class: "dev-chips" }, chips),
      h("div", { class: "px-sub", text: t("users.summary", { count: users.length, online: online }) }));
  }

  function jumpToDevice(d) {
    state.search = d.ip;
    $("device-search").value = d.ip;
    if (location.hash !== "#overview") {
      location.hash = "#overview";
      // Switch views now so the later hashchange does not reset the scroll position.
      route(false);
    }
    renderDevices();
    // scrollIntoView forces layout synchronously, so no frame callback is needed.
    const row = $("devices-body").querySelector('li[data-ip="' + CSS.escape(d.ip) + '"]');
    if (row) {
      row.scrollIntoView({ block: "center" });
      row.classList.add("is-flash");
      setTimeout(() => row.classList.remove("is-flash"), 1600);
    }
  }

  function proxyRow(p) {
    const lt = p.lastTest || null;
    const testing = state.testing.has(p.id);
    const users = devicesUsing(p.id);

    let testCell;
    if (testing) {
      testCell = h("div", { class: "px-test-line" }, h("span", { class: "spinner", "aria-hidden": "true" }), h("span", { class: "px-sub", text: t("test.running") }));
    } else if (!lt || !lt.status) {
      testCell = h("div", { class: "px-test" }, h("div", { class: "px-test-line" }, pill("idle", t("test.untested"), null, true)));
    } else if (lt.status === "ok") {
      const place = [countryName(lt), lt.city].filter(Boolean).join(", ");
      testCell = h("div", { class: "px-test" },
        h("div", { class: "px-test-line" }, pill("ok", t("test.ok"), null, true), lt.exitIp ? h("span", { class: "mono", text: lt.exitIp, title: t("test.exitIpTitle") }) : null),
        place ? h("div", { class: "px-place" }, flagEl(lt), h("span", { text: place })) : null,
        h("div", { class: "px-sub", text: [lt.isp, t("test.testedAgo", { ago: fmtAgo(lt.testedAt) })].filter(Boolean).join(" · "), title: fmtDateTime(lt.testedAt) }));
    } else {
      testCell = h("div", { class: "px-test" },
        h("div", { class: "px-test-line" }, pill("bad", t("test.failed"), null, true), h("span", { class: "px-sub", text: fmtAgo(lt.testedAt), title: fmtDateTime(lt.testedAt) })),
        lt.error ? h("div", { class: "px-test-err", text: lt.error, title: lt.error }) : null);
    }

    const lat = lt && lt.status === "ok" && lt.latencyMs ? h("span", { class: "latency tone-" + latencyTone(lt.latencyMs), text: fmtNum(lt.latencyMs) + " ms" }) : h("span", { class: "muted", text: "-" });

    const inUse = users.length > 0;
    const pname = p.name || p.host;
    const delBtn = h("button", {
      class: "btn btn-icon btn-sm btn-ghost", type: "button",
      "aria-label": inUse ? t("proxy.delete.blockedAria", { count: users.length }) : t("proxy.delete.aria", { name: pname }),
      title: inUse ? t("proxy.delete.blockedTitle", { count: users.length }) : t("proxy.delete.title"),
      "aria-disabled": inUse ? "true" : null,
      onclick: () => { if (inUse) toast("info", t("proxy.inUse.title"), t("proxy.inUse.text", { devices: users.map(deviceName).join(", ") })); else deleteProxy(p); },
    }, icon("trash", "ic-sm"));

    return h("tr", { dataset: { id: p.id }, class: testing ? "is-busy" : "" },
      h("td", { class: "cell-main" },
        h("div", { class: "px-head" },
          flagEl(lt && lt.status === "ok" ? lt : null, true),
          h("div", { style: "min-width:0" },
            h("div", { class: "px-name" }, h("span", { text: p.name || p.host }), h("span", { class: "tag tag-proto", text: PROTO_LABEL[p.protocol] || p.protocol }),
              p.tls || p.protocol === "https" || p.protocol === "trojan" || p.security === "tls" ? h("span", { class: "tag", title: t("proxy.tlsTitle") }, icon("lock", "ic-sm"), "TLS") : null,
              p.security === "reality" ? h("span", { class: "tag", title: t("proxy.realityTitle") }, icon("lock", "ic-sm"), "REALITY") : null),
            h("div", { class: "px-host", text: p.host + ":" + p.port }))),
        h("div", { class: "px-details" }, proxyDetails(p))),
      h("td", { "data-label": t("col.testResult"), class: "cell-full" }, testCell),
      h("td", { "data-label": t("col.latency") }, lat),
      h("td", { "data-label": t("col.users"), class: "cell-full" }, usersCell(users)),
      h("td", { class: "col-actions" },
        h("div", { class: "row-actions" },
          h("button", { class: "btn btn-sm btn-secondary", type: "button", disabled: testing, onclick: () => testProxy(p.id) }, icon("activity", "ic-sm"), h("span", { class: "hide-sm", text: t("proxy.test") })),
          h("button", { class: "btn btn-icon btn-sm btn-ghost", type: "button", "aria-label": t("proxy.edit.aria", { name: pname }), title: t("proxy.edit.title"), onclick: () => openProxyDialog(p.id) }, icon("edit", "ic-sm")),
          delBtn)));
  }

  $("proxy-search").addEventListener("input", (e) => { state.proxySearch = e.target.value; renderProxies(); });

  async function testProxy(id, silent) {
    if (state.testing.has(id)) return null;
    state.testing.add(id);
    renderProxies();
    let result = null;
    const p = proxyById(id);
    const name = p ? p.name || p.host : t("common.proxyGeneric");
    try {
      result = await api("POST", "/api/proxies/" + encodeURIComponent(id) + "/test");
      if (p && result) p.lastTest = result;
      if (!silent) {
        if (result && result.status === "ok") toast("ok", t("test.toast.ok", { name: name }), [result.exitIp, [result.city, result.countryCode].filter(Boolean).join(", "), result.latencyMs ? fmtNum(result.latencyMs) + " ms" : ""].filter(Boolean).join(" · "));
        else toast("bad", t("test.toast.bad", { name: name }), (result && result.error) || t("test.toast.failed"));
      }
    } catch (e) {
      if (e.status !== 401 && !silent) toastError(t("test.toast.error", { name: name }), e);
    } finally {
      state.testing.delete(id);
      renderProxies();
      if (state.loaded.devices) renderDevices();
      renderChrome();
      renderAttention();
      renderMetrics();
    }
    return result;
  }

  $("btn-test-all").addEventListener("click", async () => {
    const btn = $("btn-test-all");
    const ids = state.proxies.map((p) => p.id);
    if (!ids.length) return;
    let ok = 0;
    for (let i = 0; i < ids.length; i++) {
      setBusy(btn, true, t("test.all.progress", { current: i + 1, total: ids.length }));
      const r = await testProxy(ids[i], true);
      if (r && r.status === "ok") ok++;
      if ($("app-view").hidden) break;
    }
    setBusy(btn, false);
    renderProxies();
    toast(ok === ids.length ? "ok" : "warn", t("test.all.done", { count: ids.length }), t("test.all.summary", { ok: ok, bad: ids.length - ok }));
    refreshAll(false);
  });

  async function deleteProxy(p) {
    const name = p.name || p.host;
    const ok = await confirmAction({ tone: "bad", icon: "trash", title: t("proxy.delete.confirmTitle", { name: name }), text: p.host + ":" + p.port + "\n" + t("proxy.delete.irreversible"), ok: t("proxy.delete.title") });
    if (!ok) return;
    try {
      await api("DELETE", "/api/proxies/" + encodeURIComponent(p.id));
      state.proxies = state.proxies.filter((x) => x.id !== p.id);
      renderProxies();
      toast("ok", t("proxy.delete.done", { name: name }));
    } catch (e) {
      if (e.status === 401) return;
      if (e.status === 409) {
        const devs = (e.data && e.data.devices) || [];
        toast("warn", t("proxy.inUse.title"), (e.message || "") + (devs.length ? "\n" + t("proxy.inUse.devices", { devices: devs.join(", ") }) : ""));
      } else {
        toastError(t("proxy.delete.failed"), e);
      }
    }
    refreshAll(false);
  }

  // ---------------------------------------------------------------------------
  // Proxy dialog (add via paste/manual, edit)
  // ---------------------------------------------------------------------------

  const PF = (id) => $("pf-" + id);
  let editing = null; // full proxy object from GET when editing, else null

  // Which field groups apply to the selected protocol.
  function visibility(proto) {
    const tls = PF("tls").checked;
    const sec = PF("security").value;
    const transport = PF("transport").value;
    const isV2 = proto === "trojan" || proto === "vless" || proto === "vmess";
    const tlsOpts = proto === "https" || (proto === "http" && tls) || proto === "trojan" ||
      (proto === "vless" && (sec === "tls" || sec === "reality")) || (proto === "vmess" && tls);
    return {
      auth: ["http", "https", "socks5", "shadowsocks", "trojan"].includes(proto),
      username: ["http", "https", "socks5"].includes(proto),
      password: ["http", "https", "socks5", "shadowsocks", "trojan"].includes(proto),
      method: proto === "shadowsocks",
      uuid: proto === "vless" || proto === "vmess",
      vmess: proto === "vmess",
      vless: proto === "vless",
      tlsToggle: proto === "http" || proto === "vmess",
      tlsOpts: tlsOpts,
      fingerprint: proto === "vless" && (sec === "tls" || sec === "reality"),
      reality: proto === "vless" && sec === "reality",
      flow: proto === "vless",
      transport: isV2,
      ws: isV2 && transport === "ws",
      grpc: isV2 && transport === "grpc",
      udp: proto !== "http" && proto !== "https",
    };
  }

  const PORT_HINT = { http: "8080", https: "443", socks5: "1080", shadowsocks: "8388", trojan: "443", vless: "443", vmess: "443" };

  function applyVisibility() {
    const proto = PF("protocol").value;
    const vis = visibility(proto);
    document.querySelectorAll("#form-proxy [data-show]").forEach((el) => { el.hidden = !vis[el.dataset.show]; });
    // Username only for http/https/socks5; the auth grid also hosts the password.
    PF("username").closest(".field").hidden = !vis.username;
    const required = proto === "shadowsocks" || proto === "trojan";
    $("pf-password-req").hidden = !required;
    setKeyed($("pf-password-label"), proto === "shadowsocks" || proto === "trojan" ? "proxyForm.passwordKey" : "proxyForm.password");
    PF("port").placeholder = PORT_HINT[proto] || "";
    // Hints for stored secrets apply only when the protocol did not change.
    const sameProto = editing && editing.protocol === proto;
    $("pf-password-hint").hidden = !(sameProto && editing.hasPassword);
    $("pf-uuid-hint").hidden = !(sameProto && editing.hasUuid);
    // Auto-open "advanced" when a WS/gRPC/REALITY field needs input.
    if (vis.reality && !PF("advanced").open) PF("advanced").open = true;
  }

  ["protocol", "tls", "security", "transport"].forEach((id) => PF(id).addEventListener("change", applyVisibility));

  function setFieldError(id, msg) {
    const input = PF(id);
    const err = $("pf-" + id + "-err");
    if (msg) {
      input.setAttribute("aria-invalid", "true");
      input.setAttribute("aria-describedby", "pf-" + id + "-err");
      if (err) { err.textContent = msg; err.hidden = false; }
    } else {
      input.removeAttribute("aria-invalid");
      input.removeAttribute("aria-describedby");
      if (err) { err.textContent = ""; err.hidden = true; }
    }
  }

  function clearFormErrors() {
    ["host", "port", "password", "uuid", "publickey"].forEach((id) => setFieldError(id, ""));
    $("proxy-form-error").hidden = true;
  }

  ["host", "port", "password", "uuid", "publickey"].forEach((id) => PF(id).addEventListener("input", () => setFieldError(id, "")));

  function selectTab(which, focus) {
    const paste = which === "paste";
    $("tab-paste").setAttribute("aria-selected", String(paste));
    $("tab-manual").setAttribute("aria-selected", String(!paste));
    $("tab-paste").tabIndex = paste ? 0 : -1;
    $("tab-manual").tabIndex = paste ? -1 : 0;
    $("form-import").hidden = !paste;
    $("form-proxy").hidden = paste;
    if (focus) (paste ? $("import-text") : PF("name")).focus();
  }

  $("tab-paste").addEventListener("click", () => selectTab("paste", true));
  $("tab-manual").addEventListener("click", () => selectTab("manual", true));
  $("proxy-tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const toManual = $("tab-paste").getAttribute("aria-selected") === "true" ? e.key !== "Home" : e.key === "End";
    selectTab(toManual ? "manual" : "paste", false);
    (toManual ? $("tab-manual") : $("tab-paste")).focus();
  });

  function fillForm(p) {
    p = p || {};
    PF("name").value = p.name || "";
    PF("protocol").value = p.protocol || "socks5";
    PF("host").value = p.host || "";
    PF("port").value = p.port || "";
    PF("username").value = p.username || "";
    PF("password").value = "";
    PF("method").value = p.method || "";
    PF("uuid").value = "";
    PF("alterid").value = p.alterId || "";
    if (p.protocol === "vmess") PF("cipher").value = p.security || "auto";
    else PF("cipher").value = "auto";
    PF("security").value = p.protocol === "vless" && ["none", "tls", "reality"].includes(p.security) ? p.security : p.protocol === "vless" && p.tls ? "tls" : "none";
    PF("tls").checked = !!p.tls;
    PF("sni").value = p.sni || "";
    PF("fingerprint").value = p.fingerprint || "";
    PF("publickey").value = p.publicKey || "";
    PF("shortid").value = p.shortId || "";
    PF("flow").value = p.flow || "";
    PF("transport").value = p.transport === "ws" || p.transport === "grpc" ? p.transport : "";
    PF("wspath").value = p.wsPath || "";
    PF("wshost").value = p.wsHost || "";
    PF("grpc").value = p.grpcServiceName || "";
    PF("insecure").checked = !!p.insecure;
    PF("udp").checked = !!p.udp;
    resetReveal(PF("password"));
    resetReveal(PF("uuid"));
    PF("advanced").open = !!(p.sni || p.fingerprint || p.publicKey || p.flow || p.transport === "ws" || p.transport === "grpc" || p.insecure || p.udp);
    clearFormErrors();
    applyVisibility();
  }

  // Collects every field; fields that do not apply to the protocol are reset
  // so stale values (for example a WS path after switching to SOCKS5) are not
  // sent to the server.
  function collectAll() {
    const proto = PF("protocol").value;
    const vis = visibility(proto);
    const val = (id) => PF(id).value.trim();
    const out = {
      name: val("name"),
      protocol: proto,
      host: val("host"),
      port: val("port") === "" ? parseInt(PORT_HINT[proto], 10) || 0 : Number(val("port")),
      username: vis.username ? val("username") : "",
      password: vis.password ? PF("password").value : "",
      method: vis.method ? val("method") : "",
      uuid: vis.uuid ? val("uuid") : "",
      alterId: vis.vmess ? parseInt(val("alterid"), 10) || 0 : 0,
      security: "",
      tls: false,
      sni: vis.tlsOpts ? val("sni") : "",
      insecure: vis.tlsOpts ? PF("insecure").checked : false,
      fingerprint: vis.fingerprint ? PF("fingerprint").value : "",
      publicKey: vis.reality ? val("publickey") : "",
      shortId: vis.reality ? val("shortid") : "",
      flow: vis.flow ? PF("flow").value : "",
      transport: vis.transport ? PF("transport").value : "",
      wsPath: vis.ws ? val("wspath") : "",
      wsHost: vis.ws ? val("wshost") : "",
      grpcServiceName: vis.grpc ? val("grpc") : "",
      udp: vis.udp ? PF("udp").checked : false,
    };
    if (proto === "vmess") { out.security = PF("cipher").value; out.tls = PF("tls").checked; }
    else if (proto === "vless") { out.security = PF("security").value; out.tls = out.security === "tls"; }
    else if (proto === "http") out.tls = PF("tls").checked;
    else if (proto === "https" || proto === "trojan") out.tls = true;
    return out;
  }

  const HOST_RE = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;
  const IPV6_RE = /^\[?[0-9A-Fa-f:.]+\]?$/;

  function validate(data) {
    let first = null;
    const fail = (id, msg) => { setFieldError(id, msg); if (!first) first = id; };
    if (!data.host) fail("host", t("validate.hostRequired"));
    else if (!HOST_RE.test(data.host) && !(data.host.indexOf(":") !== -1 && IPV6_RE.test(data.host))) fail("host", t("validate.hostInvalid"));
    if (!(Number.isInteger(data.port) && data.port >= 1 && data.port <= 65535)) fail("port", t("validate.portRange"));
    const keepSecret = editing && editing.protocol === data.protocol;
    if ((data.protocol === "shadowsocks" || data.protocol === "trojan") && !data.password && !(keepSecret && editing.hasPassword)) fail("password", t("validate.passwordRequired"));
    if ((data.protocol === "vless" || data.protocol === "vmess") && !data.uuid && !(keepSecret && editing.hasUuid)) fail("uuid", t("validate.uuidRequired"));
    if (data.protocol === "vless" && data.security === "reality" && !data.publicKey) { fail("publickey", t("validate.publicKeyRequired")); PF("advanced").open = true; }
    if (first) {
      const el = PF(first);
      const det = el.closest("details");
      if (det) det.open = true;
      el.focus();
    }
    return !first;
  }

  // Text bound to a catalog key through data-i18n, so I18N.apply() keeps it current.
  function setKeyed(el, key) {
    if (!el) return;
    el.setAttribute("data-i18n", key);
    el.textContent = t(key);
  }

  function renderProxyDialogTitle() {
    const el = $("dlg-proxy-title");
    if (!editing) { setKeyed(el, "proxyForm.titleAdd"); return; }
    el.removeAttribute("data-i18n");
    el.textContent = t("proxyForm.titleEdit", { name: editing.name || editing.host });
  }

  async function openProxyDialog(id) {
    const dlg = $("dlg-proxy");
    editing = null;
    $("import-result").hidden = true;
    if (!id) {
      renderProxyDialogTitle();
      $("proxy-tabs").hidden = false;
      $("import-text").value = "";
      setKeyed($("btn-proxy-submit").querySelector(".btn-label"), "proxyForm.submitAdd");
      fillForm(null);
      selectTab("paste", false);
      openDialog(dlg);
      $("import-text").focus();
      return;
    }
    let p;
    try {
      p = await api("GET", "/api/proxies/" + encodeURIComponent(id));
    } catch (e) {
      if (e.status !== 401) toastError(t("proxyForm.openFailed"), e);
      return;
    }
    editing = p;
    renderProxyDialogTitle();
    $("proxy-tabs").hidden = true;
    setKeyed($("btn-proxy-submit").querySelector(".btn-label"), "proxyForm.submitEdit");
    fillForm(p);
    selectTab("manual", false);
    openDialog(dlg);
    PF("name").focus();
  }

  $("btn-add-proxy").addEventListener("click", () => openProxyDialog(null));
  $("dlg-proxy").addEventListener("close", () => { editing = null; });

  $("form-proxy").addEventListener("submit", async (e) => {
    e.preventDefault();
    clearFormErrors();
    const data = collectAll();
    if (!validate(data)) return;
    const btn = $("btn-proxy-submit");
    const errBox = $("proxy-form-error");
    let payload = data;
    if (editing) {
      // PUT replaces the whole proxy: start from the stored record so fields
      // this form does not show are preserved, then overlay the form values.
      const base = Object.assign({}, editing);
      ["id", "createdAt", "updatedAt", "lastTest", "hasPassword", "hasUuid"].forEach((k) => delete base[k]);
      payload = Object.assign(base, data);
      // Empty secret with the same protocol means "keep the stored value".
      if (!payload.password) delete payload.password;
      if (!payload.uuid) delete payload.uuid;
    }
    setBusy(btn, true);
    try {
      if (editing) {
        await api("PUT", "/api/proxies/" + encodeURIComponent(editing.id), payload);
        closeDialog($("dlg-proxy"));
        toast("ok", t("proxyForm.saved.title", { name: payload.name || payload.host }), t("proxyForm.saved.text"));
      } else {
        const created = await api("POST", "/api/proxies", payload);
        closeDialog($("dlg-proxy"));
        const cid = created && created.id;
        toast("ok", t("proxyForm.added.title", { name: (created && created.name) || payload.host }), t("proxyForm.added.text"),
          cid ? { actions: [{ label: t("exit.testNow"), run: () => testProxy(cid) }] } : null);
      }
      await refreshAll(false);
    } catch (ex) {
      if (ex.status === 401) return;
      clear(errBox).append(icon("alert-circle"), h("span", { text: errorText(ex) }));
      errBox.hidden = false;
    } finally {
      setBusy(btn, false);
    }
  });

  $("form-import").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("import-text").value;
    const result = $("import-result");
    if (!text.trim()) {
      clear(result).append(h("div", { class: "inline-alert tone-warn" }, icon("alert"), h("span", { text: t("import.empty") })));
      result.hidden = false;
      $("import-text").focus();
      return;
    }
    const btn = $("btn-import-submit");
    setBusy(btn, true);
    try {
      const res = await api("POST", "/api/proxies/import", { text: text, defaultProto: $("import-proto").value });
      const n = (res && res.imported) || 0;
      const errs = (res && res.errors) || [];
      await refreshAll(false);
      if (!errs.length) {
        closeDialog($("dlg-proxy"));
        toast("ok", t("import.done", { count: n }), t("import.doneHint"),
          { actions: [{ label: t("import.testAll"), run: () => $("btn-test-all").click() }] });
      } else {
        clear(result).append(h("div", { class: "inline-alert tone-warn" }, icon("alert"),
          h("div", null,
            h("div", { text: t("import.done", { count: n }) + " " + t("import.skipped", { count: errs.length }) }),
            h("ul", { class: "import-errors" }, errs.slice(0, 50).map((x) => h("li", { text: String(x) }))))));
        result.hidden = false;
        if (n) toast("ok", t("import.done", { count: n }));
      }
    } catch (ex) {
      if (ex.status === 401) return;
      const errs = (ex.data && ex.data.errors) || [];
      clear(result).append(h("div", { class: "inline-alert tone-bad" }, icon("alert-circle"),
        h("div", null,
          h("div", { text: ex.message || t("import.failed") }),
          errs.length ? h("ul", { class: "import-errors" }, errs.slice(0, 50).map((x) => h("li", { text: String(x) }))) : null)));
      result.hidden = false;
    } finally {
      setBusy(btn, false);
    }
  });

  // ---------------------------------------------------------------------------
  // Rendering: leak guard
  // ---------------------------------------------------------------------------

  function renderLeakGuard() {
    const mbox = clear($("lg-metrics"));
    const lbox = clear($("lg-layers"));
    if (!state.loaded.status) {
      if (state.loadError.status) {
        lbox.append(h("div", { class: "card" }, h("div", { class: "empty" }, h("div", { class: "empty-icon" }, icon("alert-circle")), h("div", { class: "empty-title", text: t("lg.loadFailed") }), h("div", { class: "empty-text", text: state.loadError.status.message }))));
      } else {
        mbox.append(skeletonMetrics(4));
      }
      return;
    }
    const lg = (state.status && state.status.leakGuard) || {};
    const o = overall();
    const layers = lg.layers || [];
    const okCount = layers.filter((l) => l.status === "ok").length;
    mbox.append(
      metric({ icon: o.icon, label: t("lg.overall"), value: o.title, sub: t("lg.layersActive", { ok: okCount, total: layers.length }), tone: o.tone }),
      metric({ icon: "router", label: t("lg.router.label"), value: t(lg.routerReachable ? "lg.router.connected" : "lg.router.disconnected"), sub: t(lg.routerReachable ? "lg.router.okSub" : "lg.router.badSub"), tone: lg.routerReachable ? "ok" : "bad" }),
      metric({ icon: "ban", label: t("metric.killSwitch.label"), value: fmtNum(lg.killSwitchPackets), unit: t("metric.unit.packets", { count: Number(lg.killSwitchPackets) || 0 }), sub: fmtBytes(lg.killSwitchBytes), tone: "warn" }),
      metric({ icon: "dna", label: t("metric.ipv6.label"), value: fmtNum(lg.ipv6BlockedPackets), unit: t("metric.unit.packets", { count: Number(lg.ipv6BlockedPackets) || 0 }), sub: fmtBytes(lg.ipv6BlockedBytes), tone: "idle" }));
    mbox.firstChild.querySelector(".metric-value").style.fontSize = "19px";
    mbox.children[1].querySelector(".metric-value").style.fontSize = "19px";

    if (!layers.length) {
      lbox.append(h("div", { class: "card" }, h("div", { class: "empty" }, h("div", { class: "empty-icon" }, icon("shield-question")), h("div", { class: "empty-title", text: t("lg.empty.title") }), h("div", { class: "empty-text", text: t("lg.empty.text") }))));
      return;
    }
    layers.forEach((layer, i) => {
      const info = layerInfo(layer, i);
      lbox.append(h("article", { class: "layer tone-" + info.tone, "aria-label": t("layer.aria", { num: info.num, title: info.title, status: info.statusText }) },
        h("div", { class: "layer-head" },
          h("div", { class: "layer-num", text: String(info.num) }),
          h("div", { style: "min-width:0" }, h("h3", { class: "layer-title", text: info.title }), info.raw && info.raw !== info.title ? h("div", { class: "layer-raw", text: info.raw }) : null),
          pill(info.tone, info.statusText, null, true)),
        layer.description ? h("p", { class: "layer-desc", text: layer.description }) : null,
        layer.details ? h("div", { class: "layer-details", text: layer.details }) : null));
    });
  }

  async function reconcile() {
    const btn = $("btn-reconcile");
    setBusy(btn, true);
    try {
      await api("POST", "/api/system/reconcile");
      toast("ok", t("reconcile.done.title"), t("reconcile.done.text"));
    } catch (e) {
      if (e.status !== 401) toastError(t("reconcile.failed"), e);
    } finally {
      setBusy(btn, false);
    }
    refreshAll(false);
  }

  $("btn-reconcile").addEventListener("click", reconcile);

  $("btn-flush-all").addEventListener("click", async () => {
    const ok = await confirmAction({
      tone: "bad", icon: "scissors",
      title: t("flush.all.title"),
      text: [t("flush.all.what"), t("flush.all.when"), t("flush.all.safe")].join("\n\n"),
      ok: t("flush.all.ok"),
    });
    if (!ok) return;
    const btn = $("btn-flush-all");
    setBusy(btn, true);
    try {
      await api("POST", "/api/system/flush-all");
      toast("ok", t("flush.all.done.title"), t("flush.all.done.text"));
    } catch (e) {
      if (e.status !== 401) toastError(t("flush.all.failed"), e);
    } finally {
      setBusy(btn, false);
    }
  });

  // ---------------------------------------------------------------------------
  // Rendering: logs
  // ---------------------------------------------------------------------------

  function renderSingbox() {
    const sb = state.status && state.status.singbox;
    const sp = $("sb-pill");
    const kv = clear($("sb-kv"));
    const err = $("sb-error");
    if (!sb) {
      setTone(sp, "idle");
      setKeyed(sp.querySelector(".pill-text"), state.loadError.status ? "singbox.unknown" : "common.loadingShort");
      err.hidden = true;
      return;
    }
    setTone(sp, sb.running ? (sb.lastError ? "warn" : "ok") : "bad");
    setKeyed(sp.querySelector(".pill-text"), sb.running ? "singbox.running" : "singbox.stopped");
    const rows = [
      ["PID", sb.pid ? String(sb.pid) : "-", true],
      [t("singbox.version"), sb.version || "-", true],
      [t("singbox.lastReload"), fmtDateTime(sb.lastReload), false],
      [t("singbox.configFile"), sb.configPath || "-", true],
    ];
    rows.forEach((r) => kv.append(h("div", null, h("dt", { text: r[0] }), h("dd", { class: r[2] ? "mono" : "", text: r[1] }))));
    if (sb.lastError) {
      clear(err).append(icon("alert-circle"), h("div", null, h("strong", { text: t("singbox.lastError") + " " }), sb.lastError));
      err.hidden = false;
    } else {
      err.hidden = true;
    }
  }

  function logLevel(line) {
    if (/\b(ERROR|ERRO|FATAL|PANIC)\b|level=error|"level":"error"/i.test(line)) return "error";
    if (/\b(WARN|WARNING)\b|level=warn/i.test(line)) return "warn";
    return "";
  }

  function renderLogs() {
    const box = $("log-box");
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    const q = state.logFilter.trim().toLowerCase();
    const all = state.logs || [];
    const lines = q ? all.filter((l) => String(l).toLowerCase().indexOf(q) !== -1) : all;
    const errors = all.filter((l) => logLevel(String(l)) === "error").length;
    const sub = $("logs-sub");
    sub.removeAttribute("data-i18n");
    if (state.loaded.logs) {
      const parts = [t("logs.lines", { count: all.length })];
      if (errors) parts.push(t("logs.errors", { count: errors }));
      if (q) parts.push(t("logs.matching", { count: lines.length }));
      sub.textContent = t("logs.summary", { parts: parts.join(t("common.listSeparator")) });
    } else {
      sub.textContent = t("logs.sub");
    }
    if (!state.loaded.logs) {
      box.replaceChildren(h("div", { class: "log-empty", text: state.loadError.logs ? t("logs.loadFailed", { error: state.loadError.logs.message }) : t("logs.loading") }));
      return;
    }
    if (!lines.length) {
      box.replaceChildren(h("div", { class: "log-empty", text: q ? t("logs.noMatch", { query: state.logFilter }) : t("logs.empty") }));
      return;
    }
    const frag = document.createDocumentFragment();
    lines.forEach((raw) => {
      const line = String(raw);
      const lvl = logLevel(line);
      const div = h("div", { class: "log-line" + (lvl ? " lvl-" + lvl : "") });
      if (q) {
        const lower = line.toLowerCase();
        let i = 0;
        let pos;
        while ((pos = lower.indexOf(q, i)) !== -1) {
          div.append(line.slice(i, pos), h("mark", { text: line.slice(pos, pos + q.length) }));
          i = pos + q.length;
        }
        div.append(line.slice(i));
      } else {
        div.textContent = line;
      }
      frag.append(div);
    });
    box.replaceChildren(frag);
    if (atBottom || !box.dataset.scrolled) { box.scrollTop = box.scrollHeight; box.dataset.scrolled = "1"; }
  }

  $("log-filter").addEventListener("input", (e) => { state.logFilter = e.target.value; renderLogs(); });
  $("btn-logs-refresh").addEventListener("click", () => loadLogs(true));

  $("btn-logs-copy").addEventListener("click", async () => {
    const text = (state.logs || []).join("\n");
    if (!text) { toast("info", t("logs.copy.empty")); return; }
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); ok = true; }
    } catch (e) { ok = false; }
    if (!ok) {
      // Clipboard API needs HTTPS; the dashboard is usually served over plain HTTP on the LAN.
      const ta = h("textarea", { style: "position:fixed;top:-1000px;opacity:0", readonly: true });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
    }
    if (ok) toast("ok", t("logs.copy.done", { count: state.logs.length }));
    else toast("bad", t("logs.copy.failed.title"), t("logs.copy.failed.text"));
  });

  // ---------------------------------------------------------------------------
  // Keyboard shortcuts
  // ---------------------------------------------------------------------------

  document.addEventListener("keydown", (e) => {
    if ($("app-view").hidden || anyDialogOpen()) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const el = e.target;
    const typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
    if (e.key === "Escape" && typing && el.type === "search" && el.value) {
      el.value = "";
      el.dispatchEvent(new Event("input"));
      return;
    }
    if (typing) return;
    if (e.key === "/") {
      const map = { overview: "device-search", proxies: "proxy-search", logs: "log-filter" };
      const target = map[state.view] && $(map[state.view]);
      if (target) { e.preventDefault(); target.focus(); }
    } else if (e.key === "r" || e.key === "R") {
      e.preventDefault();
      refreshAll(false, true);
    }
  });

  // ---------------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------------

  async function boot() {
    try {
      const me = await api("GET", "/api/auth/me");
      if (me && me.authenticated) showApp();
      else showLogin();
    } catch (e) {
      showLogin(e.status === 0 ? { key: "error.network" } : null);
    }
  }

  // ---------------------------------------------------------------------------
  // Language
  // ---------------------------------------------------------------------------

  function syncLangSelects() {
    document.querySelectorAll("select.lang-select").forEach((sel) => { sel.value = window.I18N.lang; });
  }

  function initLangSelects() {
    document.querySelectorAll("select.lang-select").forEach((sel) => {
      sel.replaceChildren.apply(sel, window.I18N.languages.map((l) => h("option", { value: l.code, lang: l.code, text: l.name })));
      sel.value = window.I18N.lang;
      sel.addEventListener("change", () => {
        sel.disabled = true;
        window.I18N.setLang(sel.value).finally(() => { sel.disabled = false; syncLangSelects(); });
      });
    });
  }

  // Re-render everything that was built from catalog strings, then re-fetch so
  // server-localized texts (API errors, layer descriptions) follow the new language.
  window.I18N.onChange(() => {
    refreshLocale();
    syncLangSelects();
    syncThemeButton();
    syncRevealLabels();
    renderLoginError();
    if ($("dlg-device").open) renderDeviceDetails(false);
    if ($("dlg-route").open) renderRoutePicker(false);
    if ($("dlg-proxy").open) { renderProxyDialogTitle(); applyVisibility(); }
    document.title = t("app.documentTitle", { page: t("nav." + state.view) });
    if ($("app-view").hidden) return;
    renderAll();
    if (state.refreshing) state.refreshQueued = true;
    else refreshAll(false);
  });

  window.I18N.ready.then(() => {
    window.I18N.apply(document);
    refreshLocale();
    initLangSelects();
    syncThemeButton();
    syncRevealLabels();
    boot();
  });
})();
