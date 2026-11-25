/* Proxy Gateway: minimal i18n runtime.
 * Classic script, loaded in <head> after theme.js and before app.js.
 *
 * Catalogs are flat JSON files at locales/<code>.json. English is always
 * loaded as the fallback. Keys use dotted names; placeholders use {name};
 * plural forms use the suffixes _zero/_one/_two/_few/_many/_other selected by
 * Intl.PluralRules from a numeric `count` param.
 *
 * Contract with the backend: the chosen language is stored in localStorage
 * "pgw-lang" and in the cookie "pgw_lang" so the server can localize API
 * messages.
 */
(function () {
  "use strict";

  var DEFAULT_LANG = "en";
  var STORAGE_KEY = "pgw-lang";
  var COOKIE_NAME = "pgw_lang";
  var LANGUAGES = [
    { code: "en", name: "English", locale: "en-US", htmlLang: "en" },
    { code: "vi", name: "Tiếng Việt", locale: "vi-VN", htmlLang: "vi" },
    { code: "zh", name: "简体中文", locale: "zh-CN", htmlLang: "zh-CN" },
    { code: "ru", name: "Русский", locale: "ru-RU", htmlLang: "ru" },
    { code: "ko", name: "한국어", locale: "ko-KR", htmlLang: "ko" }
  ];
  var BY_CODE = {};
  LANGUAGES.forEach(function (l) { BY_CODE[l.code] = l; });

  var catalogs = {};       // code -> flat object
  var pending = {};        // code -> Promise<object>
  var listeners = [];
  var pluralRules = null;
  var numberFormat = null;

  function normalize(code) {
    if (!code) return null;
    var c = String(code).trim().toLowerCase();
    if (BY_CODE[c]) return c;
    var base = c.split(/[-_]/)[0];
    return BY_CODE[base] ? base : null;
  }

  function readStorage() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
  }

  function readCookie() {
    try {
      var parts = document.cookie ? document.cookie.split(";") : [];
      for (var i = 0; i < parts.length; i++) {
        var kv = parts[i].trim();
        if (kv.indexOf(COOKIE_NAME + "=") === 0) {
          return decodeURIComponent(kv.slice(COOKIE_NAME.length + 1));
        }
      }
    } catch (e) { /* cookies unavailable */ }
    return null;
  }

  function persist(code, cookieOnly) {
    if (!cookieOnly) {
      try { localStorage.setItem(STORAGE_KEY, code); } catch (e) { /* storage blocked */ }
    }
    try {
      document.cookie = COOKIE_NAME + "=" + code + "; Path=/; Max-Age=31536000; SameSite=Strict";
    } catch (e) { /* cookies blocked */ }
  }

  function detect() {
    var stored = normalize(readStorage());
    if (stored) return stored;
    var cookie = normalize(readCookie());
    if (cookie) return cookie;
    var prefs = [];
    try {
      prefs = (navigator.languages && navigator.languages.length)
        ? navigator.languages
        : [navigator.language || ""];
    } catch (e) { prefs = []; }
    for (var i = 0; i < prefs.length; i++) {
      var match = normalize(prefs[i]);
      if (match) return match;
    }
    return DEFAULT_LANG;
  }

  function load(code) {
    if (catalogs[code]) return Promise.resolve(catalogs[code]);
    if (pending[code]) return pending[code];
    pending[code] = fetch("locales/" + code + ".json", { credentials: "same-origin", cache: "no-cache" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json(); // A missing file falls back to index.html and fails to parse here.
      })
      .then(function (data) {
        if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("invalid catalog");
        catalogs[code] = data;
        return data;
      })
      .catch(function (err) {
        if (window.console) console.warn("[i18n] could not load locale " + code + ": " + err.message);
        delete pending[code];
        return null;
      });
    return pending[code];
  }

  function setActive(code) {
    var info = BY_CODE[code] || BY_CODE[DEFAULT_LANG];
    I18N.lang = info.code;
    I18N.locale = info.locale;
    try { pluralRules = new Intl.PluralRules(info.locale); } catch (e) { pluralRules = null; }
    try { numberFormat = new Intl.NumberFormat(info.locale); } catch (e) { numberFormat = null; }
    document.documentElement.lang = info.htmlLang;
  }

  function lookup(key) {
    var active = catalogs[I18N.lang];
    if (active && Object.prototype.hasOwnProperty.call(active, key)) return active[key];
    var en = catalogs[DEFAULT_LANG];
    if (en && Object.prototype.hasOwnProperty.call(en, key)) return en[key];
    return undefined;
  }

  function resolve(key, params) {
    if (params && typeof params.count === "number" && isFinite(params.count)) {
      var cat = "other";
      try { if (pluralRules) cat = pluralRules.select(params.count); } catch (e) { cat = "other"; }
      var candidates = [key + "_" + cat, key + "_other", key];
      // Look in the active catalog first, then in English, keeping category order.
      var active = catalogs[I18N.lang];
      for (var i = 0; i < candidates.length; i++) {
        if (active && Object.prototype.hasOwnProperty.call(active, candidates[i])) return active[candidates[i]];
      }
      var en = catalogs[DEFAULT_LANG];
      var enCat = "other";
      try { enCat = new Intl.PluralRules("en-US").select(params.count); } catch (e) { enCat = "other"; }
      var enCandidates = [key + "_" + enCat, key + "_other", key];
      for (var j = 0; j < enCandidates.length; j++) {
        if (en && Object.prototype.hasOwnProperty.call(en, enCandidates[j])) return en[enCandidates[j]];
      }
      return undefined;
    }
    return lookup(key);
  }

  function formatValue(v) {
    if (typeof v === "number" && isFinite(v) && numberFormat) return numberFormat.format(v);
    return v == null ? "" : String(v);
  }

  function t(key, params) {
    var str = resolve(key, params);
    if (typeof str !== "string") return key;
    if (!params) return str;
    return str.replace(/\{(\w+)\}/g, function (m, name) {
      return Object.prototype.hasOwnProperty.call(params, name) ? formatValue(params[name]) : m;
    });
  }

  function apply(root) {
    var scope = root || document;
    if (!scope.querySelectorAll) return;
    var nodes = scope.querySelectorAll("[data-i18n]");
    for (var i = 0; i < nodes.length; i++) {
      var key = nodes[i].getAttribute("data-i18n");
      if (key) nodes[i].textContent = t(key);
    }
    var attrNodes = scope.querySelectorAll("[data-i18n-attr]");
    for (var j = 0; j < attrNodes.length; j++) {
      var spec = attrNodes[j].getAttribute("data-i18n-attr") || "";
      spec.split(";").forEach(function (pair) {
        var idx = pair.indexOf(":");
        if (idx < 1) return;
        var attr = pair.slice(0, idx).trim();
        var k = pair.slice(idx + 1).trim();
        if (attr && k) attrNodes[j].setAttribute(attr, t(k));
      });
    }
  }

  function notify() {
    listeners.slice().forEach(function (fn) {
      try { fn(I18N.lang, I18N.locale); } catch (e) { if (window.console) console.error(e); }
    });
  }

  function setLang(code) {
    var next = normalize(code) || DEFAULT_LANG;
    return Promise.all([load(DEFAULT_LANG), next === DEFAULT_LANG ? null : load(next)]).then(function (res) {
      if (next !== DEFAULT_LANG && !res[1]) next = DEFAULT_LANG; // Catalog failed: stay usable in English.
      // Persist the language actually shown so the server localizes API messages to match the UI.
      persist(next);
      var changed = next !== I18N.lang;
      setActive(next);
      apply(document);
      if (changed) notify();
      return next;
    });
  }

  function onChange(fn) {
    if (typeof fn === "function") listeners.push(fn);
    return function off() {
      var i = listeners.indexOf(fn);
      if (i >= 0) listeners.splice(i, 1);
    };
  }

  var I18N = {
    lang: DEFAULT_LANG,
    locale: BY_CODE[DEFAULT_LANG].locale,
    languages: LANGUAGES.map(function (l) { return { code: l.code, name: l.name }; }),
    t: t,
    apply: apply,
    setLang: setLang,
    onChange: onChange,
    has: function (key) { return typeof lookup(key) === "string"; },
    ready: null
  };
  window.I18N = I18N;

  var initial = detect();
  setActive(initial);
  I18N.ready = Promise.all([load(DEFAULT_LANG), initial === DEFAULT_LANG ? null : load(initial)])
    .then(function (res) {
      if (initial !== DEFAULT_LANG && !res[1]) setActive(DEFAULT_LANG);
      // Keep the cookie in sync so the server localizes API messages from the first request.
      // Only the cookie is written here: an auto-detected language is not a user choice.
      if (readCookie() !== I18N.lang) persist(I18N.lang, true);
      var run = function () { apply(document); };
      if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run, { once: true });
      else run();
      return I18N.lang;
    })
    .catch(function () { return I18N.lang; });
})();
