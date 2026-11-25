#!/usr/bin/env node
// Checks the translation catalogs of the dashboard UI and the API.
//
// Errors (exit code 1):
//   - a catalog is not valid JSON or is not a flat object of strings
//   - a key used in web/dist/app.js or web/dist/index.html is missing from en.json
//   - a translated key does not exist in en.json
//   - a translation uses placeholders that differ from the English text
//   - a value contains the em dash character (U+2014)
// Warnings (exit code 0):
//   - a key from en.json has no translation in another language (English is used)
//
// Usage: node scripts/check-i18n.mjs

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PLURAL_SUFFIXES = ["_zero", "_one", "_two", "_few", "_many", "_other"];
const EM_DASH = "\u2014";

const catalogs = [
  {
    name: "UI",
    dir: join(root, "web/dist/locales"),
    sources: [join(root, "web/dist/app.js"), join(root, "web/dist/index.html")],
  },
  {
    name: "API",
    dir: join(root, "internal/i18n/locales"),
    sources: [],
  },
];

let errors = 0;
let warnings = 0;

function error(msg) {
  errors++;
  console.error(`error: ${msg}`);
}

function warn(msg) {
  warnings++;
  console.warn(`warning: ${msg}`);
}

function baseKey(key) {
  for (const suffix of PLURAL_SUFFIXES) {
    if (key.endsWith(suffix)) return key.slice(0, -suffix.length);
  }
  return key;
}

function placeholders(text) {
  return [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
}

function sameSet(a, b) {
  const sa = [...new Set(a)];
  const sb = [...new Set(b)];
  return sa.length === sb.length && sa.every((v, i) => v === sb[i]);
}

function loadCatalog(file) {
  let data;
  try {
    data = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    error(`${file}: invalid JSON: ${e.message}`);
    return null;
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    error(`${file}: must be a flat JSON object`);
    return null;
  }
  for (const [key, value] of Object.entries(data)) {
    if (typeof value !== "string") {
      error(`${file}: key "${key}" must map to a string`);
      delete data[key];
    } else if (value.includes(EM_DASH)) {
      error(`${file}: key "${key}" contains an em dash`);
    }
  }
  return data;
}

// Collects static keys used by the UI. Dynamic keys (template strings,
// variables) cannot be checked here and are ignored.
function usedKeys(files) {
  const keys = new Map();
  const add = (key, where) => {
    if (!keys.has(key)) keys.set(key, where);
  };
  for (const file of files) {
    if (!existsSync(file)) continue;
    const text = readFileSync(file, "utf8");
    const rel = file.slice(root.length + 1);
    // t("key") counts, t("prefix." + name) is dynamic and skipped.
    for (const m of text.matchAll(/\bt\(\s*(['"])([\w.-]+)\1(\s*\+)?/g)) {
      if (!m[3]) add(m[2], rel);
    }
    for (const m of text.matchAll(/data-i18n="([^"]+)"/g)) add(m[1].trim(), rel);
    // data-i18n-attr="attr:key;attr:key" (also accepts "," as separator)
    for (const m of text.matchAll(/data-i18n-attr="([^"]+)"/g)) {
      for (const pair of m[1].split(/[;,]/)) {
        const idx = pair.indexOf(":");
        if (idx > 0) add(pair.slice(idx + 1).trim(), rel);
      }
    }
  }
  return keys;
}

function hasKey(catalog, key) {
  if (key in catalog) return true;
  return PLURAL_SUFFIXES.some((s) => key + s in catalog);
}

// The English text a translated key is compared against.
function englishFor(en, key) {
  if (key in en) return en[key];
  const base = baseKey(key);
  return en[`${base}_other`] ?? en[base];
}

for (const cat of catalogs) {
  if (!existsSync(cat.dir)) {
    error(`${cat.name}: directory ${cat.dir} not found`);
    continue;
  }
  const files = readdirSync(cat.dir).filter((f) => f.endsWith(".json")).sort();
  if (!files.includes("en.json")) {
    error(`${cat.name}: en.json is missing`);
    continue;
  }
  const en = loadCatalog(join(cat.dir, "en.json"));
  if (!en) continue;
  const enBases = new Set(Object.keys(en).map(baseKey));

  for (const [key, where] of usedKeys(cat.sources)) {
    if (!hasKey(en, key)) error(`${cat.name}: key "${key}" used in ${where} is missing from en.json`);
  }

  for (const file of files) {
    if (file === "en.json") continue;
    const lang = file.replace(/\.json$/, "");
    const tr = loadCatalog(join(cat.dir, file));
    if (!tr) continue;

    let missing = 0;
    for (const base of enBases) {
      if (!hasKey(tr, base)) missing++;
    }
    if (missing > 0) warn(`${cat.name} ${lang}: ${missing} key(s) not translated, English is used`);

    for (const [key, value] of Object.entries(tr)) {
      if (!enBases.has(baseKey(key))) {
        error(`${cat.name} ${lang}: key "${key}" does not exist in en.json`);
        continue;
      }
      const source = englishFor(en, key);
      // Plural forms may add or drop {count} (English "one" is often written
      // without the number, Russian "one" also covers 21, 31, ...).
      const plural = baseKey(key) !== key;
      const strip = (list) => (plural ? list.filter((p) => p !== "count") : list);
      if (source !== undefined && !sameSet(strip(placeholders(value)), strip(placeholders(source)))) {
        error(
          `${cat.name} ${lang}: key "${key}" placeholders {${placeholders(value).join("}, {")}} ` +
            `do not match English {${placeholders(source).join("}, {")}}`,
        );
      }
    }
  }
  console.log(`${cat.name}: ${files.length} catalog(s), ${enBases.size} key(s) in en.json`);
}

console.log(`${errors} error(s), ${warnings} warning(s)`);
process.exit(errors > 0 ? 1 : 0);
