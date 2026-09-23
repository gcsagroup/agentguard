#!/usr/bin/env node
/**
 * 用本机正式 Chrome（及可用时的 Edge）加载候选 ZIP 解压目录，核对 B1–B3/B5。
 * B4 无上一公开版本时记 N/A。这不是商店门禁 PASS，也不是测试 Chromium e2e。
 */
import { createServer } from "node:http";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  mkdtempSync,
  writeFileSync,
  cpSync,
} from "node:fs";
import { createRequire } from "node:module";
import { execFileSync, execSync } from "node:child_process";
import { dirname, extname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const ZIP = join(REPO, "apps/extension-chromium/dist/agentguard-extension.zip");
const FIXTURES = join(REPO, "eval/acceptance-fixtures");
const OUT = join(REPO, ".artifacts/chrome-native-b15-2026-09-22");
mkdirSync(OUT, { recursive: true });

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function loadPlaywright() {
  const candidates = [
    process.env.AGENTGUARD_PLAYWRIGHT_MODULE,
    "playwright",
    join(execSync("npm root -g", { encoding: "utf8" }).trim(), "playwright"),
    "/opt/homebrew/lib/node_modules/playwright",
    "/usr/local/lib/node_modules/playwright",
  ].filter(Boolean);
  let last;
  for (const candidate of candidates) {
    try {
      if (candidate === "playwright") return await import("playwright");
      return createRequire(import.meta.url)(candidate);
    } catch (error) {
      last = error;
    }
  }
  throw last || new Error("need playwright");
}

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript" };
const hits = [];
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path.startsWith("/fixtures/")) {
    const file = join(FIXTURES, path.slice("/fixtures/".length));
    if (!existsSync(file) || !file.startsWith(FIXTURES)) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    res.writeHead(200, { "content-type": MIME[extname(file)] || "text/plain" });
    res.end(readFileSync(file));
    return;
  }
  hits.push({ method: req.method, path });
  res.writeHead(501);
  res.end("stub");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;
const fixture = (name) => `${base}/fixtures/${name}`;
const sawHit = (method, path) => hits.some((h) => h.method === method && h.path === path);

function recordStatus(cases, id, name, status, detail) {
  cases.push({ id, name, status, detail: detail || "" });
  console.log(`${status} ${id} ${name}${detail ? ` :: ${detail}` : ""}`);
}

function record(cases, id, name, ok, detail) {
  recordStatus(cases, id, name, ok ? "PASS" : "FAIL", detail);
}

execFileSync("bash", [join(REPO, "apps/extension-chromium/scripts/package-store.sh")], {
  stdio: "inherit",
});
if (!existsSync(ZIP)) throw new Error("missing candidate zip");
const zipSha = sha256(ZIP);
const unpacked = mkdtempSync(join(tmpdir(), "agentguard-chrome-b15-"));
execFileSync("unzip", ["-o", "-q", ZIP, "-d", unpacked]);
const manifest = JSON.parse(readFileSync(join(unpacked, "manifest.json"), "utf8"));
const noNative = !JSON.stringify(manifest).includes("nativeMessaging");

const browsers = [
  {
    id: "chrome",
    name: "Google Chrome",
    path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  },
  {
    id: "edge",
    name: "Microsoft Edge",
    path: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  },
].filter((b) => existsSync(b.path));

const { chromium } = await loadPlaywright();
const DIALOG = '[role="alertdialog"]';
const CLOSE = `${DIALOG} button[data-agentguard-action="close"]`;
const reports = [];

async function waitUntil(fn, timeout = 8000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("timeout");
}

async function launchOfficial(browser, profile, loadExtension) {
  const context = await chromium.launchPersistentContext(profile, {
    headless: false,
    executablePath: browser.path,
    locale: "en-US",
    ignoreDefaultArgs: ["--disable-extensions"],
    args: ["--enable-unsafe-extension-debugging", "--no-first-run"],
  });
  let extId = null;
  if (loadExtension) {
    const cdp = await context.browser().newBrowserCDPSession();
    const loaded = await cdp.send("Extensions.loadUnpacked", { path: unpacked });
    extId = loaded.id;
  }
  return { context, extId };
}

for (const browser of browsers) {
  const cases = [];
  const profile = mkdtempSync(join(tmpdir(), `agentguard-${browser.id}-`));
  const version = execFileSync(browser.path, ["--version"], { encoding: "utf8" }).trim();
  record(
    cases,
    "B1",
    "candidate ZIP identity, official browser, no nativeMessaging",
    zipSha.length === 64 && noNative && version.length > 0,
    `sha256=${zipSha} version=${version} native=${!noNative}`
  );
  let context;
  try {
    const first = await launchOfficial(browser, profile, true);
    context = first.context;
    const extId = first.extId;
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    const enabled = await popup.evaluate(async () =>
      (await chrome.declarativeNetRequest.getEnabledRulesets()).includes("payment_shape_block")
    );
    const popupText = await popup.locator("body").innerText();
    const nativeHidden = await popup.locator("#native-settings").isHidden();
    const onboarding = await context.newPage();
    await onboarding.goto(`chrome-extension://${extId}/onboarding.html`);
    const onboardingText = await onboarding.locator("body").innerText();
    await popup.screenshot({ path: join(OUT, `${browser.id}-b2-popup.png`) });
    await onboarding.screenshot({ path: join(OUT, `${browser.id}-b2-onboarding.png`) });
    record(
      cases,
      "B2",
      "clean profile: popup/onboarding render, static ruleset enabled, no Native controls",
      enabled &&
        nativeHidden &&
        popupText.length > 0 &&
        onboardingText.length > 0,
      `id=${extId} ruleset=${enabled} nativeHidden=${nativeHidden}`
    );
    await popup.close();
    await onboarding.close();

    const page = await context.newPage();
    hits.length = 0;
    await page.goto(fixture("payment-cta.html"));
    await page.waitForTimeout(400);
    await page.click("#pay");
    await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
    const payBlocked =
      (await page.locator(DIALOG).count()) === 1 &&
      (await page.locator("#result").innerText()) === "";
    if (payBlocked) {
      await page.screenshot({ path: join(OUT, `${browser.id}-b3-payment.png`) });
      await page.click(CLOSE);
    }
    hits.length = 0;
    await page.goto(fixture("shadow-payment.html"));
    await page.waitForTimeout(400);
    await page.locator("#host").locator("#pay").click();
    await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
    const shadowBlocked =
      (await page.locator(DIALOG).count()) === 1 && !sawHit("POST", "/api/shadow");
    hits.length = 0;
    await page.goto(fixture("trap-pii.html"));
    await page.waitForTimeout(400);
    await page.click("button[type=submit]");
    await page.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
    const trapBlocked =
      (await page.locator(DIALOG).count()) === 1 && !page.url().includes("phone=");
    hits.length = 0;
    await page.goto(fixture("fetch-gate.html"));
    const fetchBlocked = await page.evaluate(async () => {
      try {
        await fetch("/pay/checkout", { method: "POST", body: "fixture=1" });
        return false;
      } catch {
        return true;
      }
    });
    await page.waitForTimeout(300);
    const beaconBlocked = await page.evaluate(() =>
      navigator.sendBeacon("/checkout/beacon", "fixture=1")
    );
    await page.click("#form-pay button[type=submit]");
    await page.waitForTimeout(400);
    await page.click('button[data-url="/pay/status"]');
    await waitUntil(() => (sawHit("GET", "/pay/status") ? true : null)).catch(() => null);
    await page.click('button[data-url="/api/search"]');
    await waitUntil(() => (sawHit("POST", "/api/search") ? true : null)).catch(() => null);
    const falsePositive = await page.evaluate(async () => {
      try {
        await fetch("/payroll", { method: "POST", body: "fixture=1" });
        return true;
      } catch {
        return false;
      }
    });
    record(
      cases,
      "B3",
      "F2/H5/F3/F4a/F4c/F4d/F5a/F5b/F5d against local fixtures",
      payBlocked &&
        shadowBlocked &&
        trapBlocked &&
        fetchBlocked &&
        !sawHit("POST", "/pay/checkout") &&
        !sawHit("POST", "/checkout/beacon") &&
        !sawHit("POST", "/charge/form") &&
        sawHit("GET", "/pay/status") &&
        sawHit("POST", "/api/search") &&
        falsePositive,
      `pay=${payBlocked} shadow=${shadowBlocked} trap=${trapBlocked} fetch=${fetchBlocked} beaconQueued=${beaconBlocked} hits=${JSON.stringify(hits)}`
    );
    recordStatus(
      cases,
      "B4",
      "upgrade from previous public version",
      "N/A",
      "no confirmed previous public release"
    );
    await context.close();
    const restarted = await launchOfficial(browser, profile, true);
    context = restarted.context;
    const page2 = await context.newPage();
    await page2.goto(fixture("payment-cta.html"));
    await page2.waitForTimeout(400);
    await page2.click("#pay");
    await page2.waitForSelector(DIALOG, { state: "visible", timeout: 5000 }).catch(() => null);
    const stillBlocked = (await page2.locator(DIALOG).count()) === 1;
    await context.close();
    const bareProfile = mkdtempSync(join(tmpdir(), `agentguard-${browser.id}-bare-`));
    const bare = await launchOfficial(browser, bareProfile, false);
    context = bare.context;
    const page3 = await context.newPage();
    await page3.goto(fixture("payment-cta.html"));
    await page3.waitForTimeout(400);
    await page3.click("#pay");
    await page3.waitForTimeout(800);
    const uninstalled = (await page3.locator(DIALOG).count()) === 0;
    record(
      cases,
      "B5",
      "restart keeps block-only; launching without the extension leaves no page-approval residue",
      stillBlocked && uninstalled,
      `restartBlocked=${stillBlocked} uninstalledNoDialog=${uninstalled}`
    );
    rmSync(bareProfile, { recursive: true, force: true });
  } catch (error) {
    for (const id of ["B1", "B2", "B3", "B5"]) {
      if (!cases.some((c) => c.id === id)) {
        record(cases, id, id, false, String(error && error.message ? error.message : error));
      }
    }
    if (!cases.some((c) => c.id === "B4")) {
      cases.push({ id: "B4", name: "upgrade", status: "N/A", detail: "no previous public release" });
    }
  } finally {
    if (context) await context.close().catch(() => {});
    rmSync(profile, { recursive: true, force: true });
  }
  reports.push({ browser: browser.id, version: version, zipSha, cases });
}

if (!browsers.some((b) => b.id === "edge")) {
  reports.push({
    browser: "edge",
    version: null,
    zipSha,
    cases: [
      { id: "B1", name: "load", status: "BLOCKED", detail: "Microsoft Edge.app not installed" },
      { id: "B2", name: "popup", status: "BLOCKED", detail: "browser missing" },
      { id: "B3", name: "fixtures", status: "BLOCKED", detail: "browser missing" },
      { id: "B4", name: "upgrade", status: "N/A", detail: "no previous public release" },
      { id: "B5", name: "lifecycle", status: "BLOCKED", detail: "browser missing" },
    ],
  });
}

server.close();
rmSync(unpacked, { recursive: true, force: true });
const summary = {
  date: "2026-09-22",
  zip: "apps/extension-chromium/dist/agentguard-extension.zip",
  zipSha,
  method:
    "official headed Chrome; CDP Extensions.loadUnpacked of the candidate ZIP unpack; not the chrome://extensions directory picker; B4 N/A; Edge missing",
  reports,
};
writeFileSync(join(OUT, "summary.json"), JSON.stringify(summary, null, 2));
cpSync(join(OUT, "summary.json"), join(REPO, "docs/evidence/chrome-native-b15-2026-09-22.json"));
console.log(JSON.stringify(summary, null, 2));
const chrome = reports.find((r) => r.browser === "chrome");
const chromeOk = chrome && ["B1", "B2", "B3", "B5"].every((id) =>
  chrome.cases.some((c) => c.id === id && c.status === "PASS")
);
process.exit(chromeOk ? 0 : 1);
