/* 把 HTML 固件在真 Chromium 里渲染成像素,交给 guard-vision 复核(make acceptance-fixtures 的第二步)。
 *
 * make-fixtures.py 生成的 PNG 固件由 Rust 测试逐字节验过"会触发";但 W4/W5 的 **HTML** 固件真机上
 * 是浏览器渲染后再被 GDI 抓走的 —— 字体光栅化、反锯齿、行距都由浏览器决定,Python 算不出来。
 * 第一版 W5 页面用 44px 粗体、3% 不透明度:人看着"很像阈下文字",实测 Chromium 渲染后
 * subliminal_ratio = 0.000 —— 大字只有边缘有小台阶,每格占比够不到探测器的 15%。真机验收会
 * 得到一个 FAIL,然后有人去怪探测器。这个脚本让那种错在容器里就现形。
 *
 * 做法:Playwright 打开固件页(1280×720 与 1920×1080 两种视口),截图;再把 #sub 删掉截一张对照;
 * W4 页面也截一张(它的判据在 OCR 交叉校验,像素探测器应保持安静)。截图重编码为 zlib **存储块**
 * PNG(和 make-fixtures.py 同一形状),写到 <out>/rendered/,由
 * `cargo test -p guard-vision --test 验收固件 -- --ignored 渲染` 读回并断言。
 *
 * 需要 playwright(容器里预装了 Chromium:/opt/pw-browsers/chromium)。刻意不进 release-gate。
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
import zlib from "node:zlib";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const outDir = process.argv[2] || join(REPO, "eval", "acceptance-fixtures", "generated");
const rendered = join(outDir, "rendered");
mkdirSync(rendered, { recursive: true });

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    try {
      const globalRoot = execSync("npm root -g", { encoding: "utf8" }).trim();
      return createRequire(import.meta.url)(join(globalRoot, "playwright"));
    } catch {
      console.error("需要 playwright:npm install -g playwright(Chromium 已预装于 /opt/pw-browsers)");
      process.exit(2);
    }
  }
}
const { chromium } = await loadPlaywright();

// ---------------------------------------------------------------------------
// PNG 解码(Playwright 截图:8-bit RGB/RGBA,过滤器 0–4)→ 重编码为存储块 + 过滤器 0。
// ---------------------------------------------------------------------------
function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}
function decodePng(buf) {
  let i = 8;
  let w = 0, h = 0, ct = 0;
  const idat = [];
  while (i < buf.length) {
    const n = buf.readUInt32BE(i);
    const tag = buf.toString("latin1", i + 4, i + 8);
    const body = buf.subarray(i + 8, i + 8 + n);
    if (tag === "IHDR") {
      w = body.readUInt32BE(0);
      h = body.readUInt32BE(4);
      if (body[8] !== 8) throw new Error("only 8-bit PNG");
      ct = body[9];
      if (ct !== 2 && ct !== 6) throw new Error(`unsupported color type ${ct}`);
      if (body[12] !== 0) throw new Error("interlaced PNG unsupported");
    } else if (tag === "IDAT") idat.push(body);
    i += 12 + n;
  }
  const bpp = ct === 6 ? 4 : 3;
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = w * bpp;
  const out = Buffer.alloc(w * h * 4);
  let prev = Buffer.alloc(stride);
  let pos = 0;
  for (let y = 0; y < h; y++) {
    const f = raw[pos];
    const line = Buffer.from(raw.subarray(pos + 1, pos + 1 + stride));
    pos += 1 + stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? line[x - bpp] : 0, b = prev[x], c = x >= bpp ? prev[x - bpp] : 0;
      if (f === 1) line[x] = (line[x] + a) & 255;
      else if (f === 2) line[x] = (line[x] + b) & 255;
      else if (f === 3) line[x] = (line[x] + ((a + b) >> 1)) & 255;
      else if (f === 4) line[x] = (line[x] + paeth(a, b, c)) & 255;
    }
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 4;
      out[o] = line[x * bpp];
      out[o + 1] = line[x * bpp + 1];
      out[o + 2] = line[x * bpp + 2];
      out[o + 3] = bpp === 4 ? line[x * bpp + 3] : 255;
    }
    prev = line;
  }
  return { w, h, rgba: out };
}
function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) {
    c ^= byte;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  }
  return (~c) >>> 0;
}
function encodeStoredPng(w, h, rgba) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0;
    rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  }
  const chunk = (tag, body) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(body.length);
    const tb = Buffer.concat([Buffer.from(tag, "latin1"), body]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(tb));
    return Buffer.concat([len, tb, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  // level 0 = 存储块,与 make-fixtures.py 一致;Rust 侧的最小解码器只认这种。
  const idat = zlib.deflateSync(raw, { level: 0 });
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0))]);
}

const w5 = join(outDir, "w5-self-drawn-overlay.html");
const w4 = join(outDir, "w4-pixel-only-payment.html");
if (!existsSync(w5) || !existsSync(w4)) {
  console.error(`固件不存在:先跑 python3 scripts/acceptance/make-fixtures.py --out ${outDir}`);
  process.exit(2);
}

const browser = await chromium.launch({ executablePath: existsSync("/opt/pw-browsers/chromium") ? "/opt/pw-browsers/chromium" : undefined });
const shots = [];
async function shoot(name, url, viewport, mutate) {
  const page = await browser.newPage({ viewport });
  await page.goto(url);
  await page.waitForTimeout(250);
  if (mutate) await page.evaluate(mutate);
  const png = await page.screenshot();
  await page.close();
  const { w, h, rgba } = decodePng(png);
  const file = join(rendered, `${name}-${viewport.width}x${viewport.height}.png`);
  writeFileSync(file, encodeStoredPng(w, h, rgba));
  shots.push(file);
  console.log(`  ${file}`);
}
for (const vp of [{ width: 1280, height: 720 }, { width: 1920, height: 1080 }]) {
  await shoot("w5-overlay", pathToFileURL(w5).href, vp);
  await shoot("w5-control", pathToFileURL(w5).href, vp, () => document.getElementById("sub").remove());
  await shoot("w4-canvas", pathToFileURL(w4).href, vp);
}
await browser.close();
writeFileSync(join(rendered, "INDEX.json"), JSON.stringify({ chromium: "playwright bundled", files: shots.map((f) => f.split("/").pop()) }, null, 2) + "\n");
console.log(`rendered ${shots.length} shots → ${rendered}\n复核:AGENTGUARD_RENDERED_FIXTURES=${rendered} cargo test -p guard-vision --test 验收固件 -- --ignored 渲染`);
