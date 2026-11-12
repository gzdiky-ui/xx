#!/usr/bin/env node
/**
 * dushe-spider.js — www.dushe05.com 采集脚本（Node.js 18+, ESM）
 *
 * 用法:
 *   node dushe-spider.js --probe                      # 连通性/反爬层预检
 *   node dushe-spider.js --mode home --pages 3        # 首页栏目+列表
 *   node dushe-spider.js --mode search --keyword 武侠 --pages 2
 *   node dushe-spider.js --mode detail --url <详情URL>
 *   node dushe-spider.js --browser                    # Playwright 兜底模式(需安装)
 *
 * 依赖: npm i axios cheerio iconv-lite   (可选: npm i playwright)
 *
 * 注意:
 *  1. 该站前置 CDNDefend(850): PoW 已内置求解; TLS 指纹层可能仍拦纯 Node 客户端,
 *     此时用 --browser 或换能打开该站的出口。
 *  2. 选择器为"候选集",真实 DOM 需 --probe 导出后校准(见 CALIBRATE 标记)。
 */

import axios from 'axios';
import * as cheerio from 'cheerio';
import iconv from 'iconv-lite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:PATH'.replace('PATH','path');

/* ============================ 配置 ============================ */
const CFG = {
  domain: 'www.dushe05.com',
  fallbackIp: '192.46.229.66',        // DoH 实测真实 IP(会动态重解析)
  delayMs: 1500,                       // 请求间隔
  concurrency: 1,
  retries: 3,
  timeoutMs: 20000,
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  outDir: 'out',
  // CALIBRATE: 过墙后按真实 DOM 修正以下选择器
  sel: {
    listItems: 'ul.list li, .list-unstyled li, .row .item, div.stui-vodlist__media',
    listTitle: 'h4 a, h3 a, .title a, .text-right a',
    listLink:  'h4 a, h3 a, .title a, .text-right a',
    listCover: 'img',
    episodes:  'ul.stui-vodlist__text li, ul.player_list li, .anthologies li',
    epLink:    'a',
    detailTitle: '.title, h1, .detail-title',
    summary:   '.sketch, .content, .detail-content, p.summary',
  },
};

/* ============================ 基础工具 ============================ */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => new Date().toISOString();

function log(...a) { console.log(`[${now()}]`, ...a); }
function fail(msg, code = 1) { console.error(`[ERROR] ${msg}`); process.exit(code); }

/* ---------- 1) DNS 黑洞绕过: DoH 解析真实 IP ---------- */
async function resolveRealIp() {
  const dohEndpoints = [
    (n) => `https://cloudflare-dns.com/dns-query?name=${n}&type=A`,
    (n) => `https://dns.google/resolve?name=${n}&type=A`,
  ];
  for (const mk of dohEndpoints) {
    try {
      const res = await axios.get(mk(CFG.domain), { timeout: 8000, headers: { accept: 'application/dns-json' } });
      const a = res.data?.Answer?.find((x) => x.type === 1)?.data;
      if (a && /^\d+\.\d+\.\d+\.\d+$/.test(a)) return a;
    } catch (e) { log(`DoH 失败: ${e.message}`); }
  }
  log(`DoH 全部失败, 回退硬编码 IP ${CFG.fallbackIp}`);
  return CFG.fallbackIp;
}

/* ---------- 2) CDNDefend PoW 求解 ----------
 * 850 页逻辑(实测解码): 页内数组 a0_0x2a54[0] 为 40 位 hex seed;
 * 找最小 i>=0 使 SHA1(seed+str(i))[2]==0xb0 && [3]==0x0b;
 * cookie = 'cdndefend_js_cookie=' + seed + i
 */
function solvePow(seed) {
  for (let i = 0; ; i++) {
    const d = crypto.createHash('sha1').update(seed + String(i)).digest();
    if (d[2] === 0xb0 && d[3] === 0x0b) return i;
  }
}
function extractSeedFrom850(html) {
  const m = html.match(/a0_0x2a54\s*=\s*\[\s*'([0-9A-Fa-f]{40})'/)
         || html.match(/'([0-9A-Fa-f]{40})'\s*,\s*'cdndefend_js_cookie='/);
  return m ? m[1] : null;
}

/* ---------- 3) HTTP 客户端(IP+Host+SNI 分离, cookie jar) ---------- */
class Crawler {
  constructor(ip) {
    this.ip = ip;
    this.cookies = new Map();
    this.http = axios.create({
      baseURL: `https://${ip}/`,
      timeout: CFG.timeoutMs,
      maxRedirects: 5,
      validateStatus: () => true,
      httpsAgent: new (require('https').Agent)({
        servername: CFG.domain,          // SNI
        rejectUnauthorized: false,       // 该站证书可能挂在兄弟域名上
      }),
      headers: {
        'User-Agent': CFG.ua,
        'Host': CFG.domain,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'Upgrade-Insecure-Requests': '1',
      },
    });
  }
  cookieHeader() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
  saveCookies(res) {
    const sc = res.headers['set-cookie'] || [];
    for (const c of sc) {
      const [pair] = c.split(';');
      const idx = pair.indexOf('=');
      if (idx > 0) this.cookies.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    }
  }
  /** GET 相对路径, 返回 {status, html, buffer, headers} */
  async get(p, { binary = false } = {}) {
    const headers = this.cookies.size ? { Cookie: this.cookieHeader() } : {};
    const res = await this.http.get(p, { headers, responseType: binary ? 'arraybuffer' : 'text' });
    this.saveCookies(res);
    const buf = Buffer.isBuffer(res.data) ? res.data : Buffer.from(res.data, 'binary');
    return { status: res.status, buffer: buf, headers: res.headers };
  }
  /** 带重试的 GET */
  async getRetry(p, tries = CFG.retries) {
    for (let i = 1; i <= tries; i++) {
      try {
        const r = await this.get(p);
        if (r.status === 850 || r.status === 429) throw new Error(`blocked ${r.status}`);
        return r;
      } catch (e) {
        const backoff = 2 ** i * 1000;
        log(`GET ${p} 第${i}次失败: ${e.message}, ${backoff}ms 后重试`);
        if (i === tries) throw e;
        await sleep(backoff);
      }
    }
  }
  /** 解码: 页面声明 charset 优先, 兜底 utf8/gbk */
  decode(r) {
    const head = r.buffer.subarray(0, 2048).toString('latin1');
    const m = head.match(/charset=["']?([\w-]+)/i);
    let enc = m ? m[1].toLowerCase() : null;
    if (enc && ['utf-8', 'gb2312', 'gbk', 'gb18030', 'big5', 'iso-8859-1'].includes(enc)) {
      try { return iconv.decode(r.buffer, enc); } catch {}
    }
    const buf = r.buffer;
    const utf8 = buf.toString('utf8');
    return utf8.includes('\ufffd') ? iconv.decode(buf, 'gbk') : utf8;
  }
}

/* ---------- 4) 过墙: 850 → PoW → cookie → 重试 ---------- */
async function ensureThroughWall(cr) {
  let r = await cr.get('/');
  if (r.status !== 850) return r;
  const html = cr.decode(r);
  const seed = extractSeedFrom850(html);
  if (!seed) throw new Error('850 拦截页中未找到 seed, 可能是纯 IP 封锁或页面结构变化');
  log(`命中 CDNDefend 850, seed=${seed}, 开始 PoW 求解...`);
  const t0 = Date.now();
  const i = solvePow(seed);
  log(`PoW 解出 i=${i} (${Date.now() - t0}ms)`);
  cr.cookies.set('cdndefend_js_cookie', seed + String(i));
  r = await cr.get('/');
  if (r.status === 850) {
    throw new Error(
      'PoW 后仍 850: TLS 指纹/IP 层被拦。纯 Node 客户端在本出口无法过墙。\n' +
      '  → 方案A: node dushe-spider.js --browser (Playwright 执行挑战)\n' +
      '  → 方案B: 换能正常打开该站的出口网络重跑'
    );
  }
  log(`过墙成功: HTTP ${r.status}`);
  return r;
}

/* ---------- 5) 解析(候选选择器, 需 CALIBRATE) ---------- */
function absolutize(base, u) {
  if (!u) return null;
  try { return new URL(u, `https://${CFG.domain}${base}`).toString(); } catch { return null; }
}
function parseList(html, baseUrl) {
  const $ = cheerio.load(html);
  const items = [];
  $(CFG.sel.listItems).each((_, el) => {
    const t = $(el).find(CFG.sel.listTitle).first();
    const a = $(el).find(CFG.sel.listLink).first();
    const title = (t.text() || a.text() || '').trim();
    const link = absolutize(baseUrl, a.attr('href'));
    const cover = absolutize(baseUrl, $(el).find(CFG.sel.listCover).first().attr('src'));
    if (title && link) items.push({ title, url: link, cover, _raw: $(el).text().replace(/\s+/g, ' ').slice(0, 200) });
  });
  return items;
}
function parseDetail(html, baseUrl) {
  const $ = cheerio.load(html);
  const episodes = [];
  $(CFG.sel.episodes).each((_, li) => {
    const a = $(li).find(CFG.sel.epLink).first();
    const title = (a.text() || $(li).text()).trim();
    const url = absolutize(baseUrl, a.attr('href'));
    if (title && url) episodes.push({ title, url });
  });
  return {
    title: ($(CFG.sel.detailTitle).first().text() || '').trim(),
    summary: ($(CFG.sel.summary).first().text() || '').trim().slice(0, 500),
    episodes,
  };
}
function parseCmsApi(j) { /* 苹果CMS provide API 结构 */
  return (j?.list || []).map((v) => ({
    vod_id: v.vod_id,
    title: v.vod_name,
    type: v.type_name, year: v.vod_year, area: v.vod_area,
    actors: v.vod_actor, score: v.vod_score,
    summary: (v.vod_content || '').slice(0, 300),
    cover: v.vod_pic,
    episodes: String(v.vod_play_url || '')
      .split('#').slice(0, 1)
      .map((s) => s.replace(/&n;/g, '\n'))
      .split(/\n|，|,/)
      .filter(Boolean)
      .map((s) => { const [t, u] = s.split('$'); return { title: (t || '').trim(), url: u }; }),
  }));
}

/* ---------- 6) Playwright 兜底(可选) ---------- */
async function browserBootstrap() {
  let pw;
  try { ({ chromium: pw } = await import('playwright')); }
  catch { fail('未安装 playwright: npm i playwright && npx playwright install chromium'); }
  const browser = await pw.chromium.launch({ headless: true });
  const page = await browser.newPage({ userAgent: CFG.ua });
  log('Playwright: 加载首页, 等待 JS 挑战自动执行...');
  await page.goto(`https://${CFG.domain}/`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(8000);           // 给 PoW 执行+刷新留时间
  const url = page.url();
  const text = await page.evaluate(() => document.body.innerText.slice(0, 500));
  const cookies = await page.cookies();
  log(`Playwright 结果: ${url} | cookie=${cookies.map((c) => c.name).join(',')}`);
  await browser.close();
  return { url, bodyPreview: text, cookies: cookies.map((c) => `${c.name}=${c.value}`) };
}

/* ---------- 7) 输出 ---------- */
function writeOut(file, rows) {
  fs.mkdirSync(CFG.outDir, { recursive: true });
  const jsonl = file.replace(/\.jsonl$/, '') + '.jsonl';
  rows.forEach((r) => fs.appendFileSync(jsonl, JSON.stringify({ ts: now(), ...r }) + '\n'));
  if (rows.length) {
    const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))];
    const csv = keys.join(',');
    const lines = rows.map((r) => keys.map((k) => JSON.stringify(r[k] ?? '')).join(','));
    fs.appendFileSync(file.replace(/\.jsonl$/, '') + '.csv', csv + '\n' + lines.join('\n') + '\n');
  }
  log(`已写入 ${jsonl} (${rows.length} 条)`);
}
async function dumpRaw(cr, name) {
  fs.mkdirSync(CFG.outDir, { recursive: true });
  const r = await cr.get('/');
  fs.writeFileSync(`${CFG.outDir}/${name}`, cr.decode(r));
  log(`原始页已存: ${CFG.outDir}/${name} (HTTP ${r.status})`);
}

/* ============================ 主流程 ============================ */
async function main() {
  const argv = process.argv.slice(2);
  const flag = (n) => argv.includes(n);
  const opt = (n, d) => { const i = argv.indexOf(n); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
  const mode = opt('--mode', 'home');
  const pages = parseInt(opt('--pages', '1'), 10);
  const keyword = opt('--keyword', '');

  if (flag('--browser')) { const b = await browserBootstrap(); console.log(JSON.stringify(b, null, 2)); return; }

  log(`解析真实 IP (DoH)...`);
  const ip = await resolveRealIp();
  log(`真实 IP: ${ip} (域名 DNS 黑洞已由 DoH 绕过)`);
  const cr = new Crawler(ip);

  if (flag('--probe')) {
    const r = await ensureThroughWall(cr);
    await dumpRaw(cr, 'home.html');
    log(`probe 完成: HTTP ${r.status}, 长度 ${r.buffer.length} 字节。请检查 out/home.html 校准选择器。`);
    // 探测苹果CMS API
    try {
      const a = await cr.get('/api.php/provide/vod/?pg=1');
      log(`provide API: HTTP ${a.status}${a.status === 200 ? ' (存在, 可直接用 JSON API!)' : ''}`);
    } catch {}
    return;
  }

  await ensureThroughWall(cr);
  const results = [];

  if (mode === 'home') {
    for (let p = 1; p <= pages; p++) {
      const r = await cr.getRetry(`/`);
      const html = cr.decode(r);
      // CALIBRATE: 真实栏目/列表容器
      const items = parseList(html, '/');
      results.push(...items.map((x) => ({ mode: 'home', page: p, ...x })));
      log(`home 第${p}页: ${items.length} 条`);
      await sleep(CFG.delayMs);
    }
  } else if (mode === 'search') {
    if (!keyword) fail('search 模式需要 --keyword');
    for (let p = 1; p <= pages; p++) {
      // CALIBRATE: 确认搜索端点 (?searchword= 或 /search.php?keyword=)
      const r = await cr.getRetry(`/index.php?m=vod&a=search&s=${encodeURIComponent(keyword)}&page=${p}`);
      const items = parseList(cr.decode(r), '/index.php');
      results.push(...items.map((x) => ({ mode: 'search', keyword, page: p, ...x })));
      log(`search "${keyword}" 第${p}页: ${items.length} 条`);
      await sleep(CFG.delayMs);
    }
  } else if (mode === 'detail') {
    const url = opt('--url', '');
    if (!url) fail('detail 模式需要 --url');
    const r = await cr.getRetry(url.startsWith('http') ? url.replace(`https://${CFG.domain}`, '') : url);
    const d = parseDetail(cr.decode(r), new URL(url, `https://${CFG.domain}/`).pathname);
    results.push({ mode: 'detail', ...d });
    log(`detail: ${d.title} | 剧集 ${d.episodes.length} 集`);
  }

  writeOut('dushe_vods.jsonl', results);
  log(`完成: 共 ${results.length} 条`);
}

main().catch((e) => fail(e.stack || e.message));