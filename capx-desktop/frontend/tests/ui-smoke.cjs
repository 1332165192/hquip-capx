/* Run with Node.js and Playwright; the Wails bridge and all API traffic are local fixtures. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const dist = path.resolve(__dirname, '../dist');
const output = process.env.UI_SCREENSHOT_DIR || path.join(os.tmpdir(), 'capx-desktop-ui-qa');
const originalIDs = `state auto-refresh ports start stop reload tabs-main tabs-extra capx-frame offline cfg-api cfg-proxy save-ports offline-start offline-state panel-wx wx-root wx-scan wx-open wx-reconstruct wx-state wx-list wx-out panel-sequencer seq-load-values seq-run seq-clear seq-summary seq-in seq-m-count seq-m-uniq seq-m-entropy seq-bars seq-out panel-turbo tb-scheme tb-host tb-mode tb-run tb-count tb-concurrency tb-delay tb-raw tb-payloads tb-results tb-detail`.split(' ');
const originalViews = `web:dashboard web:target web:proxy web:client web:mobile web:wxdesk web:repeater web:intruder panel:turbo web:enhance panel:sequencer web:dnslog panel:wx web:wxhook web:wxapkg web:rules web:decoder web:comparer web:enhance web:hook web:memory web:correlate web:script web:enhance web:logger web:settings`.split(' ').sort();
const server = http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname.startsWith('/console/')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!doctype html><html><body style="margin:0;background:#f4f6f8;font:14px sans-serif;color:#172b3a;padding:24px">本地控制台 iframe 测试夹具<script>
      const parentOrigin=new URLSearchParams(location.search).get('parent_origin');
      addEventListener('message',event=>{if(event.source!==parent||event.origin!==parentOrigin)return;
        if(event.data.type==='capx:navigate'){location.hash=event.data.view;parent.postMessage({type:'capx:viewchange',view:event.data.view},parentOrigin);}
      });
      parent.postMessage({type:'capx:ready'},parentOrigin);
    </script></body></html>`);
  }
  const file = path.join(dist, pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, ''));
  if (!file.startsWith(dist + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404);
    return res.end();
  }
  const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' }[path.extname(file)] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': mime });
  fs.createReadStream(file).pipe(res);
});

async function installBridge(page, origin) {
  await page.addInitScript(({ origin }) => {
    const fixture = window.__fixture = { running: false, calls: [] };
    const record = (name, args) => fixture.calls.push({ name, args });
    window.go = { main: { App: {
      BaseURL: async () => origin + '/console',
      ProxyAddr: async () => '127.0.0.1:18080',
      CapxRunning: async () => fixture.running,
      Health: async () => JSON.stringify({ sniffer: 'stub', hook: 'frida', inline: 'stub' }),
      StartCapx: async () => { record('StartCapx', []); fixture.running = true; },
      StopCapx: async () => { record('StopCapx', []); fixture.running = false; return '服务已停止'; },
      ConfigurePorts: async (...args) => { record('ConfigurePorts', args); return '端口设置已保存'; },
      SelectFolder: async () => 'C:\\sandbox\\packages',
      OpenFolder: async (folder) => { record('OpenFolder', [folder]); return folder; },
      ClearWxAppletDir: async (...args) => { record('ClearWxAppletDir', args); return 'fixture'; },
      ClearWxUnpackedDirs: async (...args) => { record('ClearWxUnpackedDirs', args); return 'fixture'; },
      ApiGet: async (url) => {
        record('ApiGet', [url]);
        if (url === '/api/collect') return JSON.stringify({ items: { values: ['alpha', 'bravo', 'charlie'] } });
        if (url.startsWith('/api/wxapkg/scan')) return JSON.stringify({ root: 'C:\\sandbox\\packages', count: 2, apps: [
          { name: '示例商城', appid: 'wx-fixture-001', path: 'C:\\sandbox\\packages\\sample.wxapkg', version: '102', mtime: '2026-09-21' },
          { name: '文档中心', appid: 'wx-fixture-002', path: 'C:\\sandbox\\packages\\docs.wxapkg', version: '24', mtime: '2026-09-20' }
        ] });
        if (url === '/api/wxapkg/rules') return JSON.stringify({ api: ['https?://[^\\s]+'], url: ['fixture-rule'] });
        throw new Error('Unexpected API GET: ' + url);
      },
      ApiPost: async (url, rawBody) => {
        record('ApiPost', [url, JSON.parse(rawBody)]);
        if (url === '/api/turbo/run') return JSON.stringify({ results: [
          { index: 1, payload: 'fixture', status: 200, length: 23, millis: 18, resp_raw: 'HTTP/1.1 200 OK\r\n\r\nfixture response' }
        ] });
        if (url === '/api/wxapkg/unpack') return JSON.stringify({ appid: 'wx-fixture-001', outdir: 'C:\\sandbox\\sample_unpacked', count: 3, written: 3, extracted: { api: ['/api/fixture'], url: ['https://fixture.invalid'] } });
        throw new Error('Unexpected API POST: ' + url);
      }
    } } };
  }, { origin });
}

async function layout(page, width, height) {
  await page.setViewportSize({ width, height });
  await page.waitForTimeout(100);
  const boxes = await page.evaluate(() => {
    const read = (selector) => {
      const el = document.querySelector(selector);
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, right: r.right, bottom: r.bottom, width: r.width, height: r.height, scroll: el.scrollWidth, client: el.clientWidth };
    };
    return { top: read('.top'), actions: read('.top-actions'), main: read('.main'), page: read('body') };
  });
  assert.ok(boxes.actions.right <= width + 1, `Top actions overflow at ${width}`);
  assert.ok(boxes.main.height >= height - 161, `Unexpected content height at ${width}`);
  assert.ok(Math.abs(boxes.main.bottom - height) < 1, 'Main viewport does not fill window');
  assert.ok(boxes.page.scroll <= width, 'Document has horizontal overflow');
}

(async () => {
  fs.mkdirSync(output, { recursive: true });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const launch = { headless: true };
  if (process.env.BROWSER_PATH) launch.executablePath = process.env.BROWSER_PATH;
  const browser = await chromium.launch(launch);
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await installBridge(page, origin);
    await page.goto(origin);
    await page.locator('#offline.on').waitFor();
    const contract = await page.evaluate(() => ({
      ids: [...document.querySelectorAll('[id]')].map(el => el.id),
      views: [...document.querySelectorAll('.tab')].map(el => el.dataset.kind + ':' + el.dataset.view).sort(),
      background: getComputedStyle(document.body).backgroundColor,
      loaded: [...document.styleSheets].some(sheet => sheet.href?.endsWith('/desktop.css'))
    }));
    assert.equal(contract.ids.length, new Set(contract.ids).size, 'Duplicate HTML IDs');
    originalIDs.forEach(id => assert.ok(contract.ids.includes(id), 'Missing DOM hook: ' + id));
    assert.deepEqual(contract.views, originalViews);
    assert.equal(contract.background, 'rgb(244, 246, 248)');
    assert.ok(contract.loaded, 'Modern stylesheet did not load');
    await layout(page, 1280, 820);
    await page.screenshot({ path: path.join(output, 'desktop-overview-1280.png') });
    await layout(page, 960, 600);
    await page.screenshot({ path: path.join(output, 'desktop-overview-960.png') });
    await page.locator('#ports').click();
    await page.locator('#cfg-api').fill('19101');
    await page.locator('#cfg-proxy').fill('18101');
    await page.locator('#save-ports').click();
    assert.deepEqual(await page.evaluate(() => window.__fixture.calls.find(x => x.name === 'ConfigurePorts').args), ['19101', '18101']);

    await page.locator('[data-view="sequencer"]').click();
    await page.locator('#seq-in').fill('ab12\nab34\nab12\ncd56');
    await page.locator('#seq-run').click();
    assert.equal(await page.locator('#seq-m-count').textContent(), '4');
    assert.equal(await page.locator('#seq-m-uniq').textContent(), '3');
    assert.equal(await page.locator('.seq-bar').count(), 4);
    assert.ok(JSON.parse(await page.locator('#seq-out').textContent()).position_entropy.length === 4);
    assert.equal(await page.locator('[aria-current="page"]').count(), 1);
    await layout(page, 1280, 820);
    await page.screenshot({ path: path.join(output, 'desktop-sequencer-1280.png') });
    await page.locator('#seq-clear').click();
    assert.equal(await page.locator('#seq-m-count').textContent(), '0');
    await page.locator('#seq-load-values').click();
    await page.waitForFunction(() => document.querySelector('#seq-m-count').textContent === '3');

    await page.locator('[data-view="turbo"]').click();
    await page.locator('#tb-host').fill('fixture.invalid');
    await page.locator('#tb-payloads').fill('fixture');
    await page.locator('#tb-run').click();
    await page.locator('.tb-row').waitFor();
    await page.locator('.tb-row').click();
    assert.ok((await page.locator('#tb-detail').textContent()).includes('fixture response'));
    const turbo = await page.evaluate(() => window.__fixture.calls.find(x => x.name === 'ApiPost' && x.args[0] === '/api/turbo/run').args[1]);
    assert.equal(turbo.host, 'fixture.invalid');
    assert.deepEqual(turbo.payloads, ['fixture']);
    assert.equal(turbo.gate, true);
    await page.locator('#panel-turbo').evaluate(el => el.scrollTop = 0);
    await page.screenshot({ path: path.join(output, 'desktop-turbo-1280.png') });
    await layout(page, 960, 600);
    await page.screenshot({ path: path.join(output, 'desktop-turbo-960.png') });

    await page.locator('[data-view="wx"]').click();
    await page.locator('.wx-app-card').first().waitFor();
    assert.equal(await page.locator('.wx-app-card').count(), 2);
    assert.ok(await page.locator('#wx-state').isVisible());
    assert.ok(await page.evaluate(() => {
      const ids = [...document.querySelectorAll('[id]')].map(el => el.id);
      return ids.length === new Set(ids).size;
    }), 'Duplicate IDs after mini-app workbench mount');
    await page.screenshot({ path: path.join(output, 'desktop-wx-960.png') });
    await layout(page, 1280, 820);
    await page.screenshot({ path: path.join(output, 'desktop-wx-1280.png') });
    await page.locator('#wx-search').fill('文档');
    assert.equal(await page.locator('.wx-app-card').count(), 1);
    await page.locator('#wx-search').fill('');
    await page.locator('.wx-act-unpack').first().click();
    await page.locator('#wx-extract-list').waitFor();
    assert.ok((await page.locator('#wx-extract-list').textContent()).includes('/api/fixture'));
    await page.locator('[data-cat="url"]').click();
    assert.ok((await page.locator('#wx-extract-list').textContent()).includes('https://fixture.invalid'));
    await page.locator('#wx-open').click();
    assert.ok(await page.evaluate(() => window.__fixture.calls.some(x => x.name === 'OpenFolder')));
    await page.locator('#wx-rules').click();
    await page.locator('.wx-rule-item').first().waitFor();
    assert.equal(await page.locator('.wx-rule-item').count(), 2);
    await page.locator('#wx-scan').click();
    assert.equal(await page.locator('.wx-app-card').count(), 2);
    await page.locator('#wx-help').click();
    assert.equal(new URL(page.url()).hash, '');
    assert.equal(await page.locator('#wx-result-title').textContent(), '路径帮助');
    page.once('dialog', dialog => dialog.dismiss());
    await page.locator('#wx-clear-applet').click();
    assert.ok(!await page.evaluate(() => window.__fixture.calls.some(x => x.name === 'ClearWxAppletDir')));

    await page.locator('[data-view="dashboard"]').click();
    await page.locator('#offline-start').click();
    await page.waitForFunction(() => document.querySelector('#capx-frame').src.includes('embed=1'));
    assert.equal(await page.locator('#state').textContent(), '已连接');
    assert.ok(!await page.locator('#offline').isVisible());
    const webTabs = page.locator('.tab[data-kind="web"]');
    for (let i = 0; i < await webTabs.count(); i++) {
      const tab = webTabs.nth(i);
      const view = await tab.getAttribute('data-view');
      await tab.click();
      await page.frameLocator('#capx-frame').locator('body').evaluate((_,view)=>new Promise(resolve=>{
        const check=()=>location.hash==='#'+view?resolve(true):setTimeout(check,20);check();
      }),view);
      assert.equal(await page.locator('.tab.on').count(), 1);
      assert.equal(await page.locator('[aria-current="page"]').count(), 1);
    }
    await page.locator('[data-view="repeater"]').click();
    const src = await page.locator('#capx-frame').getAttribute('src');
    await page.waitForFunction(() => document.querySelector('#capx-frame').contentWindow.location.hash === '#repeater');
    assert.equal(await page.frameLocator('#capx-frame').locator('body').evaluate(()=>location.hash), '#repeater');
    assert.equal(new URL(src).searchParams.get('embed'), '1');
    await layout(page, 960, 600);
    const frame = await page.locator('#capx-frame').boundingBox();
    assert.equal(frame.width, await page.locator('.main').evaluate(el=>el.clientWidth));
    assert.equal(frame.y + frame.height, 600);
    await page.locator('#reload').click();
    await page.locator('#stop').click();
    await page.waitForFunction(() => document.querySelector('#state').textContent === '未连接');
    assert.deepEqual(errors, [], 'Browser JavaScript errors');
    console.log(`PASS: desktop DOM contracts, ${originalViews.length} navigation entries, port settings, service bridge, iframe, Sequencer, Turbo, mini-app workflow, 1280/960 layouts.`);
    console.log('Screenshots: ' + output);
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); server.close(); process.exitCode = 1; });
