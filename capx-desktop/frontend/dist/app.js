(function () {
  let BASE = "http://127.0.0.1:19091";
  const $ = (id) => document.getElementById(id);
  const frame = $("capx-frame");
  const state = $("state");
  const offline = $("offline");
  let connected = false;
  let currentWebView = "dashboard";
  try{const saved=localStorage.getItem('capx:desktop-view');if([...document.querySelectorAll('.tab[data-kind="web"]')].some(button=>button.dataset.view===saved))currentWebView=saved;}catch(_){}
  let wxLastOutDir = "";
  let wxApps = [];
  let frameReady = false;

  const navIcons={dashboard:'grid',target:'target',proxy:'activity',client:'activity',mobile:'layers',wxdesk:'lock',repeater:'code',intruder:'target',turbo:'code',decoder:'code',comparer:'layers',logger:'layers',settings:'settings'};
  document.querySelectorAll('.desktop-sidebar .tab').forEach(button=>{
    const text=[...button.childNodes].filter(node=>node.nodeType===Node.TEXT_NODE).map(node=>node.textContent).join('').trim();
    [...button.childNodes].filter(node=>node.nodeType===Node.TEXT_NODE).forEach(node=>node.remove());
    if(!button.querySelector('svg')){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.classList.add('icon');const use=document.createElementNS(svg.namespaceURI,'use');use.setAttribute('href','#icon-'+(navIcons[button.dataset.view]||'code'));svg.appendChild(use);button.prepend(svg);}
    const label=document.createElement('span');label.className='desktop-nav-label';label.textContent=text;button.appendChild(label);button.title=text;
  });
  const toolSearch=document.getElementById('desktop-nav-search');
  if(toolSearch)toolSearch.oninput=()=>{const query=toolSearch.value.trim().toLowerCase();document.querySelectorAll('.desktop-sidebar .tab').forEach(button=>button.classList.toggle('hidden',!(button.title+' '+button.dataset.view).toLowerCase().includes(query)));};

  function api() {
    return window.go && window.go.main && window.go.main.App ? window.go.main.App : null;
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[c]);
  }

  function setState(ok, text) {
    connected = !!ok;
    state.textContent = text;
    state.classList.toggle("bad", !ok);
    const os = $("offline-state");
    if (os) os.textContent = ok ? "capx 已连接，可以开始捕获流量。" : "capx 未运行，点击「启动代理」连接本地服务。";
  }

  function setTopInfo(base, proxy, health) {
    if (base) {
      BASE = String(base).replace(/\/+$/, "");
      const urls = document.querySelectorAll(".url");
      if (urls[0]) urls[0].textContent = BASE;
    }
    if (health) {
      const urls = document.querySelectorAll(".url");
      if (urls[1]) urls[1].textContent =
        `sniffer:${health.sniffer || "?"} hook:${health.hook || "?"} inline:${health.inline || "?"}`;
    }
    if (proxy) {
      const cfgProxy = $("cfg-proxy");
      if (cfgProxy && !cfgProxy.value) cfgProxy.placeholder = proxy;
      const cfgApi = $("cfg-api");
      if (cfgApi && !cfgApi.value) cfgApi.placeholder = BASE;
      document.querySelectorAll('input[value="127.0.0.1:18080"], input[value="自动分配端口"]').forEach((el) => {
        if (!el.id) el.value = proxy;
      });
      const ol = document.querySelector(".quick ol");
      if (ol && ol.children[1]) {
        ol.children[1].innerHTML = `&#27983;&#35272;&#22120;&#25110;&#31995;&#32479;&#20195;&#29702;&#25351;&#21521; ${esc(proxy)}&#12290;`;
      }
    }
  }

  async function loadRuntimeInfo() {
    const a = api();
    if (!a) return;
    try {
      const [base, proxy] = await Promise.all([
        a.BaseURL ? a.BaseURL() : BASE,
        a.ProxyAddr ? a.ProxyAddr() : ""
      ]);
      setTopInfo(base, proxy);
    } catch {}
  }

  async function rawGet(path) {
    const a = api();
    if (a && a.ApiGet) return JSON.parse(await a.ApiGet(path));
    const r = await fetch(BASE + path, { cache: "no-store" });
    return await r.json();
  }

  async function rawPost(path, body) {
    const a = api();
    if (a && a.ApiPost) return JSON.parse(await a.ApiPost(path, JSON.stringify(body || {})));
    const r = await fetch(BASE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
    return await r.json();
  }

  async function check() {
    const a = api();
    if (a && a.CapxRunning) {
      try {
        await loadRuntimeInfo();
        const ok = await a.CapxRunning();
        setState(ok, ok ? "已连接" : "未连接");
        if (ok && a.Health) {
          try { setTopInfo(null, null, JSON.parse(await a.Health())); } catch {}
        }
        return ok;
      } catch {
        setState(false, "检测失败");
        return false;
      }
    }
    try {
      const r = await fetch(BASE + "/health", { cache: "no-store" });
      setState(r.ok, r.ok ? "已连接" : "未连接");
      return r.ok;
    } catch {
      setState(false, "未连接");
      return false;
    }
  }

  function webSrc(view) {
    const nativeBridge=api()?.ApiRequest ? '&desktop_bridge=1' : '';
    return BASE + "/?embed=1&parent_origin=" + encodeURIComponent(location.origin) + nativeBridge + "#" + encodeURIComponent(view);
  }

  function postFrame(type, extra) {
    if (!frameReady || !frame.contentWindow) return false;
    frame.contentWindow.postMessage(Object.assign({ type }, extra || {}), new URL(BASE).origin);
    return true;
  }

  function markWebView(view) {
    currentWebView = view;
    try{localStorage.setItem('capx:desktop-view',view);}catch(_){}
    const selected = document.querySelector('.tab[data-kind="web"][data-view="' + view + '"]');
    if (!selected || frame.style.display === "none") return;
    document.querySelectorAll('.tab').forEach(button => {
      button.classList.toggle('on', button === selected);
      if (button === selected) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
  }

  function openWeb(view, force) {
    currentWebView = view || currentWebView || "dashboard";
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("on"));
    if (!connected) {
      frame.style.display = "none";
      offline.classList.add("on");
      return;
    }
    offline.classList.remove("on");
    frame.style.display = "block";
    // Keep a single console document alive. Navigation and data refresh must not
    // discard in-progress requests, filters, selection, or unsent editor drafts.
    if (frame.dataset.base !== BASE) {
      frameReady = false;
      frame.dataset.base = BASE;
      frame.src = webSrc(currentWebView);
    } else {
      postFrame('capx:navigate', { view: currentWebView });
    }
  }

  frame.addEventListener('load', () => {
    if (!frame.dataset.base) return;
    frameReady = true;
    postFrame('capx:navigate', { view: currentWebView });
  });
  window.addEventListener('message', event => {
    if (event.source !== frame.contentWindow || event.origin !== new URL(BASE).origin) return;
    const message = event.data;
    if (!message || typeof message !== 'object') return;
    if (message.type === 'capx:api-request' && typeof message.id==='string' && typeof message.path==='string' && typeof message.method==='string') {
      const source=event.source,origin=event.origin,client=api();
      if (!client?.ApiRequest) return;
      client.ApiRequest(message.method,message.path,typeof message.body==='string'?message.body:'').then(result=>{
        if(source===frame.contentWindow && origin===new URL(BASE).origin) source.postMessage({type:'capx:api-response',id:message.id,result},origin);
      }).catch(error=>{if(source===frame.contentWindow && origin===new URL(BASE).origin)source.postMessage({type:'capx:api-response',id:message.id,error:String(error.message||error)},origin);});
    } else if (message.type === 'capx:stream-request') {
      const source=event.source,origin=event.origin,client=api();
      Promise.resolve(client?.StreamStatus?.()||false).then(connected=>{if(source===frame.contentWindow && origin===new URL(BASE).origin)source.postMessage({type:'capx:stream-state',state:connected?'up':'down'},origin);});
    } else if (message.type === 'capx:ready') {
      frameReady = true;
      postFrame('capx:navigate', { view: currentWebView });
    } else if (message.type === 'capx:viewchange' && typeof message.view === 'string' &&
      [...document.querySelectorAll('.tab[data-kind="web"]')].some(button => button.dataset.view === message.view)) {
      markWebView(message.view);
    }
  });

  if (window.runtime?.EventsOn) {
    window.runtime.EventsOn('capx:stream',status=>postFrame('capx:stream-state',{state:status}));
    window.runtime.EventsOn('capx:event',raw=>{try{const data=typeof raw==='string'?JSON.parse(raw):raw;postFrame('capx:stream-event',{event:data.kind,data:typeof raw==='string'?raw:JSON.stringify(raw)});}catch(_){}});
  }

  function openPanel(name) {
    frame.style.display = "none";
    offline.classList.remove("on");
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("on", p.id === "panel-" + name));
    if (name === "wx") {
      wxInstallWorkbench();
      if (!wxApps.length) setTimeout(() => wxScan(), 0);
    }
  }

  function activate(btn) {
    document.querySelectorAll(".tab").forEach((b) => {
      b.classList.toggle("on", b === btn);
      if (b === btn) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    const kind = btn.dataset.kind;
    const view = btn.dataset.view;
    if (kind === "panel") openPanel(view);
    else openWeb(view, true);
  }

  async function startCapx() {
    const a = api();
    if (!a || !a.StartCapx) return setState(false, "桌面后端未就绪");
    setState(false, "启动中...");
    try {
      await a.StartCapx();
      await loadRuntimeInfo();
      setTimeout(async () => {
        await check();
        openWeb(currentWebView, true);
      }, 800);
    } catch (e) {
      setState(false, "启动失败");
      console.error(e);
    }
  }

  async function savePorts() {
    const a = api();
    if (!a || !a.ConfigurePorts) {
      const apiPort = prompt("REST API 端口/地址，留空=自动", "");
      const proxyPort = prompt("代理端口/地址，留空=自动", "");
      console.log("ConfigurePorts unavailable", apiPort, proxyPort);
      return;
    }
    const apiInput = $("cfg-api");
    const proxyInput = $("cfg-proxy");
    try {
      const msg = await a.ConfigurePorts(apiInput ? apiInput.value.trim() : "", proxyInput ? proxyInput.value.trim() : "");
      const os = $("offline-state");
      if (os) os.textContent = msg;
      await loadRuntimeInfo();
      setState(false, "未连接");
    } catch (e) {
      const os = $("offline-state");
      if (os) os.textContent = String(e);
      alert(String(e));
    }
  }

  function focusPorts() {
    offline.classList.add("on");
    frame.style.display = "none";
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("on"));
    setTimeout(() => {
      const x = $("cfg-api");
      if (x) x.focus();
    }, 0);
  }

  async function stopCapx() {
    const a = api();
    if (!a || !a.StopCapx) return;
    try {
      const msg = await a.StopCapx();
      const os = $("offline-state");
      if (os && msg) os.textContent = msg;
    } finally {
      setTimeout(check, 500);
    }
  }

  function reload() {
    if (frame.style.display !== "none") postFrame('capx:refresh');
    check();
  }

  function entropy(chars) {
    const m = new Map();
    for (const c of chars) m.set(c, (m.get(c) || 0) + 1);
    let h = 0;
    const n = chars.length || 1;
    for (const v of m.values()) {
      const p = v / n;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function seqAnalyze() {
    const samples = $("seq-in").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!samples.length) return;
    const lens = samples.map((s) => s.length);
    const uniq = new Set(samples).size;
    const maxLen = Math.max(...lens);
    const pos = [];
    for (let i = 0; i < maxLen; i++) pos.push(entropy(samples.map((s) => s[i] || "")));
    const avg = pos.reduce((a, b) => a + b, 0) / (pos.length || 1);
    $("seq-m-count").textContent = samples.length;
    $("seq-m-uniq").textContent = uniq;
    $("seq-m-entropy").textContent = avg.toFixed(3);
    $("seq-summary").textContent = "长度 " + Math.min(...lens) + "-" + Math.max(...lens) + " | 位置熵越低越可预测";
    $("seq-bars").innerHTML = pos.map((h) => `<div class="seq-bar" title="${h.toFixed(3)} bits"><div class="seq-fill" style="height:${Math.max(2, Math.min(60, h / 6 * 60))}px"></div></div>`).join("");
    const charset = [...new Set(samples.join(""))].sort().join("");
    const prefixes = {};
    samples.forEach((s) => {
      const p = s.slice(0, 4);
      prefixes[p] = (prefixes[p] || 0) + 1;
    });
    $("seq-out").textContent = JSON.stringify({
      charset,
      position_entropy: pos.map((x) => +x.toFixed(4)),
      common_prefixes: prefixes
    }, null, 2);
  }

  async function seqLoadValues() {
    try {
      const r = await rawGet("/api/collect");
      const items = r.items || {};
      const vals = [
        ...(items.values || []),
        ...(items.params || []),
        ...(items.cookies || [])
      ].map((x) => typeof x === "object" ? (x.value || x.name || "") : x).filter(Boolean);
      $("seq-in").value = vals.slice(0, 1000).join("\n");
      seqAnalyze();
    } catch (e) {
      $("seq-out").textContent = "加载失败: " + e;
    }
  }

  async function wxScan() {
    $("wx-state").textContent = "扫描中...";
    const root = $("wx-root").value.trim();
    try {
      const r = await rawGet("/api/wxapkg/scan" + (root ? "?root=" + encodeURIComponent(root) : ""));
      $("wx-root").value = r.root || root;
      $("wx-state").textContent = "找到 " + (r.count || 0) + " 个小程序";
      $("wx-list").innerHTML = (r.apps || []).map((x, i) => `
        <div class="wx-card">
          <b>${esc(x.name || "(未识别名)")}</b>
          <div><code>${esc(x.appid || "")}</code></div>
          <div class="hint">${esc(x.path || "")}</div>
          <div class="row">
            <span class="hint">${Math.round((x.size || 0) / 1024)} KB</span>
            <button class="btn wx-unpack" data-i="${i}">解包</button>
          </div>
        </div>`).join("") || '<div class="hint">没有找到缓存。可以手动填 root。</div>';
      document.querySelectorAll(".wx-unpack").forEach((b) => b.onclick = () => wxUnpack((r.apps || [])[+b.dataset.i]));
    } catch (e) {
      $("wx-state").textContent = "扫描失败: " + e;
    }
  }

  async function wxUnpack(app) {
    if (!app || !app.path) return;
    $("wx-out").textContent = "解包中...\n" + app.path;
    try {
      const r = await rawPost("/api/wxapkg/unpack", {
        path: app.path,
        appid: app.appid || "",
        reconstruct: $("wx-reconstruct").checked
      });
      wxLastOutDir = r.outdir || "";
      $("wx-out").textContent = JSON.stringify({
        appid: r.appid,
        encrypted: r.encrypted,
        outdir: r.outdir,
        files: r.count,
        written: r.written,
        extracted: r.extracted || {},
        notes: r.notes || []
      }, null, 2);
    } catch (e) {
      $("wx-out").textContent = "解包失败: " + e;
    }
  }

  async function wxOpen() {
    const a = api();
    if (!wxLastOutDir) {
      $("wx-out").textContent += "\n\n没有输出目录";
      return;
    }
    if (a && a.OpenFolder) $("wx-out").textContent += "\n\n" + await a.OpenFolder(wxLastOutDir);
  }

  function wxIcon(name) {
    const icons = {
      unpack: '<svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.7-5.7"/><path d="M18 3v4h-4"/><path d="M20 12a8 8 0 0 1-13.7 5.7"/><path d="M6 21v-4h4"/></svg>',
      folder: '<svg viewBox="0 0 24 24"><path d="M3 6h6l2 2h10v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
      result: '<svg viewBox="0 0 24 24"><path d="M7 3h8l4 4v14H7z"/><path d="M15 3v5h5"/><path d="M10 13h7"/><path d="M10 17h7"/></svg>',
      search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/></svg>'
    };
    return icons[name] || "";
  }

  function wxInstallWorkbench() {
    const panel = $("panel-wx");
    if (!panel || panel.dataset.ready === "1") return;
    panel.dataset.ready = "1";
    panel.classList.add("wx-workbench-panel");
    panel.innerHTML = `
      <div class="wx-workbench">
        <div class="wx-toolbar">
          <div class="wx-workbench-heading"><h2>小程序包分析</h2><span id="wx-state" class="hint" role="status" aria-live="polite">等待扫描</span></div>
          <div class="wx-toolbar-line">
            <label for="wx-root">Applet 目录</label>
            <input id="wx-root" class="wx-path" value="C:\\Users\\baisha\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages" />
            <button id="wx-choose">选择</button>
            <button id="wx-scan" class="wx-btn-blue">扫描目录</button>
            <button id="wx-open">打开输出目录</button>
            <a id="wx-help" class="wx-help" href="#">路径帮助</a>
          </div>
          <div class="wx-toolbar-line">
            <label>提取线程量 <input id="wx-extract-threads" class="wx-num" value="16" /></label>
            <label>美化线程量 <input id="wx-beautify-threads" class="wx-num" value="16" /></label>
            <label class="wx-check"><input id="wx-auto-unpack" type="checkbox" /> 自动解包</label>
            <label class="wx-check"><input id="wx-reconstruct" type="checkbox" /> 文件内容美化</label>
            <button id="wx-clear-applet" class="wx-btn-red">清空Applet目录</button>
            <button id="wx-clear-output" class="wx-btn-red">清空解包后的文件</button>
            <button id="wx-rules" class="wx-btn-blue">信息提取规则</button>
          </div>
          <div class="wx-advice">建议先执行清空Applet目录以避免无法回溯是哪个小程序，已经尽可能去掉了不必要的程序包前端资源文件路径避免污染过多</div>
        </div>
        <div class="wx-main">
          <aside class="wx-left">
            <div class="wx-search">
              <input id="wx-search" aria-label="搜索小程序名称、AppID 或主体" placeholder="搜索小程序名称、AppID或主体" />
              <button id="wx-search-btn" title="搜索" aria-label="搜索小程序">${wxIcon("search")}</button>
            </div>
            <div id="wx-list" class="wx-app-list"></div>
          </aside>
          <section class="wx-right">
            <div id="wx-empty" class="wx-empty">
              <div class="wx-empty-icon">${wxIcon("search")}</div>
              <div class="wx-empty-title">请选择一个已经完成的提取结果</div>
              <div class="wx-empty-sub">点击左侧小程序列表中的“获取提取结果”按钮</div>
            </div>
            <div id="wx-result" class="wx-result">
              <h3 id="wx-result-title">提取结果</h3>
              <div id="wx-result-meta" class="wx-result-meta"></div>
              <pre id="wx-out">等待解包。</pre>
            </div>
          </section>
        </div>
      </div>`;
    $("wx-search").oninput = wxRenderList;
    $("wx-search").onkeydown = (e) => {
      if (e.key === "Enter") wxScan();
    };
    $("wx-search-btn").onclick = () => wxApps.length ? wxRenderList() : wxScan();
    $("wx-choose").onclick = wxChooseDir;
    $("wx-scan").onclick = wxScan;
    $("wx-open").onclick = wxOpen;
    $("wx-help").onclick = (event) => {
      event.preventDefault();
      wxSetResult("路径帮助", "", "常见路径：C:\\Users\\baisha\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages");
    };
    $("wx-rules").onclick = wxShowRules;
    $("wx-clear-applet").onclick = wxClearApplet;
    $("wx-clear-output").onclick = wxClearOutput;
  }

  function wxSetResult(title, meta, data) {
    $("wx-empty").style.display = "none";
    $("wx-result").classList.add("on");
    $("wx-result").innerHTML = `
      <h3 id="wx-result-title">提取结果</h3>
      <div id="wx-result-meta" class="wx-result-meta"></div>
      <pre id="wx-out">等待解包。</pre>`;
    $("wx-result-title").textContent = title || "提取结果";
    $("wx-result-meta").textContent = meta || "";
    $("wx-out").textContent = typeof data === "string" ? data : JSON.stringify(data || {}, null, 2);
  }

  function wxCategoryItems(extracted, key) {
    if (!extracted) return [];
    if (key === "cred") return [...(extracted.cred || []), ...(extracted.sensitive || [])];
    return extracted[key] || [];
  }

  function wxRenderExtractedList(items) {
    const list = $("wx-extract-list");
    if (!list) return;
    if (!items || !items.length) {
      list.innerHTML = '<div class="wx-extract-empty">暂无结果</div>';
      return;
    }
    list.innerHTML = items.map((v, i) => `
      <div class="wx-extract-row">
        <div class="wx-extract-line">${i + 1}</div>
        <div class="wx-extract-value">${esc(v)}</div>
      </div>`).join("");
  }

  function wxSetExtractedResult(app) {
    const result = app.extractResult || {};
    const extracted = result.extracted || {};
    const cats = [
      ["api", "API"],
      ["url", "URL"],
      ["cred", "账号密码"],
      ["key", "Key"],
      ["static", "静态资源"]
    ].map(([key, label]) => ({ key, label, items: wxCategoryItems(extracted, key) }));
    $("wx-empty").style.display = "none";
    $("wx-result").classList.add("on");
    $("wx-result").innerHTML = `
      <div class="wx-extract-title">${esc(app.name || app.appid || result.appid || "提取结果")}</div>
      <div class="wx-extract-path">${esc(result.outdir || app.outdir || app.path || "")}</div>
      <div class="wx-extract-tabs">
        ${cats.map((c, i) => `<button class="wx-extract-tab ${i === 0 ? "on" : ""}" data-cat="${esc(c.key)}">${esc(c.label)}(${c.items.length})</button>`).join("")}
      </div>
      <div id="wx-extract-list" class="wx-extract-list"></div>`;
    document.querySelectorAll(".wx-extract-tab").forEach((b) => {
      b.onclick = () => {
        document.querySelectorAll(".wx-extract-tab").forEach((x) => x.classList.toggle("on", x === b));
        const cat = cats.find((x) => x.key === b.dataset.cat);
        wxRenderExtractedList(cat ? cat.items : []);
      };
    });
    wxRenderExtractedList(cats[0] ? cats[0].items : []);
  }

  function wxSetRulesResult(rules) {
    const entries = Object.entries(rules || {}).sort((a, b) => a[0].localeCompare(b[0]));
    $("wx-empty").style.display = "none";
    $("wx-result").classList.add("on");
    $("wx-result").innerHTML = `
      <div class="wx-extract-title">信息提取规则</div>
      <div class="wx-extract-path">用于从小程序包中提取 API、URL、账号密码、Key、静态资源等信息</div>
      <div class="wx-rule-list">
        ${entries.map(([name, patterns]) => `
          <div class="wx-rule-item">
            <div class="wx-rule-head">
              <div class="wx-rule-name">${esc(name)}</div>
              <div class="wx-rule-count">${(patterns || []).length} 条</div>
            </div>
            ${(patterns || []).map((p) => `<div class="wx-rule-pattern">${esc(p)}</div>`).join("") || '<div class="wx-rule-pattern">暂无规则</div>'}
          </div>`).join("") || '<div class="wx-extract-empty">暂无规则</div>'}
      </div>`;
  }

  function wxVersion(x) {
    const v = x && (x.version || x.ver || x.pkg_version || "");
    return String(v || "-").replace(/^v/i, "");
  }

  function wxFilterApps() {
    const q = (($("wx-search") || {}).value || "").trim().toLowerCase();
    return wxApps.filter((x) => {
      const hay = [x.name, x.appid, x.path, x.subject].map((v) => String(v || "").toLowerCase()).join(" ");
      return !q || hay.includes(q);
    });
  }

  function wxRenderList() {
    const list = $("wx-list");
    if (!list) return;
    const rows = wxFilterApps();
    list.innerHTML = rows.map((x, i) => `
      <div class="wx-app-card" data-i="${i}">
        <div class="wx-app-head">
          <div class="wx-app-name">${esc(x.name || x.appid || "(未识别名)")}</div>
          <div class="wx-app-time">${esc(x.mtime || "")}</div>
        </div>
        <div class="wx-app-actions">
          <span class="wx-version">版本: ${esc(wxVersion(x))}</span>
          <button class="wx-icon-btn wx-act-unpack" data-tip="解包" aria-label="解包" data-i="${i}">${wxIcon("unpack")}</button>
          <button class="wx-icon-btn wx-act-folder" data-tip="打开文件夹" aria-label="打开文件夹" data-i="${i}">${wxIcon("folder")}</button>
          <button class="wx-icon-btn wx-act-result" data-tip="获取提取结果" aria-label="获取提取结果" data-i="${i}">${wxIcon("result")}</button>
        </div>
      </div>`).join("") || '<div class="wx-extract-empty">没有找到小程序缓存，可以修改 Applet 目录后重新扫描。</div>';
    list.querySelectorAll(".wx-act-unpack").forEach((b) => b.onclick = () => wxUnpack(rows[+b.dataset.i], true));
    list.querySelectorAll(".wx-act-folder").forEach((b) => b.onclick = () => wxOpenPath((rows[+b.dataset.i] || {}).outdir || (rows[+b.dataset.i] || {}).path));
    list.querySelectorAll(".wx-act-result").forEach((b) => b.onclick = () => wxShowResult(rows[+b.dataset.i]));
  }

  wxScan = async function () {
    wxInstallWorkbench();
    $("wx-state").textContent = "扫描中...";
    const root = $("wx-root").value.trim();
    try {
      const r = await rawGet("/api/wxapkg/scan" + (root ? "?root=" + encodeURIComponent(root) : ""));
      $("wx-root").value = r.root || root;
      wxApps = (r.apps || []).map((x) => ({ ...x }));
      $("wx-state").textContent = "找到 " + (r.count || wxApps.length || 0) + " 个小程序";
      wxRenderList();
      if ($("wx-auto-unpack").checked) {
        for (const app of wxApps) await wxUnpack(app, false);
        wxSetResult("自动解包完成", r.root || root, { count: wxApps.length, apps: wxApps.map((x) => ({ appid: x.appid, outdir: x.outdir, extracted: x.extractResult && x.extractResult.extracted })) });
      }
    } catch (e) {
      $("wx-state").textContent = "扫描失败: " + e;
      wxSetResult("扫描失败", root, String(e));
    }
  };

  wxUnpack = async function (app, showResult) {
    if (!app || !app.path) return;
    if (showResult) wxSetResult("解包中...", app.path, "正在解包，请稍等。");
    try {
      const r = await rawPost("/api/wxapkg/unpack", {
        path: app.path,
        appid: app.appid || "",
        reconstruct: $("wx-reconstruct").checked
      });
      app.outdir = r.outdir || "";
      app.extractResult = {
        appid: r.appid,
        encrypted: r.encrypted,
        outdir: r.outdir,
        files: r.count,
        written: r.written,
        extracted: r.extracted || {},
        notes: r.notes || []
      };
      wxLastOutDir = app.outdir || wxLastOutDir;
      wxRenderList();
      if (showResult) wxShowResult(app);
    } catch (e) {
      app.extractError = String(e);
      if (showResult) wxSetResult("解包失败", app.path || "", String(e));
    }
  };

  async function wxOpenPath(path) {
    const a = api();
    if (!path) return wxSetResult("没有可打开的目录", "", "请先解包，或者选择一个有效的小程序缓存。");
    const dir = String(path).toLowerCase().endsWith(".wxapkg") ? String(path).replace(/[\\/][^\\/]*$/, "") : path;
    if (a && a.OpenFolder) {
      const msg = await a.OpenFolder(dir);
      wxSetResult("打开文件夹", dir, msg || dir);
    } else {
      wxSetResult("打开文件夹", dir, "当前运行环境没有桌面打开目录能力。");
    }
  }

  wxOpen = async function () {
    return wxOpenPath(wxLastOutDir);
  };

  async function wxShowResult(app) {
    if (!app) return;
    if (app.extractResult) {
      wxSetExtractedResult(app);
      return;
    }
    app.extractError = "";
    wxSetResult("获取提取结果中...", app.path || "", "未发现本次提取结果，正在自动解包并提取信息。");
    await wxUnpack(app, true);
  }

  async function wxShowRules() {
    try {
      const r = await rawGet("/api/wxapkg/rules");
      wxSetRulesResult(r);
    } catch (e) {
      wxSetResult("规则读取失败", "", String(e));
    }
  }

  async function wxChooseDir() {
    const a = api();
    if (!a || !a.SelectFolder) {
      wxSetResult("选择目录", "", "当前环境没有目录选择能力，可以直接把 Applet 目录粘贴到上方输入框。");
      return;
    }
    try {
      const picked = await a.SelectFolder($("wx-root").value || "");
      if (picked) {
        $("wx-root").value = picked;
        await wxScan();
      }
    } catch (e) {
      wxSetResult("选择目录失败", "", String(e));
    }
  }

  async function wxClearApplet() {
    const root = $("wx-root").value.trim();
    if (!root) return wxSetResult("清空Applet目录", "", "请先填写 Applet 目录。");
    if (!confirm("确认清空 Applet 缓存目录？\n" + root)) return;
    const a = api();
    try {
      const msg = a && a.ClearWxAppletDir ? await a.ClearWxAppletDir(root) : "桌面后端未提供清理接口。";
      wxApps = [];
      wxRenderList();
      wxSetResult("清空Applet目录", root, msg);
    } catch (e) {
      wxSetResult("清空Applet目录失败", root, String(e));
    }
  }

  async function wxClearOutput() {
    const root = $("wx-root").value.trim();
    if (!root) return wxSetResult("清空解包后的文件", "", "请先填写 Applet 目录。");
    if (!confirm("确认清空解包后的 *_unpacked 文件夹？\n" + root)) return;
    const a = api();
    try {
      const msg = a && a.ClearWxUnpackedDirs ? await a.ClearWxUnpackedDirs(root) : "桌面后端未提供清理接口。";
      for (const app of wxApps) {
        app.outdir = "";
        app.extractResult = null;
      }
      wxRenderList();
      wxSetResult("清空解包后的文件", root, msg);
    } catch (e) {
      wxSetResult("清空解包后的文件失败", root, String(e));
    }
  }

  async function turboRun() {
    const body = {
      scheme: $("tb-scheme").value,
      host: $("tb-host").value.trim(),
      raw: $("tb-raw").value,
      payloads: $("tb-payloads").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
      count: parseInt($("tb-count").value, 10) || 1,
      concurrency: parseInt($("tb-concurrency").value, 10) || 1,
      gate: $("tb-mode").value === "race",
      delay_ms: parseInt($("tb-delay").value, 10) || 60
    };
    $("tb-results").innerHTML = '<tr><td colspan="6" class="hint">运行中...</td></tr>';
    $("tb-detail").textContent = "等待响应。";
    try {
      const r = await rawPost("/api/turbo/run", body);
      const rows = r.results || [];
      $("tb-results").innerHTML = rows.map((x, i) => `
        <tr class="tb-row" data-i="${i}">
          <td>${x.index}</td>
          <td>${esc(x.payload || "")}</td>
          <td>${x.status || ""}</td>
          <td>${x.length || ""}</td>
          <td>${x.millis || ""}</td>
          <td>${esc(x.error || "")}</td>
        </tr>`).join("") || '<tr><td colspan="6" class="hint">无结果</td></tr>';
      document.querySelectorAll(".tb-row").forEach((tr) => tr.onclick = () => {
        const x = rows[+tr.dataset.i] || {};
        $("tb-detail").textContent = x.resp_raw || x.error || "无响应体";
      });
    } catch (e) {
      $("tb-results").innerHTML = '<tr><td colspan="6" class="hint">失败</td></tr>';
      $("tb-detail").textContent = String(e);
    }
  }

  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => activate(b)));
  $("start").onclick = startCapx;
  $("ports").onclick = focusPorts;
  $("save-ports").onclick = savePorts;
  $("offline-start").onclick = startCapx;
  $("stop").onclick = stopCapx;
  $("reload").onclick = reload;
  $("wx-scan").onclick = wxScan;
  $("wx-open").onclick = wxOpen;
  $("seq-run").onclick = seqAnalyze;
  $("seq-load-values").onclick = seqLoadValues;
  $("seq-clear").onclick = () => {
    $("seq-in").value = "";
    $("seq-out").textContent = "等待分析。";
    $("seq-bars").innerHTML = "";
    $("seq-summary").textContent = "";
    $("seq-m-count").textContent = "0";
    $("seq-m-uniq").textContent = "0";
    $("seq-m-entropy").textContent = "0";
  };
  $("tb-run").onclick = turboRun;

  setInterval(() => {
    check().then((ok) => {
      if (ok && offline.classList.contains("on")) openWeb(currentWebView, true);
    });
    if ($("auto-refresh").checked && frame.style.display !== "none") postFrame('capx:refresh');
  }, 3000);

  loadRuntimeInfo().then(() => check()).then(() => openWeb(currentWebView, true));
})();
