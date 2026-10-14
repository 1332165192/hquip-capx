(() => {
  api = async function(url, options) {
    const target = new URL(url, location.href);
    const postOnly = new Set([
      '/api/start', '/api/stop', '/api/stop-all', '/api/open', '/api/browser',
      '/api/ghost', '/api/ghost-stop', '/api/adb', '/api/adb-stop',
      '/api/open-dir', '/api/copy', '/api/src-template', '/api/select-directory', '/api/exit'
    ]);
    const request = Object.assign({}, options || {});
    if (postOnly.has(target.pathname) && !request.method) request.method = 'POST';
    if (request.body) {
      request.headers = Object.assign({'Content-Type': 'application/json'}, request.headers || {});
    }
    let response;
    try { response = await fetch(url, request); }
    catch (_) { throw new Error('管理器后台连接断开，请重新打开 ' + location.origin + '/'); }
    const value = await response.json();
    if (!value.ok) throw new Error(value.error || 'failed');
    return value;
  };
  const apiLabel = document.getElementById('apiPort').previousElementSibling;
  apiLabel.insertAdjacentHTML('beforebegin',
    '<label class="label" for="instanceId" title="受管实例的稳定名称，也是项目配置中的 CAPX_INSTANCE_ID">实例 ID</label><input id="instanceId" placeholder="例如 src_demo" spellcheck="false"><button class="btn compact" type="button" onclick="deriveInstanceId()">自动命名</button><span></span>' +
    '<label class="label" for="projectRoot" title="受管实例所属项目目录；用于校验 .codex/config.toml 或 .mcp.json">项目目录</label><input id="projectRoot" placeholder="选择 CODEX.md / CLAUDE.md 所在项目" spellcheck="false"><button class="btn compact" type="button" onclick="selectProjectDirectory()">选择目录</button><button class="btn compact" type="button" onclick="generateSRCTemplate()">生成模板</button>' +
    '<label class="label" for="jadxDir" title="JADX 安装目录或当前项目的反编译工作目录">JADX 目录</label><input id="jadxDir" placeholder="选择 JADX 安装或工作目录" spellcheck="false"><button class="btn compact" type="button" onclick="selectJADXDirectory()">选择目录</button><button class="btn compact" type="button" onclick="openJADXDirectory()">打开</button>');
  document.getElementById('count').insertAdjacentHTML('afterend',
    '<label class="label" for="cdpPort">CDP 端口</label><input id="cdpPort" type="number" min="0" max="65535" placeholder="自动分配"><span></span><span></span>');
  document.querySelector('.checks').insertAdjacentHTML('afterbegin',
    '<label class="check"><input id="autoPorts" type="checkbox" checked> API / Proxy / CDP 独立自动分配</label>');
  document.querySelector('.checks').insertAdjacentHTML('afterend',
    '<div id="srcTemplatePanel" class="template-panel">' +
      '<div class="template-head"><b>SRC 连接模板</b><span id="srcTemplateMeta" class="small"></span><button class="btn compact" type="button" title="关闭模板" aria-label="关闭模板" onclick="closeSRCTemplate()">×</button></div>' +
      '<textarea id="srcTemplateOutput" spellcheck="false" aria-label="SRC 连接模板"></textarea>' +
      '<div class="template-actions"><button class="btn green" type="button" onclick="copySRCTemplate()">复制全部</button><button class="btn" type="button" onclick="generateSRCTemplate()">按当前表单刷新</button></div>' +
    '</div>');
  document.querySelector('button[onclick="stopAll()"]' ).textContent = '停止全部服务';
  const projectFilterLabel = document.getElementById('showOnlyPath').parentElement;
  projectFilterLabel.lastChild.textContent = ' 只显示所选项目实例';

  const stored = (key) => { try { return localStorage.getItem(key) || ''; } catch (_) { return ''; } };

  const setAutoPorts = (automatic) => {
    const checkbox = document.getElementById('autoPorts');
    checkbox.checked = Boolean(automatic);
    try { localStorage.setItem('capx.autoPorts', checkbox.checked ? 'true' : 'false'); } catch (_) {}
  };

  const selectCustomPorts = () => {
    setAutoPorts(false);
    syncProxy();
  };

  document.getElementById('instanceId').value = stored('capx.instanceId');
  document.getElementById('projectRoot').value = stored('capx.projectRoot');
  document.getElementById('jadxDir').value = stored('capx.jadxDir') || ((cfg && cfg.jadx_dir) || '');

  const originalFill = fill;
  fill = function(value) {
    originalFill(value);
    document.getElementById('jadxDir').value = value.jadx_dir || stored('capx.jadxDir');
    const storedMode = stored('capx.autoPorts');
    document.getElementById('autoPorts').checked = storedMode
      ? storedMode === 'true'
      : value.auto_ports !== false;
    syncProxy();
  };

  const originalSyncProxy = syncProxy;
  syncProxy = function() {
    if (document.getElementById('instanceId').value.trim()) {
      const automatic = document.getElementById('autoPorts').checked;
      document.getElementById('autoProxy').checked = false;
      document.getElementById('mApi').textContent = automatic ? 'auto' : (document.getElementById('apiPort').value || 'auto');
      document.getElementById('mProxy').textContent = automatic ? 'auto' : (document.getElementById('proxyPort').value || 'auto');
      document.getElementById('mapHint').textContent = automatic ? '受管实例：三个端口独立自动分配' : '受管实例：使用表单中的自定义端口';
      return;
    }
    originalSyncProxy();
  };

  const originalReadCfg = readCfg;
  readCfg = function() {
    const value = originalReadCfg();
    const automatic = document.getElementById('autoPorts').checked;
    value.instance_id = document.getElementById('instanceId').value.trim();
    value.project_root = document.getElementById('projectRoot').value.trim();
    value.jadx_dir = document.getElementById('jadxDir').value.trim();
    value.cdp_port = automatic ? 0 : +(document.getElementById('cdpPort').value || 0);
    value.auto_ports = automatic;
    if (automatic && value.instance_id) {
      value.api_port = 0;
      value.proxy_port = 0;
      value.auto_proxy = false;
    }
    return value;
  };

  const originalStart = start;
  start = async function() {
    const instanceID = document.getElementById('instanceId').value.trim();
    const root = document.getElementById('projectRoot').value.trim();
    if (Boolean(instanceID) !== Boolean(root)) {
      status('受管模式需要同时填写实例 ID 和项目根；legacy 模式请将两项都清空', false);
      toast('实例 ID / 项目根需要成对填写');
      return;
    }
    try {
      localStorage.setItem('capx.instanceId', instanceID);
      localStorage.setItem('capx.projectRoot', root);
      localStorage.setItem('capx.jadxDir', document.getElementById('jadxDir').value.trim());
      localStorage.setItem('capx.autoPorts', document.getElementById('autoPorts').checked ? 'true' : 'false');
    } catch (_) {}
    return originalStart();
  };

  const selectDirectory = async (kind) => {
    const input = document.getElementById(kind === 'project' ? 'projectRoot' : 'jadxDir');
    const response = await api('/api/select-directory', {
      method: 'POST',
      body: JSON.stringify({kind, initial: input.value.trim()})
    });
    if (!response.data || !response.data.path) return null;
    input.value = response.data.path;
    return response.data;
  };

  selectProjectDirectory = async function() {
    try {
      const selected = await selectDirectory('project');
      if (!selected) return;
      document.getElementById('instanceId').value = selected.instance_id || '';
      document.getElementById('showOnlyPath').checked = true;
      localStorage.setItem('capx.projectRoot', selected.path);
      localStorage.setItem('capx.instanceId', selected.instance_id || '');
      await saveConfig();
      await refresh();
      status(selected.project_bound
        ? '已绑定项目 ' + selected.path + ' / ' + selected.instance_id
        : '已选择项目；请先把生成模板中的 CAPX_INSTANCE_ID 加入项目配置');
    } catch (error) {
      status(error.message, false);
      toast(error.message);
    }
  };

  selectJADXDirectory = async function() {
    try {
      const selected = await selectDirectory('jadx');
      if (!selected) return;
      localStorage.setItem('capx.jadxDir', selected.path);
      await saveConfig();
      status(selected.jadx_detected ? '已选择并识别 JADX 目录' : '已选择 JADX 工作目录');
    } catch (error) {
      status(error.message, false);
      toast(error.message);
    }
  };

  openJADXDirectory = async function() {
    const directory = document.getElementById('jadxDir').value.trim();
    if (!directory) {
      toast('请先选择 JADX 目录');
      return;
    }
    await openDir(directory);
  };

  deriveInstanceId = function() {
    const root = document.getElementById('projectRoot').value.trim().replace(/[\\/]+$/, '');
    const leaf = root ? root.split(/[\\/]/).pop() : '';
    let value = (leaf || ('src_' + (document.getElementById('apiPort').value || 'project')))
      .toLowerCase().replace(/[^a-z0-9._-]+/g, '_').replace(/^[_\-.]+|[_\-.]+$/g, '');
    if (!value) value = 'src_project';
    if (!value.includes('src')) value += '_src';
    document.getElementById('instanceId').value = value.slice(0, 64);
    syncProxy();
    status('已生成实例 ID：' + document.getElementById('instanceId').value);
  };

  const requestSRCTemplate = async (runtimeAPIPort) => {
    const body = runtimeAPIPort ? {runtime_api_port: Number(runtimeAPIPort)} : {
      instance_id: document.getElementById('instanceId').value.trim(),
      project_root: document.getElementById('projectRoot').value.trim(),
      api_port: Number(document.getElementById('apiPort').value || 0),
      proxy_port: Number(document.getElementById('proxyPort').value || 0),
      cdp_port: Number(document.getElementById('cdpPort').value || 0)
    };
    return api('/api/src-template', {method: 'POST', body: JSON.stringify(body)});
  };

  const displaySRCTemplate = (response) => {
    const data = response.data || {};
    document.getElementById('srcTemplateOutput').value = data.text || '';
    document.getElementById('srcTemplateMeta').textContent =
      (data.source === 'runtime' ? '运行实例' : '启动前') + ' · ' + (data.mode || 'legacy') + ' · 连接由 manifest 动态解析';
    const panel = document.getElementById('srcTemplatePanel');
    panel.classList.add('open');
    panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    status('已生成完整 SRC 模板；连接信息在执行时从当前实例动态解析');
  };

  generateSRCTemplate = async function() {
    try {
      displaySRCTemplate(await requestSRCTemplate(0));
    } catch (error) {
      status(error.message, false);
      toast(error.message);
    }
  };

  showRuntimeSRCTemplate = async function(apiPort) {
    try {
      displaySRCTemplate(await requestSRCTemplate(apiPort));
    } catch (error) {
      status(error.message, false);
      toast(error.message);
    }
  };

  copySRCTemplate = async function() {
    const text = document.getElementById('srcTemplateOutput').value;
    if (!text) return;
    await copy(text);
    status('SRC 模板已复制，可直接粘贴到项目配置或任务中');
  };

  closeSRCTemplate = function() {
    document.getElementById('srcTemplatePanel').classList.remove('open');
  };

  findFree = async function() {
    try {
      const query = new URLSearchParams({api: '0', proxy: '0', cdp: '0'});
      const response = await api('/api/choose-free?' + query.toString());
      document.getElementById('apiPort').value = response.data.api_port;
      document.getElementById('proxyPort').value = response.data.proxy_port;
      document.getElementById('cdpPort').value = response.data.cdp_port;
      setAutoPorts(false);
      syncProxy();
      status('已选择三个独立空闲端口');
    } catch (error) {
      status(error.message, false);
    }
  };

  let managedByPID = new Map();
  let managedByAPI = new Map();
  const originalRender = render;
  render = function(rows) {
    const selectedRoot = document.getElementById('projectRoot').value.trim().toLowerCase().replace(/[\\/]+$/, '');
    const projectOnly = document.getElementById('showOnlyPath').checked && selectedRoot;
    const visibleRows = projectOnly
      ? (rows || []).filter((row) => String(row.project_root || '').toLowerCase().replace(/[\\/]+$/, '') === selectedRoot)
      : (rows || []);
    managedByPID = new Map(visibleRows.map((row) => [Number(row.pid), row]));
    managedByAPI = new Map(visibleRows.map((row) => [Number(row.api_port), row]));
    originalRender(visibleRows);
    const tableRows = [...document.querySelectorAll('#tbody tr')];
    visibleRows.forEach((row, index) => {
      if (!row.instance_id || !tableRows[index]) return;
      const tag = tableRows[index].querySelector('.tag');
      if (tag) {
        tag.textContent = row.instance_id + ' / ' + row.status;
        tag.dataset.state = row.status;
      }
      if (tableRows[index].children[1]) tableRows[index].children[1].title = 'CDP ' + row.cdp_port;
    });
    visibleRows.forEach((row, index) => {
      if (!tableRows[index]) return;
      const operations = tableRows[index].querySelector('.op');
      if (!operations || operations.querySelector('.src-template-btn')) return;
      const button = document.createElement('button');
      button.className = 'btn src-template-btn';
      button.type = 'button';
      button.textContent = 'SRC模板';
      button.title = '生成动态连接、完整测试队列、证据和 Gate 模板';
      button.addEventListener('click', () => showRuntimeSRCTemplate(row.api_port));
      const stopButton = operations.querySelector('.danger');
      operations.insertBefore(button, stopButton || null);
    });
  };

  const originalOpenBrowser = openBrowser;
  openBrowser = async function(apiPort, proxyPort) {
    const row = managedByAPI.get(Number(apiPort));
    if (!row || !row.instance_id) return originalOpenBrowser(apiPort, proxyPort);
    try {
      await api('/api/browser?instance_id=' + encodeURIComponent(row.instance_id));
      toast('已在受管浏览器中打开 Capx');
    } catch (error) {
      status(error.message, false);
      toast(error.message);
    }
  };

  const originalStop = stop;
  stop = async function(pid) {
    const row = managedByPID.get(Number(pid));
    if (!row || !row.instance_id) return originalStop(pid);
    if (!confirm('停止受管实例 ' + row.instance_id + ' ?')) return;
    try {
      await api('/api/stop', {method: 'POST', body: JSON.stringify({pid, instance_id: row.instance_id})});
      toast('受管实例已停止');
      await refresh();
    } catch (error) {
      status(error.message, false);
      toast(error.message);
    }
  };

  useDefaultADB = function() {
    document.getElementById('adbPath').value = (cfg && cfg.adb_path) || 'adb.exe';
    saveConfig();
  };

  document.getElementById('instanceId').addEventListener('input', syncProxy);
  for (const id of ['apiPort', 'proxyPort', 'cdpPort']) {
    document.getElementById(id).addEventListener('input', selectCustomPorts);
  }
  document.getElementById('autoPorts').addEventListener('change', () => {
    setAutoPorts(document.getElementById('autoPorts').checked);
    syncProxy();
  });
  syncProxy();
})();
