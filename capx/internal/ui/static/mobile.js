/* Android / iOS capture workspace. Opening the page only reads device/listener state. */
(() => {
  'use strict';
  const el = id => document.getElementById('mob_' + id);
  const panel = document.getElementById('v_mobile');
  if (!panel) return;
  const state = { platform: 'android', screenWidth: 0, screenHeight: 0, serial: '', devices: [], proxy: null, status: null, error: '', busy: false,
    reading: false, epoch: 0, photoURL: '', photoSerial: '', snapshotSerial: '' };
  const ios = () => state.platform === 'ios';
  const online = () => state.devices.some(d => d.serial === state.serial && d.state === 'device');
  const active = () => panel.classList.contains('active');
  const lan = { data: null, busy: false, error: '', portEdited: false };

  function renderLAN() {
    const running = !!lan.data?.running;
    el('lan_state').textContent = lan.error ? '状态读取失败' : running ? '已开启' : '未开启';
    el('lan_state').dataset.tone = lan.error ? 'error' : running ? 'ok' : '';
    el('lan_addr').textContent = running ? lan.data.addr : '未开启';
    el('lan_start').disabled = lan.busy || running || !lan.data?.available || !el('lan_host').value || !el('lan_clients').value.trim();
    el('lan_stop').disabled = lan.busy || !running;
    el('lan_host').disabled = el('lan_port').disabled = lan.busy || running;
    el('lan_clients').disabled=lan.busy||running;
    el('lan_refresh').disabled = lan.busy;
    if (!running && !lan.portEdited && state.proxy?.addr) {
      const match = /:(\d+)$/.exec(state.proxy.addr);if(match)el('lan_port').value=match[1];
    }
  }

  async function refreshLAN() {
    if(lan.busy)return;
    lan.busy=true;renderLAN();
    try {
      const data=await request('/api/proxy/lan');
      const selected=el('lan_host').value;
      const options=(data.addresses||[]).map(address=>new Option(address.host+' · '+address.interface,address.host));
      el('lan_host').replaceChildren(...(options.length?options:[new Option('未检测到局域网 IPv4 地址','')]));
      if(options.some(option=>option.value===selected))el('lan_host').value=selected;
      if(data.running){const match=/^([^:]+):(\d+)$/.exec(data.addr);if(match){el('lan_host').value=match[1];el('lan_port').value=match[2];}}
      if(data.running)el('lan_clients').value=(data.allowed_clients||[]).join(', ');
      lan.data=data;lan.error='';
    }catch(error){lan.error=error.message;el('lan_message').textContent=error.message;}
    finally{lan.busy=false;renderLAN();}
  }

  async function changeLAN(start) {
    if(lan.busy)return;
    const host=el('lan_host').value,port=Number(el('lan_port').value);
    if(start&&(!host||!Number.isInteger(port)||port<1||port>65535)){el('lan_message').textContent='请选择电脑局域网 IP，并填写有效端口。';return;}
    lan.busy=true;renderLAN();
    try {
      const allowed_clients=el('lan_clients').value.split(/[,;\s]+/).filter(Boolean);
      lan.data=await request('/api/proxy/lan/'+(start?'start':'stop'),start?{host,port,allowed_clients}:{});
      lan.error='';
      el('lan_message').textContent=start?'已开启。请在手机 Wi-Fi 手动代理中填写服务器 '+host+'，端口 '+port+'。':'Wi-Fi 入口已关闭，请在手机 Wi-Fi 设置中关闭手动代理。';
    }catch(error){el('lan_message').textContent=error.message;}
    finally{lan.busy=false;renderLAN();}
  }

  async function request(path, body, serial = '', binary = false) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120000);
    try {
      const query = new URLSearchParams();
      if (serial) query.set('serial', serial);
      if (path.startsWith('/api/mobile/') && ios()) query.set('platform', 'ios');
      const url = path + (query.size ? '?' + query.toString() : '');
      const response = await fetch(url, { signal: controller.signal, cache: 'no-store',
        ...(body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }) });
      if (binary && response.ok) {
        if (!response.headers.get('Content-Type')?.includes('image/png')) throw new Error('截图接口未返回 PNG 图片');
        const blob = await response.blob();
        return { blob, width: Number(response.headers.get('X-Capx-Screen-Width')), height: Number(response.headers.get('X-Capx-Screen-Height')) };
      }
      const text = await response.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; }
      catch (_) { throw new Error('后台返回了无法识别的响应，请确认使用新版抓包服务'); }
      if (!response.ok) {
        if (response.status === 404 && path.startsWith('/api/mobile/')) throw new Error('当前后台不支持 App 抓包，请重新编译并重启新版后台');
        throw new Error(data.error || '请求失败：HTTP ' + response.status);
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('请求超时，请刷新链路状态确认结果');
      throw error;
    } finally { clearTimeout(timeout); }
  }

  function message(text, tone = '') {
    el('message').textContent = text;
    el('message').dataset.tone = tone;
  }

  function controls() {
    const ready = online() && !state.busy && !state.error;
    el('platform').disabled = state.busy || preparing;
    el('ios_controls').classList.toggle('hidden', !ios());
    el('android_capture').classList.toggle('hidden', ios());
    el('wda_connect').disabled = state.busy;
    el('wda_disconnect').disabled = state.busy || !state.serial;
    el('wda_endpoint').disabled = el('wda_session').disabled = state.busy;
    el('input_note').textContent = ios() ? 'iOS WDA 支持中文。请先点击手机输入框。' : 'Android 需先切到英文输入模式，仅支持 ASCII。请先点击手机输入框。';
    el('ca').textContent = ios() ? 'iPhone 证书安装说明' : '推送 CA 证书';
    for (const id of ['ca', 'launch', 'screenshot', 'snapshot', 'back', 'home', 'input']) el(id).disabled = !ready;
    el('ca').disabled = state.busy || (!ios() && (!ready || !state.proxy?.available));
    el('back').disabled = !ready || ios();
    el('start').disabled = ios() || !ready || !!state.error || !state.status || !state.proxy?.available || !!state.status.managed;
    el('stop').disabled = ios() || !online() || state.busy || !state.status?.managed;
    el('device').disabled = state.busy;
    el('refresh').disabled = state.busy || state.reading;
    el('proxy_addr').disabled = state.busy || !!state.proxy?.running;
    el('package').disabled = state.busy;
    el('text').disabled = state.busy;
    el('tap_enabled').disabled = state.busy || !online();
    const photoReady = ready && state.photoSerial === state.serial && !!state.photoURL;
    el('screen_tap').disabled = !photoReady || !el('tap_enabled').checked;
    el('up').disabled = el('down').disabled = !photoReady;
    panel.querySelectorAll('[data-mobile-element]').forEach(button => {
      button.disabled = !ready || button.dataset.usable !== 'true' || state.snapshotSerial !== state.serial;
    });
  }

  function renderStatus() {
    let label = '等待设备', tone = '';
    if (state.error) { label = '状态读取失败'; tone = 'error'; }
    else if (ios() && online()) { label = 'WDA 已连接'; tone = 'ok'; }
    else if (online() && state.status?.wired) {
      label = state.status.managed ? '链路已连接' : '已有代理链路'; tone = state.status.managed ? 'ok' : 'warn';
    } else if (online() && state.status?.managed) { label = '链路需要恢复'; tone = 'warn'; }
    else if (online()) label = '未开启';
    else if (state.serial) { label = '设备未就绪'; tone = 'warn'; }
    el('state').textContent = label;
    el('state').dataset.tone = tone;
    el('listener').textContent = state.proxy?.running ? state.proxy.addr : state.proxy ? '未启动' : '未检查';
    el('proxy').textContent = state.error || !online() ? '未确认' : state.status?.proxy || '未设置';
    el('reverse').textContent = state.error || !online() ? '未确认' : state.status?.reverse || '未建立';
    if (state.proxy?.running) el('proxy_addr').value = state.proxy.addr;
    renderLAN();
    controls();
  }

  function clearScreen() {
    if (state.photoURL) URL.revokeObjectURL(state.photoURL);
    state.photoURL = state.photoSerial = '';
    state.screenWidth = state.screenHeight = 0;
    el('screen').removeAttribute('src');
    el('screen_tap').classList.add('hidden');
    el('screen_empty').classList.remove('hidden');
    el('screen_size').textContent = '尚未读取屏幕';
  }

  function clearElements(note = '尚未读取页面元素') {
    state.snapshotSerial = '';
    const row = document.createElement('tr'), cell = document.createElement('td');
    cell.colSpan = 4; cell.className = 'hint'; cell.textContent = note;
    row.appendChild(cell); el('elements').replaceChildren(row);
    el('elements_note').textContent = '按需读取当前页面，可按元素定位操作。';
  }

  function changedDevice() {
    state.status = null; state.error = '';
    clearScreen(); clearElements();
    el('tap_enabled').checked = false;
    el('ca_note').textContent = ios() ? '请安装当前工作区的 CA，并在设置 → 通用 → 关于本机 → 证书信任设置中开启完全信任。' : '文件将保存到 Download/capx-ca.crt。安装后仍需目标 App 信任该证书。';
  }

  function renderDevices() {
    const select = el('device');
    const options = [new Option('选择设备', '')];
    const names = { device: '已连接', unauthorized: '待授权', offline: '离线' };
    state.devices.forEach(d => options.push(new Option(`${d.model || (ios() ? 'iPhone' : 'Android')} · ${d.serial}（${names[d.state] || d.state}）`, d.serial)));
    if (state.serial && !state.devices.some(d => d.serial === state.serial)) options.push(new Option(state.serial + '（已断开）', state.serial));
    select.replaceChildren(...options); select.value = state.serial;
    const device = state.devices.find(d => d.serial === state.serial);
    el('device_hint').textContent = ios() ? (device?.state === 'device' ? 'WDA 操作通道已连接；HTTPS 抓包另外使用 Wi-Fi 代理和 CA。' : '请启动手机 WDA 的 XCTest 后连接；离线时请检查 USB 转发、签名和授权。') : device?.state === 'unauthorized' ? '请解锁手机，并在手机上允许此电脑进行 USB 调试。'
      : device?.state === 'offline' ? '设备处于离线状态，请重新连接 USB 后刷新。'
      : !state.devices.length ? '未检测到设备。请连接 USB、开启调试并在手机上授权。'
      : !device ? (state.serial ? '所选设备已断开；重新连接后可继续恢复原来的代理配置。' : '检测到多台设备，请选择要抓包的手机。')
      : '通过 USB 转发连接本地代理，手机与电脑无需处于同一 Wi-Fi。';
  }

  async function refresh() {
    const epoch = ++state.epoch;
    state.reading = true; controls();
    try {
      const results = await Promise.allSettled([request('/api/mobile/devices'), request('/api/proxy/status')]);
      if (epoch !== state.epoch) return;
      if (results[0].status === 'rejected') throw results[0].reason;
      state.devices = Array.isArray(results[0].value.devices) ? results[0].value.devices : [];
      if (!state.serial) {
        const connected = state.devices.filter(d => d.state === 'device');
        if (connected.length === 1) { state.serial = connected[0].serial; changedDevice(); }
      }
      renderDevices();
      if (!online()) { state.status = null; clearScreen(); clearElements(); }
      if (results[1].status === 'rejected') throw results[1].reason;
      state.proxy = results[1].value;
      if (state.error && el('message').textContent === state.error) message('设备状态已更新。');
      state.error = '';
      if (online()) {
        const serial = state.serial;
        const status = await request('/api/mobile/status', undefined, serial);
        if (epoch !== state.epoch || serial !== state.serial) return;
        if (status.serial !== serial) throw new Error('后台返回的设备不匹配，请升级后台后重试');
        state.status = status;
      }
    } catch (error) {
      if (epoch !== state.epoch) return;
      state.error = error.message;
      clearScreen(); clearElements('状态读取失败，请刷新设备后重新读取');
      message(error.message, 'error');
    } finally {
      if (epoch === state.epoch) { state.reading = false; renderStatus(); }
    }
  }

  async function run(label, action) {
    if (state.busy || !online()) return;
    const serial = state.serial;
    ++state.epoch; state.reading = false; state.busy = true;
    controls(); message(label + '…');
    try {
      const result = await action(serial);
      if (result) message(result, 'ok');
    } catch (error) { message(error.message, 'error'); }
    finally { state.busy = false; controls(); }
  }

  async function screenshot(serial) {
    clearScreen();
    const picture = await request('/api/mobile/screenshot', undefined, serial, true);
    const blob = picture.blob;
    const url = URL.createObjectURL(blob);
    try {
      const probe = new Image(); probe.src = url; await probe.decode();
      if (serial !== state.serial) { URL.revokeObjectURL(url); return; }
      if (ios() && (!Number.isFinite(picture.width) || !Number.isFinite(picture.height) || !(picture.width > 0) || !(picture.height > 0))) throw new Error('iOS 截图缺少 points 尺寸，请升级后台');
      el('screen').src = url;
      await el('screen').decode();
      state.photoURL = url; state.photoSerial = serial;
      state.screenWidth = picture.width || probe.naturalWidth; state.screenHeight = picture.height || probe.naturalHeight;
      el('screen_tap').classList.remove('hidden'); el('screen_empty').classList.add('hidden');
      el('screen_size').textContent = probe.naturalWidth + ' × ' + probe.naturalHeight + (ios() ? ' 像素 · ' + state.screenWidth + ' × ' + state.screenHeight + ' points' : '');
    } catch (error) { URL.revokeObjectURL(url); clearScreen(); throw error; }
  }

  async function operate(serial, path, body) {
    const hadPhoto = state.photoSerial === serial;
    await request('/api/mobile/' + path, body, serial);
    clearScreen(); clearElements('页面已变化，请重新读取元素');
    if (hadPhoto) {
      try { await screenshot(serial); }
      catch (error) { throw new Error('操作已完成，但刷新截图失败：' + error.message); }
    }
    return '操作已完成。';
  }

  let preparing = false, prepareGeneration = 0;
  function setupControls() {
    for (const id of ['ios_check','ios_prepare']) el(id).disabled = preparing || state.busy;
  }
  async function checkIOSSetup() {
    el('ios_check').disabled = true;
    try {
      const info = await request('/api/mobile/ios/setup');
      const selected = el('ios_usb').value;
      const options = [new Option('自动选择唯一设备',''), ...(info.devices || []).map(d => new Option(d.udid,d.udid))];
      el('ios_usb').replaceChildren(...options);
      if (options.some(o=>o.value===selected)) el('ios_usb').value = selected;
      const note = info.profile_expired ? '；配置的 WDA 描述文件已过期，需要重新签名' : '';
      el('ios_job').textContent = (info.message || ('工具已就绪，检测到 '+(info.devices || []).length+' 台 iPhone')) + note;
    } catch (error) { el('ios_job').textContent = error.message; }
    finally { setupControls(); }
  }
  async function pollIOSSetup(generation, backendGeneration) {
    while (preparing && generation === prepareGeneration) {
      try {
        const job = await request('/api/mobile/ios/setup/status');
        if (generation !== prepareGeneration) return;
        if (job.generation !== backendGeneration) { preparing = false; setupControls(); el('ios_job').textContent = '准备任务已更新，请重新检测环境'; return; }
        el('ios_job').textContent = job.phase + ' · ' + job.message;
        if (!job.running) {
          preparing = false; setupControls();
          if (job.state === 'ready') {
            el('wda_endpoint').value = job.endpoint;
            if (ios()) { state.serial = ''; changedDevice(); await refresh(); }
          }
          return;
        }
      } catch (error) { el('ios_job').textContent = error.message; preparing = false; setupControls(); return; }
      await new Promise(resolve => setTimeout(resolve,1500));
    }
  }
  el('ios_check').onclick = checkIOSSetup;
  el('ios_prepare').onclick = async () => {
    if (preparing || state.busy) return;
    preparing = true; setupControls();
    try {
      const raw = new URL(el('wda_endpoint').value);
      if (!['127.0.0.1','localhost','[::1]'].includes(raw.hostname) || raw.protocol !== 'http:' || !raw.port) throw new Error('WDA 请使用有效的本机转发端口');
      const body = { udid:el('ios_usb').value, ipa_path:el('ios_ipa').value.trim(), bundle_id:el('ios_bundle').value.trim(), p12_path:el('ios_p12').value.trim(), profile_path:el('ios_profile').value.trim(), port:Number(raw.port) };
      const job = await request('/api/mobile/ios/prepare', body);
      el('ios_job').textContent = job.message;
      pollIOSSetup(++prepareGeneration, job.generation);
    } catch (error) { preparing = false; setupControls(); el('ios_job').textContent = error.message; }
  };
  el('ios_prepare_stop').onclick = async () => {
    try { const job = await request('/api/mobile/ios/prepare/stop', {}); ++prepareGeneration; preparing = false; setupControls(); el('ios_job').textContent = job.message; }
    catch (error) { el('ios_job').textContent = error.message; }
  };

  el('platform').onchange = () => {
    state.platform = el('platform').value; state.serial = ''; state.devices = [];
    changedDevice(); el('package').value = ios() ? 'com.tencent.xin' : 'com.tencent.mm';
    renderDevices(); renderStatus(); refresh();
  };
  async function connectIOS(connect) {
    if (state.busy) return;
    ++state.epoch; state.reading = false; state.busy = true; controls();
    try {
      await request('/api/mobile/ios/' + (connect ? 'connect' : 'disconnect'), connect ? { endpoint: el('wda_endpoint').value.trim(), session_id: el('wda_session').value.trim() } : {});
      state.serial = ''; state.devices = []; changedDevice();
      await refresh();
      if (state.error) throw new Error(state.error);
      message(connect ? 'WDA 已连接，可以读取屏幕和操作手机。抓包请配置 Wi-Fi 代理。' : '操作连接已断开，手机 App 和 WDA 保持运行。', 'ok');
    } catch (error) { message(error.message, 'error'); }
    finally { state.busy = false; controls(); }
  }
  el('wda_connect').onclick = () => connectIOS(true);
  el('wda_disconnect').onclick = () => connectIOS(false);

  el('refresh').onclick = () => refresh();
  el('device').onchange = () => {
    state.serial = el('device').value; changedDevice();
    message('已切换设备，请检查链路状态。'); renderStatus(); refresh();
  };
  el('start').onclick = () => run('正在开启抓包', async serial => {
    let proxy = await request('/api/proxy/status');
    if (!proxy.available) throw new Error('当前实例的 MITM 代理不可用');
    if (!proxy.running) {
      const addr = el('proxy_addr').value.trim();
      const match = /^(127\.0\.0\.1|localhost):(\d{1,5})$/.exec(addr);
      if (!match || Number(match[2]) > 65535) throw new Error('请填写本地代理地址，例如 127.0.0.1:18080');
      try { await request('/api/proxy/start', { addr }); }
      catch (error) {
        proxy = await request('/api/proxy/status');
        if (!proxy.running) throw error;
      }
    }
    try { await request('/api/mobile/capture/start', {}, serial); }
    catch (error) { await refresh(); throw error; }
    await refresh();
    if (typeof proxyStatus === 'function') await proxyStatus().catch(() => {});
    if (!state.status?.wired || state.error) throw new Error(state.error || '已创建抓包会话，但链路未就绪；请检查状态后停止并重试');
    return '设备代理已配置。操作手机后，点击「查看 HTTP 流量」查看请求。';
  });
  el('stop').onclick = () => run('正在恢复设备代理', async serial => {
    try { await request('/api/mobile/capture/stop', {}, serial); }
    catch (error) { await refresh(); throw error; }
    await refresh();
    if (state.error) throw new Error('停止请求已完成，但状态确认失败：' + state.error);
    return '已停止本次抓包，并恢复本实例修改的设备代理。';
  });
  el('ca').onclick = () => { if (ios()) { el('ca_note').textContent = '先启用上方 Wi-Fi 代理。通过当前工作区下载 CA，在 iPhone 安装并开启完全信任。WDA 操作授权不包含 CA 信任。'; message('iPhone CA 安装与信任需在系统设置中确认。'); return; } return run('正在推送 CA 证书', async serial => {
    const result = await request('/api/mobile/ca', {}, serial);
    el('ca_note').textContent = result.ca_note || '证书已推送，请在手机安全设置中确认安装。';
    clearScreen(); clearElements('手机已打开证书设置，请重新读取元素');
    return '证书已推送，请在手机上完成安装。';
  }); };
  el('screenshot').onclick = () => run('正在读取手机屏幕', async serial => { await screenshot(serial); return '截图已更新。'; });
  el('launch').onclick = () => run('正在启动 App', serial => {
    const pkg = el('package').value.trim();
    const validPackage = ios() ? /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/ : /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
    if (!validPackage.test(pkg)) throw new Error(ios() ? '请输入有效的 iOS bundle ID，例如 com.tencent.xin' : '请输入有效的 Android 包名，例如 com.tencent.mm');
    return operate(serial, 'launch', { package: pkg });
  });
  el('back').onclick = () => run('正在返回', serial => operate(serial, 'back', {}));
  el('home').onclick = () => run('正在返回桌面', serial => operate(serial, 'key', { keycode: 'KEYCODE_HOME' }));
  el('input').onclick = () => run('正在输入文字', async serial => {
    const value = el('text').value;
    if (!value) throw new Error('请先填写要输入的文字');
    if (!ios() && /[^\x20-\x7e]/.test(value)) throw new Error('当前输入通道仅支持英文字母、数字和符号，暂不支持中文');
    const result = await operate(serial, 'input', { value });
    el('text').value = ''; return result;
  });
  el('tap_enabled').onchange = controls;
  el('screen_tap').onclick = event => {
    if (el('screen_tap').disabled || state.photoSerial !== state.serial) return;
    // Keyboard activation does not identify a screen coordinate.
    if (event.detail === 0) { message('请在截图上点击要操作的位置。'); return; }
    const img = el('screen'), rect = img.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const x = Math.floor((event.clientX - rect.left) / rect.width * state.screenWidth);
    const y = Math.floor((event.clientY - rect.top) / rect.height * state.screenHeight);
    if (x < 0 || y < 0 || x >= state.screenWidth || y >= state.screenHeight) return;
    run('正在点击手机', serial => operate(serial, 'tap', { x, y }));
  };
  for (const [id, from, to] of [['up', .75, .25], ['down', .25, .75]]) {
    el(id).onclick = () => run('正在滑动', serial => {
      const img = el('screen');
      const x = Math.floor(state.screenWidth / 2);
      return operate(serial, 'swipe', { x1: x, y1: Math.floor(state.screenHeight * from), x2: x, y2: Math.floor(state.screenHeight * to), duration_ms: 350 });
    });
  }

  el('snapshot').onclick = () => run('正在读取页面元素', async serial => {
    clearElements('正在读取页面元素…');
    const snapshot = await request('/api/mobile/snapshot', undefined, serial);
    const elements = Array.isArray(snapshot.elements) ? snapshot.elements : [];
    state.snapshotSerial = serial;
    el('elements_note').textContent = snapshot.degraded
      ? '当前为基础视图模式，无文字定位，位置可能不准确。请通过截图操作。'
      : '已读取 ' + elements.length + ' 个元素；点击后重新定位目标。';
    if (!elements.length) {
      clearElements('当前页面没有可用元素，可使用截图操作。');
      return '页面读取完成，没有可用元素。';
    }
    const rows = elements.map(item => {
      const row = document.createElement('tr');
      for (const text of [item.text || item.content_desc || '—', item.resource_id || '—', `${item.x}, ${item.y}`]) {
        const cell = document.createElement('td'); cell.textContent = text; row.appendChild(cell);
      }
      const cell = document.createElement('td'), button = document.createElement('button');
      button.className = 'btn sec sm'; button.textContent = '点击'; button.type = 'button'; button.dataset.mobileElement = 'true';
      const locator = item.resource_id ? { resource_id: item.resource_id } : item.text ? { text: item.text } : item.content_desc ? { content_desc: item.content_desc } : null;
      button.dataset.usable = String(!!locator && snapshot.bounds_accurate === true && !snapshot.degraded && item.width > 0 && item.height > 0);
      if (button.dataset.usable !== 'true') button.title = '该元素无法可靠定位，请使用截图操作';
      button.onclick = () => run('正在定位并点击元素', target => {
        if (serial !== target) throw new Error('设备已切换，请重新读取元素');
        return operate(target, 'tap', locator);
      });
      cell.appendChild(button); row.appendChild(cell); return row;
    });
    el('elements').replaceChildren(...rows);
    return snapshot.degraded ? '已读取基础视图，文字定位不可用，请结合截图操作。' : '页面元素已更新。';
  });

  el('decrypt_run').onclick = async () => {
    const id = el('decrypt_id').value, key = el('decrypt_key').value, keyEnv = el('decrypt_key_env').value.trim();
    const output = el('decrypt_result');
    if (!/^[1-9][0-9]*$/.test(id)) { output.textContent = '请选择 HTTP 历史中的有效交易 ID'; return; }
    if (key && keyEnv) { output.textContent = '直接密钥和环境变量引用只能选择一种'; return; }
    el('decrypt_run').disabled = true; output.textContent = '正在解密所选交易…';
    try {
      const result = await request('/api/http/' + id + '/decrypt', { algorithm:'aes', mode:el('decrypt_mode').value, side:el('decrypt_side').value, json_pointer:el('decrypt_pointer').value, input_enc:el('decrypt_encoding').value, key, key_env:keyEnv, iv:el('decrypt_iv').value });
      output.textContent = (result.integrity_verified ? 'AES-GCM 认证标签已验证\n' : '解密运算完成；此模式不提供消息认证\n') + (result.json !== undefined ? JSON.stringify(result.json,null,2) : result.output);
    } catch (error) { output.textContent = error.message; }
    finally { el('decrypt_key').value = ''; el('decrypt_run').disabled = false; }
  };

  el('lan_host').onchange=renderLAN;
  el('lan_clients').oninput=renderLAN;
  el('lan_port').oninput=()=>{lan.portEdited=true;};
  el('lan_refresh').onclick=refreshLAN;
  el('lan_start').onclick=()=>changeLAN(true);
  el('lan_stop').onclick=()=>changeLAN(false);
  window.addEventListener('capx:viewchange', event => { if (event.detail.view === 'mobile' && !state.busy) {refresh();refreshLAN();} });
  setInterval(() => { if (active() && !document.hidden && !state.busy && !state.reading) refresh(); }, 5000);
  window.addEventListener('pagehide', () => { if (state.photoURL) URL.revokeObjectURL(state.photoURL); });
  if (active()) {refresh();refreshLAN();}
})();
