/* This workbench targets only the sandbox relay on the host. */
(() => {
  'use strict';
  const panel = document.getElementById('v_wxdesk'); if (!panel) return;
  const el = name => document.getElementById('wxb_' + name);
  const state = {environment: null, windows: [], selected: '', photo: '', photoWindow: '', busy: false, loading: false, epoch: 0, error: false};
  async function api(path, body) {
    const response = await fetch('/api/wxdesk/' + path, {cache:'no-store', signal:AbortSignal.timeout(25000), ...(body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
    if (path.startsWith('screenshot') && response.ok) return response.blob();
    let data;try {data=await response.json();}catch(_){throw new Error('后台未提供隔离微信接口，请更新并重启新版后台');}
    if (!response.ok) throw new Error(data.error || '请求失败：HTTP ' + response.status);
    return data;
  }
  function message(text,error=false) {el('message').textContent=text;el('message').dataset.error=String(error);el('log').textContent=new Date().toLocaleTimeString()+' '+text+'\n'+el('log').textContent.slice(0,6000);}
  function controls() {
    const ready=state.environment?.available&&!state.busy&&!state.error;
    el('prepare').disabled=state.busy||!!state.environment?.available||state.environment?.mode==='windows-sandbox';
    el('start_environment').disabled=state.busy||!!state.environment?.available||state.environment?.mode==='windows-sandbox';
    el('refresh').disabled=state.busy||state.loading;el('window').disabled=state.busy;el('launch').disabled=!ready;
    el('source').disabled=state.busy||!!state.environment?.available;
    el('installer').disabled=el('wechat_exe').disabled=state.busy||!!state.environment?.available;
    for (const name of ['show','shot','input','escape','up','down']) el(name).disabled=!ready||!state.selected;
    el('image_button').disabled=!ready||!state.photo||state.photoWindow!==state.selected||!el('click_enabled').checked;
  }
  function clear() {if(state.photo)URL.revokeObjectURL(state.photo);state.photo=state.photoWindow='';el('image').removeAttribute('src');el('image_button').classList.add('hidden');el('empty').classList.remove('hidden');el('size').textContent='尚未读取';}
  async function refresh() {
    const epoch=++state.epoch;state.loading=true;controls();
    try {
      const environment=await api('environment');if(epoch!==state.epoch)return;
      state.environment=environment;el('environment_state').textContent=environment.available?'隔离环境已连接':'隔离环境未连接';el('environment_note').textContent=environment.note;
      if(!environment.available){state.windows=[];state.selected='';clear();}
      else {
        const result=await api('windows');if(epoch!==state.epoch)return;
        state.windows=Array.isArray(result.windows)?result.windows:[];
        if(state.selected&&!state.windows.some(w=>w.id===state.selected)){state.selected='';clear();}
        if(!state.selected&&state.windows.length===1)state.selected=state.windows[0].id;
      }
      const options=[new Option(state.environment.available?'选择沙箱中的窗口':'请先启动隔离环境','')];
      state.windows.forEach(w=>options.push(new Option((w.title||'微信窗口')+' · '+w.process+' · '+w.pid+(w.minimized?'（最小化）':''),w.id)));
      el('window').replaceChildren(...options);el('window').value=state.selected;
      el('window_state').textContent=state.selected?'窗口已连接（登录待确认）':'未选择窗口';state.error=false;
    }catch(error){if(epoch===state.epoch){state.error=true;clear();message(error.message,true);el('environment_state').textContent='连接读取失败';}}
    finally{if(epoch===state.epoch){state.loading=false;controls();}}
  }
  async function run(action) {
    if(state.busy)return;
    ++state.epoch;state.loading=false;state.busy=true;controls();
    try {await action();}catch(error){message(error.message,true);}finally{state.busy=false;controls();}
  }
  async function photo() {
    const selected=state.selected;clear();
    const blob=await api('screenshot?window_id='+encodeURIComponent(selected));
    const url=URL.createObjectURL(blob);
    try {el('image').src=url;await el('image').decode();if(selected!==state.selected){URL.revokeObjectURL(url);return;}
      state.photo=url;state.photoWindow=selected;el('image_button').classList.remove('hidden');el('empty').classList.add('hidden');el('size').textContent=el('image').naturalWidth+' × '+el('image').naturalHeight;
    }catch(error){URL.revokeObjectURL(url);throw new Error('无法显示窗口截图：'+error.message);}
  }
  async function action(name,body={}) {
    const selected=state.selected;await api(name,{window_id:selected,...body});clear();await refresh();
    if(state.selected===selected&&!state.error) await photo();
    message('操作已发送，请以新画面确认结果。');
  }
  el('refresh').onclick=refresh;
  el('source').onchange=()=>{el('installer_field').classList.toggle('hidden',el('source').value!=='installer');el('client_field').classList.toggle('hidden',el('source').value!=='client');};
  el('window').onchange=()=>{state.selected=el('window').value;el('click_enabled').checked=false;clear();controls();};
  el('prepare').onclick=()=>run(async()=>{message('正在生成隔离包并校验官方安装包…');const source=el('source').value;const body={source};if(source==='client')body.wechat_exe=el('wechat_exe').value.trim();if(source==='installer'){body.installer=el('installer').value.trim();if(!body.installer)throw new Error('请填写官方微信安装包路径');}const result=await api('prepare',body);el('configuration').textContent=result.configuration;message(result.note+(result.sandbox_installed?'':'。此电脑尚未检测到 Windows Sandbox，请先启用该 Windows 功能。'));await refresh();});
  el('start_environment').onclick=()=>run(async()=>{await api('start-environment',{});message('沙箱正在启动，稍后点击刷新环境。进入微信后请使用小号扫码确认。');});
  el('launch').onclick=()=>run(async()=>{await api('launch',{});message('已请求打开沙箱里的官方微信。');await refresh();});
  el('show').onclick=()=>run(()=>action('show'));
  el('shot').onclick=()=>run(async()=>{await photo();message('窗口画面已更新；二维码和登录状态以画面为准。');});
  el('input').onclick=()=>run(async()=>{const value=el('text').value;if(!value)throw new Error('请输入内容');await action('input',{value});el('text').value='';});
  el('escape').onclick=()=>run(()=>action('key',{key:'ESC'}));
  el('up').onclick=()=>run(()=>action('scroll',{delta:360}));el('down').onclick=()=>run(()=>action('scroll',{delta:-360}));
  el('click_enabled').onchange=controls;
  el('image_button').onclick=event=>{if(el('image_button').disabled||event.detail===0)return;const image=el('image'),box=image.getBoundingClientRect();
    const width=image.naturalWidth,height=image.naturalHeight,x=Math.floor((event.clientX-box.left)*width/box.width),y=Math.floor((event.clientY-box.top)*height/box.height);
    if(x<0||y<0||x>=width||y>=height)return;run(()=>action('tap',{x,y,width,height}));};
  el('copy_task').onclick=()=>run(async()=>{await navigator.clipboard.writeText('使用 capx_wxdesk_environment 确认独立微信沙箱已连接，列出隔离窗口并截图。登录由我扫码确认。登录完成后，在小号微信里打开我指定的已发布小程序，依次检查首页、列表和详情，每步重新截图验证。仅操作隔离窗口，不使用本机主号。记录步骤、截图和失败原因。');message('任务已复制，粘贴给已配置 capx-mcp 的 AI 客户端后指定目标小程序。');});
  window.addEventListener('capx:viewchange',event=>{if(event.detail.view==='wxdesk'&&!state.busy)refresh();});
  setInterval(()=>{if(panel.classList.contains('active')&&!document.hidden&&!state.loading&&!state.busy)refresh();},5000);
  window.addEventListener('pagehide',clear);if(panel.classList.contains('active'))refresh();
})();
