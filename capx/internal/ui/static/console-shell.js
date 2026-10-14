/* Presentation-only workspace controls. Capture operations remain in index.html. */
(() => {
  'use strict';

  const nav = document.getElementById('nav');
  const filter = document.getElementById('nav_filter');
  const toggle = document.getElementById('sidebar_toggle');
  const compactScreen = window.matchMedia('(max-width: 960px)');
  const recent = document.getElementById('recent_requests');
  const emptyRecent = recent.firstElementChild.cloneNode(true);
  const navButtons = [...nav.querySelectorAll('button[data-v]')];

  function updateWorkspace(view) {
    const active = navButtons.find(button => button.dataset.v === view);
    if (!active) return;
    document.getElementById('workspace_title').textContent = active.dataset.title;
    document.getElementById('workspace_group').textContent = active.closest('.nav-group').dataset.groupLabel;
    document.title = active.dataset.title + ' · Capx';
    navButtons.forEach(button => {
      if (button === active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
  }

  function filterTools() {
    const query = filter.value.trim().toLocaleLowerCase();
    let count = 0;
    navButtons.forEach(button => {
      const matches = (button.title + ' ' + button.dataset.v).toLocaleLowerCase().includes(query);
      button.classList.toggle('hidden', !matches);
      if (matches) count++;
    });
    nav.querySelectorAll('.nav-group').forEach(group => {
      group.classList.toggle('hidden', !group.querySelector('button:not(.hidden)'));
    });
    document.getElementById('nav_no_results').classList.toggle('hidden', count > 0);
  }

  function updateToggle() {
    const expanded = !document.body.classList.contains('sidebar-collapsed') && !compactScreen.matches;
    toggle.setAttribute('aria-expanded', String(expanded));
    toggle.setAttribute('aria-label', expanded ? '收起导航' : '展开导航');
    toggle.title = expanded ? '收起导航' : '展开导航';
  }

  try {
    document.body.classList.toggle('sidebar-collapsed', localStorage.getItem('capx:sidebar-collapsed') === '1');
  } catch (_) { /* A restricted WebView may not allow persistent preferences. */ }
  updateToggle();
  compactScreen.addEventListener('change', () => {
    if (compactScreen.matches) { filter.value = ''; filterTools(); }
    updateToggle();
  });
  toggle.addEventListener('click', () => {
    const collapsed = document.body.classList.toggle('sidebar-collapsed');
    filter.value = '';
    filterTools();
    updateToggle();
    try { localStorage.setItem('capx:sidebar-collapsed', collapsed ? '1' : '0'); } catch (_) {}
  });
  filter.addEventListener('input', filterTools);
  filter.addEventListener('keydown', event => {
    if (event.key === 'Escape') { filter.value = ''; filterTools(); }
    if (event.key === 'Enter') {
      const first = navButtons.find(button => !button.classList.contains('hidden'));
      if (first) { first.click(); first.focus(); }
    }
  });
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && !compactScreen.matches && !document.body.classList.contains('embed')) {
      event.preventDefault();
      if (document.body.classList.contains('sidebar-collapsed')) toggle.click();
      filter.focus();
      filter.select();
    }
  });

  async function openView(view, sub, transactionID) {
    showView(view);
    if (sub) {
      const tab = document.querySelector(`.subtabs[data-group="${view}"] button[data-s="${sub}"]`);
      if (tab) tab.click();
    }
    if (transactionID != null) {
      const row = [...document.querySelectorAll('#hh_listwrap tr[data-id]')].find(item => item.dataset.id === String(transactionID));
      if (row) { row.click(); row.scrollIntoView({ block: 'nearest' }); }
      else {
        // A dashboard item can be outside an existing history filter or a dedup group.
        const summary = HIST.find(item => String(item.id) === String(transactionID));
        if (summary) {
          await openHttpDetail(summary, 'hh');
        }
      }
    }
  }

  document.addEventListener('click', event => {
    const action = event.target.closest('[data-open-view]');
    if (!action) return;
    openView(action.dataset.openView, action.dataset.openSub, action.dataset.transactionId);
  });

  function cell(row, text, className) {
    const td = document.createElement('td');
    td.textContent = text;
    if (className) td.className = className;
    row.appendChild(td);
    return td;
  }

  function renderRecent(data) {
    const rows = Array.isArray(data.recent) ? data.recent : [];
    recent.replaceChildren();
    document.getElementById('recent_summary').textContent = data.total
      ? `最近 ${rows.length} 条 · 共 ${Number(data.total).toLocaleString()} 条请求`
      : '实时展示当前工作空间的最新流量';
    if (!rows.length) { recent.appendChild(emptyRecent.cloneNode(true)); return; }
    rows.forEach(tx => {
      const row = document.createElement('tr');
      const method = document.createElement('span');
      method.className = 'method-badge ' + methodCls(tx.method);
      method.textContent = tx.method || '—';
      cell(row, '').appendChild(method);
      const link = document.createElement('button');
      link.className = 'request-link';
      link.textContent = (tx.host || '') + (tx.path || '/');
      link.title = link.textContent;
      link.dataset.openView = 'proxy';
      link.dataset.openSub = 'httphist';
      link.dataset.transactionId = tx.id;
      cell(row, '').appendChild(link);
      cell(row, tx.status || '—', statusCls(tx.status));
      cell(row, fmtBytes(tx.resp_len));
      cell(row, (tx.scheme || 'http').toUpperCase(), 'protocol');
      recent.appendChild(row);
    });
  }

  window.addEventListener('capx:viewchange', event => updateWorkspace(event.detail.view));
  window.addEventListener('capx:traffic', event => renderRecent(event.detail));
  updateWorkspace(curView);
  renderRecent({ recent: newestHttp().slice(0, 6), total: Math.max(HTTP_TOTAL, HIST.length) });

  // Keep unsent work inside this tab/session. Never restore operational controls
  // (proxy, capture, intercept, scripts, or credentials) or dispatch submit events.
  const draftKey = 'capx:workspace-drafts:v1';
  const draftSelector = ['#v_intruder', '#v_turbo', '#v_decoder', '#v_comparer']
    .flatMap(view => ['input[id]', 'select[id]', 'textarea[id]'].map(kind => view + ' ' + kind)).join(',');
  const draftControls = () => [...document.querySelectorAll(draftSelector)]
    .filter(el => !['file', 'password', 'hidden', 'button', 'submit'].includes(el.type));
  function saveDrafts() {
    try {
      const values = {};
      draftControls().forEach(el => { values[el.id] = ['checkbox', 'radio'].includes(el.type) ? el.checked : el.value; });
      sessionStorage.setItem(draftKey, JSON.stringify(values));
    } catch (_) { /* The in-memory workspace still survives navigation and refresh. */ }
  }
  try {
    const values = JSON.parse(sessionStorage.getItem(draftKey) || '{}');
    draftControls().forEach(el => {
      if (!Object.hasOwn(values, el.id)) return;
      if (['checkbox', 'radio'].includes(el.type) && typeof values[el.id] === 'boolean') el.checked = values[el.id];
      else if (typeof values[el.id] === 'string') el.value = values[el.id];
    });
    if (curView === 'intruder') itrSyncPos();
  } catch (_) {}
  document.addEventListener('input', event => { if (event.target.matches(draftSelector)) saveDrafts(); });
  document.addEventListener('change', event => { if (event.target.matches(draftSelector)) saveDrafts(); });
  window.addEventListener('pagehide', saveDrafts);

  // Desktop shell messages are deliberately limited to navigation/read refresh.
  // Validate both the embedding window and its exact origin; no wildcard trust.
  let parentOrigin = '';
  try {
    const supplied = new URLSearchParams(location.search).get('parent_origin');
    parentOrigin = new URL(supplied || document.referrer).origin;
    if (parentOrigin === 'null') parentOrigin = '';
  } catch (_) {}
  const embedded = window.parent !== window && new URLSearchParams(location.search).get('embed') === '1';
  let refreshPending = null;
  function tellParent(type, extra = {}) {
    if (embedded && parentOrigin) window.parent.postMessage({ type, ...extra }, parentOrigin);
  }
  window.addEventListener('message', event => {
    if (!embedded || !parentOrigin || event.source !== window.parent || event.origin !== parentOrigin) return;
    const message = event.data;
    if (!message || typeof message !== 'object') return;
    if (message.type === 'capx:navigate' && typeof message.view === 'string' && navButtons.some(b => b.dataset.v === message.view)) {
      showView(message.view);
    } else if (message.type === 'capx:refresh' && !refreshPending) {
      saveDrafts();
      refreshPending = refreshWorkspaceData().catch(error => {
        document.getElementById('t_state').textContent = '刷新失败：' + (error.message || error);
      }).finally(() => { refreshPending = null; });
    }
  });
  window.addEventListener('capx:viewchange', event => tellParent('capx:viewchange', { view: event.detail.view }));
  tellParent('capx:ready');
})();
