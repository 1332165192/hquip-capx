(function () {
  var ATTR = 'data-capx-auto-id';
  var seq = Number(globalThis.__capxAutoSeq || 0);
  var all = [];
  var seen = new Set();

  function walk(root) {
    if (!root || !root.querySelectorAll) return;
    var nodes = root.querySelectorAll('*');
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!seen.has(node)) {
        seen.add(node);
        all.push(node);
      }
      if (node.shadowRoot) walk(node.shadowRoot);
    }
  }

  function selectorFor(el) {
    if (el.id) return '#' + CSS.escape(el.id);
    var testID = el.getAttribute('data-testid') || el.getAttribute('data-test');
    if (testID) return '[data-testid="' + String(testID).replace(/"/g, '\\"') + '"]';
    var parts = [];
    var cur = el;
    while (cur && cur.nodeType === 1 && parts.length < 6) {
      var part = cur.tagName.toLowerCase();
      var parent = cur.parentElement;
      if (parent) {
        var same = Array.prototype.filter.call(parent.children, function (x) { return x.tagName === cur.tagName; });
        if (same.length > 1) part += ':nth-of-type(' + (same.indexOf(cur) + 1) + ')';
      }
      parts.unshift(part);
      if (!parent || cur.getRootNode() instanceof ShadowRoot) break;
      cur = parent;
    }
    return parts.join(' > ');
  }

  function roleOf(el) {
    var role = el.getAttribute('role');
    if (role) return role;
    var tag = el.tagName.toLowerCase();
    if (tag === 'button') return 'button';
    if (tag === 'a') return 'link';
    if (tag === 'input' || tag === 'textarea') return 'textbox';
    if (tag === 'select') return 'combobox';
    return '';
  }

  function actionable(el, style) {
    var tag = el.tagName.toLowerCase();
    var role = roleOf(el);
    if (['button', 'a', 'input', 'textarea', 'select', 'option', 'label', 'wx-button'].indexOf(tag) >= 0) return true;
    if (['button', 'link', 'tab', 'checkbox', 'radio', 'textbox', 'combobox', 'menuitem', 'switch'].indexOf(role) >= 0) return true;
    if (el.hasAttribute('onclick') || el.hasAttribute('bindtap') || el.hasAttribute('catchtap')) return true;
    if (el.tabIndex >= 0 || style.cursor === 'pointer') return true;
    return false;
  }

  walk(document);
  var elements = [];
  for (var i = 0; i < all.length && elements.length < 300; i++) {
    var el = all[i];
    var style = getComputedStyle(el);
    var rect = el.getBoundingClientRect();
    var visible = style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity || 1) > 0 && rect.width > 1 && rect.height > 1;
    if (!visible || !actionable(el, style)) continue;
    var id = el.getAttribute(ATTR);
    if (!id) {
      seq++;
      id = 'wx-' + seq;
      el.setAttribute(ATTR, id);
    }
    var tag = el.tagName.toLowerCase();
    var text = String(el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder') || '').replace(/\s+/g, ' ').trim().slice(0, 240);
    elements.push({
      id: id,
      tag: tag,
      role: roleOf(el),
      type: String(el.getAttribute('type') || ''),
      name: String(el.getAttribute('name') || ''),
      text: text,
      placeholder: String(el.getAttribute('placeholder') || ''),
      selector: selectorFor(el),
      disabled: Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true'),
      x: rect.x,
      y: rect.y,
      width: rect.width,
      height: rect.height
    });
  }
  globalThis.__capxAutoSeq = seq;
  var pages = typeof getCurrentPages === 'function' ? getCurrentPages() : [];
  var page = pages && pages.length ? pages[pages.length - 1] : null;
  return {
    route: String((page && (page.route || page.__route__)) || location.pathname || ''),
    url: String(location.href || ''),
    title: String(document.title || ''),
    viewport: {width: innerWidth, height: innerHeight, scrollX: scrollX, scrollY: scrollY},
    elements: elements
  };
})()
