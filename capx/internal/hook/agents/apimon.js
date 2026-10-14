'use strict';
// capx generic function-hook ("API monitor") agent. Unlike the TLS agent it
// hooks an arbitrary set of exported functions named in CAPX_HOOK_TARGETS (a
// comma-separated env list, e.g. "connect,send,recv,CreateFileW") and reports
// each call's argument pointers and return value. It is a building block for
// "watch what this process calls" without writing a bespoke script.
//
// Targets default to a handful of common network/file syscalls when the env is
// empty. Each call is shipped as a tls-style event so it shows in the hook
// event stream (func = the hooked name, data = "args=...; ret=...").

function resolveExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      var g = Module.findGlobalExportByName(name);
      if (g) return g;
    }
  } catch (e) {}
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    try {
      var a = mods[i].findExportByName(name);
      if (a) return a;
    } catch (e) {}
  }
  return null;
}

function targets() {
  var env = '';
  try {
    if (typeof Process.getEnvironmentVariable === 'function') {
      env = Process.getEnvironmentVariable('CAPX_HOOK_TARGETS') || '';
    }
  } catch (e) {}
  if (!env) {
    return ['connect', 'send', 'recv', 'WSASend', 'WSARecv', 'CreateFileW', 'open'];
  }
  return env.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
}

var hooked = [];
targets().forEach(function (name) {
  var addr = resolveExport(name);
  if (!addr) return;
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.a = [];
        for (var i = 0; i < 4; i++) {
          try { this.a.push(args[i].toString()); } catch (e) { this.a.push('?'); }
        }
      },
      onLeave: function (retval) {
        var line = 'args=[' + this.a.join(', ') + '] ret=' + retval.toString();
        send({ event: 'tls', func: name, dir: 'call', len: line.length, peer: '' },
             new TextEncoder().encode(line).buffer);
      },
    });
    hooked.push(name);
  } catch (e) {}
});

send({ event: 'ready', hooked: hooked });
