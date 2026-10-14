'use strict';

// Redirect direct WeChatAppEx TCP connections for HTTP(S) to capx's local
// transparent listener. The original HTTP Host / TLS SNI remains untouched,
// so capx can recover the upstream authority and store a normal transaction.
var CAPX_PORT = @@PORT@@;
var CAPX_CONFIG = @@CONFIG@@;
var redirectedCount = 0;
var lastReportedCount = 0;
var diagnostics = {};
function diagnosticOnce(key, message) {
  if (diagnostics[key]) return;
  diagnostics[key] = true;
  send({event:'wxredirect', stage:'diagnostic', msg:message, redirected:redirectedCount});
}
function reportRedirect(transport) {
  redirectedCount++;
  if (redirectedCount < 6 || redirectedCount % 32 === 0) {
    lastReportedCount = redirectedCount;
    send({event:'wxredirect', stage:'redirect', transport:transport, redirected:redirectedCount});
  }
}
setInterval(function () {
  if (lastReportedCount !== redirectedCount) {
    lastReportedCount = redirectedCount;
    send({event:'wxredirect', stage:'redirect', redirected:redirectedCount});
  }
}, 1000);
var AF_INET = 2;
var AF_INET6 = 23;
var SOL_SOCKET = 0xffff;
var SO_TYPE = 0x1008;
var SOCK_STREAM = 1;

function resolveWs2(name) {
  try {
    var module = Process.getModuleByName('ws2_32.dll');
    var address = module.findExportByName(name);
    if (address) return address;
  } catch (e) {}
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      return Module.findGlobalExportByName(name);
    }
  } catch (e) {}
  return null;
}

var getSockOptAddress = resolveWs2('getsockopt');
var getSockOpt = null;
if (getSockOptAddress) {
  try {
    getSockOpt = new NativeFunction(getSockOptAddress, 'int', ['pointer', 'int', 'int', 'pointer', 'pointer']);
  } catch (e) {}
}

function isTCP(socket) {
  if (!getSockOpt) return false;
  try {
    var value = Memory.alloc(4);
    var length = Memory.alloc(4);
    length.writeS32(4);
    if (getSockOpt(socket, SOL_SOCKET, SO_TYPE, value, length) !== 0) { diagnosticOnce('socket-type','Socket type unavailable; connection left unchanged.'); return false; }
    return value.readS32() === SOCK_STREAM;
  } catch (e) {
    diagnosticOnce('socket-type','Socket type query failed; connection left unchanged.');
    return false;
  }
}

function networkPort(sockaddr) {
  return (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
}

function writeNetworkPort(sockaddr, port) {
  sockaddr.add(2).writeU8((port >>> 8) & 0xff);
  sockaddr.add(3).writeU8(port & 0xff);
}

function isLoopback(sockaddr, family) {
  if (family === AF_INET) return sockaddr.add(4).readU8() === 127;
  if (family !== AF_INET6) return false;
  var loopback = true;
  for (var i = 0; i < 15; i++) {
    if (sockaddr.add(8 + i).readU8() !== 0) loopback = false;
  }
  return loopback && sockaddr.add(23).readU8() === 1;
}

function matchesUpstream(sockaddr, port) {
  if (!CAPX_CONFIG.explicit_port || port !== CAPX_CONFIG.upstream_port) return false;
  var parts = CAPX_CONFIG.upstream_host.split('.');
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i++) if (sockaddr.add(4+i).readU8() !== Number(parts[i])) return false;
  return true;
}

function redirectedAddress(socket, sockaddr, length) {
  if (sockaddr.isNull() || length < 4 || length > 128 || !isTCP(socket)) return null;
  var family = sockaddr.readU16();
  var port = networkPort(sockaddr);
  if (family === AF_INET6) {
    // A socket created as AF_INET6 cannot safely be supplied sockaddr_in.
    // The configured bridges are IPv4-only; leave IPv6 entirely unchanged.
    if (length >= 28 && (port === 80 || port === 443 || port === CAPX_CONFIG.upstream_port)) {
      diagnosticOnce('ipv6','IPv6 TCP connection not redirected: this capture bridge accepts IPv4 only; sockaddr family was preserved.');
    }
    return null;
  }
  if (family !== AF_INET || length < 16) return null;
  var targetPort = 0;
  var transport = '';
  if (matchesUpstream(sockaddr, port)) {
    targetPort = CAPX_CONFIG.explicit_port;
    transport = 'explicit-http-proxy';
  } else if ((port === 80 || port === 443) && !isLoopback(sockaddr, family)) {
    targetPort = CAPX_PORT;
    transport = 'direct-tcp';
  }
  if (!targetPort) return null;
  var redirected = Memory.alloc(length);
  for (var i = 0; i < length; i++) redirected.add(i).writeU8(sockaddr.add(i).readU8());
  // Preserve AF_INET and the original sockaddr length. Only the destination
  // changes: original HTTP CONNECT / TLS / HTTP bytes are never rewritten.
  writeNetworkPort(redirected, targetPort);
  redirected.add(4).writeU8(127);
  redirected.add(5).writeU8(0);
  redirected.add(6).writeU8(0);
  redirected.add(7).writeU8(1);
  reportRedirect(transport);
  return redirected;
}

function attachRedirect(name) {
  var address = resolveWs2(name);
  if (!address) return false;
  Interceptor.attach(address, {
    onEnter: function (args) {
      try {
        var redirected = redirectedAddress(args[0], args[1], args[2].toInt32());
        if (!redirected) return;
        this.redirected = redirected;
        args[1] = redirected;
      } catch (e) {}
    }
  });
  return true;
}

function guidEquals(ptr, data1, data2, data3, data4) {
  try {
    if (ptr.readU32() !== data1) return false;
    if (ptr.add(4).readU16() !== data2) return false;
    if (ptr.add(6).readU16() !== data3) return false;
    if (!data4 || data4.length !== 8) return false;
    for (var i = 0; i < 8; i++) {
      if (ptr.add(8 + i).readU8() !== data4[i]) return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

function isConnectExGuid(guid) {
  // WSAID_CONNECTEX {25a207b9-ddf3-4660-8ee9-76e58c74063e}
  // Data4 is 8ee9-76e58c74063e (8 bytes), not a truncated tail starting at 76.
  return guidEquals(guid, 0x25a207b9, 0xddf3, 0x4660, [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e]);
}

var connectExHooked = {};
function hookConnectExPtr(ptr) {
  var key = ptr.toString();
  if (connectExHooked[key]) return;
  connectExHooked[key] = true;
  try {
    Interceptor.attach(ptr, {
      onEnter: function (args) {
        try {
          var redirected = redirectedAddress(args[0], args[1], args[2].toInt32());
          if (!redirected) return;
          this.redirected = redirected;
          args[1] = redirected;
        } catch (e) {}
      }
    });
    hooks.push('ConnectEx');
  } catch (e) {}
}

function attachWSAIoctlConnectEx() {
  var address = resolveWs2('WSAIoctl');
  if (!address) return false;
  var SIO_GET_EXTENSION_FUNCTION_POINTER = 0xC8000006;
  Interceptor.attach(address, {
    onEnter: function (args) {
      this.wantConnectEx = false;
      this.outPtr = null;
      try {
        var code = args[1].toInt32() >>> 0;
        if (code !== SIO_GET_EXTENSION_FUNCTION_POINTER) return;
        if (args[2].isNull() || args[4].isNull()) return;
        if (!isConnectExGuid(args[2])) return;
        this.wantConnectEx = true;
        this.outPtr = args[4];
      } catch (e) {}
    },
    onLeave: function (retval) {
      if (!this.wantConnectEx || this.outPtr.isNull()) return;
      try {
        if (retval.toInt32() !== 0) return;
        var fn = this.outPtr.readPointer();
        if (!fn.isNull()) hookConnectExPtr(fn);
      } catch (e) {}
    }
  });
  return true;
}

function attachMswsockConnectEx() {
  try {
    var module = Process.getModuleByName('mswsock.dll');
    var address = module.findExportByName('ConnectEx');
    if (address) {
      hookConnectExPtr(address);
      return true;
    }
  } catch (e) {}
  return false;
}

var hooks = [];
if (attachRedirect('connect')) hooks.push('connect');
if (attachRedirect('WSAConnect')) hooks.push('WSAConnect');
attachMswsockConnectEx();
attachWSAIoctlConnectEx();
if (!getSockOpt || hooks.length === 0) {
  send({event:'wxredirect',stage:'error',fatal:true,msg:'TCP redirect initialization failed: getsockopt or connect hook is unavailable.'});
  throw new Error('TCP redirect initialization failed');
}
send({event:'wxredirect',stage:'ready',hooks:hooks,port:CAPX_PORT,explicit_port:CAPX_CONFIG.explicit_port,redirected:0,msg:'Hooks ready for new IPv4 TCP connections only; existing sockets are unchanged.'});
