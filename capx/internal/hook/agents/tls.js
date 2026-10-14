'use strict';
// capx M5 native TLS plaintext agent. It captures application data *before* it
// is encrypted (and right after it is decrypted), so it works even against
// certificate pinning. It covers the common native TLS stacks:
//
//   - OpenSSL / BoringSSL : SSL_write / SSL_read (+ _ex variants)
//   - NSS (Firefox/Thunderbird) : PR_Write / PR_Read
//   - GnuTLS : gnutls_record_send / gnutls_record_recv
//   - Windows SChannel : EncryptMessage / DecryptMessage (secur32/sspicli)
//
// Each observation is shipped to the host via send({...}, arrayBuffer). When a
// socket fd is recoverable we also resolve the remote peer ip:port, which lets
// capx correlate the plaintext to the matching L3/L4 flow and HTTP transaction.
//
// Uses the Frida >= 17 module API (instance methods on Module objects); the
// older static Module.findExportByName(null, ...) was removed in Frida 17.

function resolveExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      var g = Module.findGlobalExportByName(name);
      if (g) return g;
    }
  } catch (e) {}
  var modules = Process.enumerateModules();
  for (var i = 0; i < modules.length; i++) {
    try {
      var addr = modules[i].findExportByName(name);
      if (addr) return addr;
    } catch (e) {}
  }
  return null;
}

// peerFromFd best-effort resolves "ip:port" for a socket fd; "" when unknown.
function peerFromFd(fd) {
  if (fd === null || fd < 0) return '';
  try {
    var a = Socket.peerAddress(fd);
    if (a && a.ip !== undefined) return a.ip + ':' + a.port;
  } catch (e) {}
  return '';
}

function emit(fn, dir, buf, len, peer) {
  if (len <= 0 || buf.isNull()) return;
  try {
    var data = buf.readByteArray(len);
    send({ event: 'tls', func: fn, dir: dir, len: len, peer: peer || '' }, data);
  } catch (e) {}
}

var hooked = [];

// ---- OpenSSL / BoringSSL ----------------------------------------------------

// SSL_get_fd(ssl) -> int; lets us resolve the remote endpoint for correlation.
var sslGetFd = null;
(function () {
  var a = resolveExport('SSL_get_fd');
  if (a) {
    try { sslGetFd = new NativeFunction(a, 'int', ['pointer']); } catch (e) {}
  }
})();

function sslPeer(ssl) {
  if (!sslGetFd || ssl.isNull()) return '';
  try { return peerFromFd(sslGetFd(ssl)); } catch (e) { return ''; }
}

function hookSSLWrite(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.ssl = args[0];
      this.buf = args[1];
      this.num = args[2].toInt32();
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) emit(name, 'send', this.buf, Math.min(n, this.num), sslPeer(this.ssl));
    },
  });
  return true;
}

function hookSSLRead(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.ssl = args[0];
      this.buf = args[1];
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) emit(name, 'recv', this.buf, n, sslPeer(this.ssl));
    },
  });
  return true;
}

function hookSSLWriteEx(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.ssl = args[0];
      this.buf = args[1];
      this.num = args[2].toInt32();
      this.pw = args[3];
    },
    onLeave: function (retval) {
      if (retval.toInt32() !== 1 || this.pw.isNull()) return;
      var written = this.pw.readULong().toNumber();
      if (written > 0) emit(name, 'send', this.buf, Math.min(written, this.num), sslPeer(this.ssl));
    },
  });
  return true;
}

function hookSSLReadEx(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.ssl = args[0];
      this.buf = args[1];
      this.pr = args[3];
    },
    onLeave: function (retval) {
      if (retval.toInt32() !== 1 || this.pr.isNull()) return;
      var got = this.pr.readULong().toNumber();
      if (got > 0) emit(name, 'recv', this.buf, got, sslPeer(this.ssl));
    },
  });
  return true;
}

// ---- NSS (Firefox) ----------------------------------------------------------
// PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount)
// PRInt32 PR_Read (PRFileDesc *fd, void *buf, PRInt32 amount)
function hookPRWrite(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.buf = args[1]; this.num = args[2].toInt32(); },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) emit(name, 'send', this.buf, Math.min(n, this.num), '');
    },
  });
  return true;
}

function hookPRRead(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.buf = args[1]; },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) emit(name, 'recv', this.buf, n, '');
    },
  });
  return true;
}

// ---- GnuTLS -----------------------------------------------------------------
// ssize_t gnutls_record_send(gnutls_session_t, const void *data, size_t size)
// ssize_t gnutls_record_recv(gnutls_session_t, void *data, size_t size)
function hookGnuSend(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.buf = args[1]; this.num = args[2].toInt32(); },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) emit(name, 'send', this.buf, Math.min(n, this.num), '');
    },
  });
  return true;
}

function hookGnuRecv(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.buf = args[1]; },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) emit(name, 'recv', this.buf, n, '');
    },
  });
  return true;
}

// ---- Windows SChannel -------------------------------------------------------
// EncryptMessage(ctx, fQOP, PSecBufferDesc pMessage, MessageSeqNo): plaintext is
// in the SECBUFFER_DATA buffer before the call. DecryptMessage(...): the
// SECBUFFER_DATA buffer holds the decrypted plaintext after the call.
var SECBUFFER_DATA = 1;
function eachDataBuffer(pMessage, fn) {
  if (pMessage.isNull()) return;
  var ps = Process.pointerSize;
  // SecBufferDesc { ULONG ulVersion; ULONG cBuffers; PSecBuffer pBuffers; }
  var cBuffers = pMessage.add(4).readU32();
  var pBuffers = pMessage.add(ps === 8 ? 8 : 8).readPointer();
  // SecBuffer { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; } (16 bytes on x64)
  var stride = ps === 8 ? 16 : 12;
  for (var i = 0; i < cBuffers && i < 16; i++) {
    var b = pBuffers.add(i * stride);
    var cb = b.readU32();
    var type = b.add(4).readU32();
    var pv = b.add(8).readPointer();
    if (type === SECBUFFER_DATA && cb > 0 && !pv.isNull()) fn(pv, cb);
  }
}

function hookEncryptMessage(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try { eachDataBuffer(args[2], function (pv, cb) { emit(name, 'send', pv, cb, ''); }); } catch (e) {}
    },
  });
  return true;
}

function hookDecryptMessage(name) {
  var addr = resolveExport(name);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.msg = args[1]; },
    onLeave: function () {
      try { eachDataBuffer(this.msg, function (pv, cb) { emit(name, 'recv', pv, cb, ''); }); } catch (e) {}
    },
  });
  return true;
}

// ---- OpenSSL key-log callback ----------------------------------------------
// SSL_CTX_set_keylog_callback(ctx, cb) makes OpenSSL hand us each NSS key-log
// line (CLIENT_RANDOM / TLS1.3 traffic secrets). Dumping these lets capx (and
// Wireshark) decrypt the *captured* TLS without being an inline proxy — and it
// works under certificate pinning. We install our own callback on every new
// SSL_CTX via SSL_CTX_new's return value.
function installKeylog() {
  var setCb = resolveExport('SSL_CTX_set_keylog_callback');
  var ctxNew = resolveExport('SSL_CTX_new');
  if (!setCb || !ctxNew) return false;
  var setKeylog = new NativeFunction(setCb, 'void', ['pointer', 'pointer']);
  // void cb(const SSL* ssl, const char* line)
  var cb = new NativeCallback(function (ssl, line) {
    try {
      var s = line.readUtf8String();
      if (s) send({ event: 'keylog', msg: s });
    } catch (e) {}
  }, 'void', ['pointer', 'pointer']);
  // Keep a global reference so the callback isn't GC'd.
  global.__capx_keylog_cb = cb;
  Interceptor.attach(ctxNew, {
    onLeave: function (retval) {
      if (!retval.isNull()) {
        try { setKeylog(retval, cb); } catch (e) {}
      }
    },
  });
  return true;
}

[
  ['SSL_write', hookSSLWrite],
  ['SSL_read', hookSSLRead],
  ['SSL_write_ex', hookSSLWriteEx],
  ['SSL_read_ex', hookSSLReadEx],
  ['PR_Write', hookPRWrite],
  ['PR_Read', hookPRRead],
  ['gnutls_record_send', hookGnuSend],
  ['gnutls_record_recv', hookGnuRecv],
  ['EncryptMessage', hookEncryptMessage],
  ['DecryptMessage', hookDecryptMessage],
].forEach(function (h) {
  try {
    if (h[1](h[0])) hooked.push(h[0]);
  } catch (e) {}
});

try {
  if (installKeylog()) hooked.push('SSL_CTX_keylog');
} catch (e) {}

send({ event: 'ready', hooked: hooked });
