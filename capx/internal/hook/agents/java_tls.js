'use strict';
// capx Java/Android TLS plaintext agent. Targets the JVM/ART TLS stack used by
// Android apps and desktop Java: Conscrypt (the default provider on modern
// Android) and the generic javax.net.ssl SSLSocket streams. It captures the
// cleartext at the SSLOutputStream.write / SSLInputStream.read boundary — i.e.
// before encryption / after decryption — defeating certificate pinning.
//
// Requires a Frida build with a Java bridge (Android, or desktop with a JVM).
// On a process without Java it no-ops gracefully.

function bytesToArrayBuffer(jbytes, off, len) {
  // Copy a Java byte[] slice into a JS ArrayBuffer for send().
  var out = new Uint8Array(len);
  for (var i = 0; i < len; i++) out[i] = jbytes[off + i] & 0xff;
  return out.buffer;
}

function emit(fn, dir, jbytes, off, len) {
  if (len <= 0) return;
  try {
    send({ event: 'tls', func: fn, dir: dir, len: len, peer: '' }, bytesToArrayBuffer(jbytes, off, len));
  } catch (e) {}
}

function hookConscrypt() {
  var names = [
    'com.android.org.conscrypt.ConscryptEngineSocket$SSLOutputStream',
    'org.conscrypt.ConscryptEngineSocket$SSLOutputStream',
  ];
  names.forEach(function (cn) {
    try {
      var Out = Java.use(cn);
      Out.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        emit('Conscrypt.write', 'send', b, off, len);
        return this.write(b, off, len);
      };
    } catch (e) {}
  });
  var inNames = [
    'com.android.org.conscrypt.ConscryptEngineSocket$SSLInputStream',
    'org.conscrypt.ConscryptEngineSocket$SSLInputStream',
  ];
  inNames.forEach(function (cn) {
    try {
      var In = Java.use(cn);
      In.read.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        var n = this.read(b, off, len);
        if (n > 0) emit('Conscrypt.read', 'recv', b, off, n);
        return n;
      };
    } catch (e) {}
  });
}

// Generic OkHttp/javax fallback: hook the application-facing buffer copy.
function hookOkio() {
  try {
    var Buffer = Java.use('okio.Buffer');
    Buffer.writeUtf8.overload('java.lang.String').implementation = function (s) {
      try {
        var bytes = Java.use('java.lang.String').$new(s).getBytes();
        emit('okio.writeUtf8', 'send', bytes, 0, bytes.length);
      } catch (e) {}
      return this.writeUtf8(s);
    };
  } catch (e) {}
}

if (typeof Java !== 'undefined' && Java.available) {
  Java.perform(function () {
    hookConscrypt();
    hookOkio();
    send({ event: 'ready', hooked: ['conscrypt', 'okio'] });
  });
} else {
  send({ event: 'error', msg: 'no Java runtime in target (use the native tls agent instead)' });
}
