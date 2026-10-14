// Deterministic Frida API fixture. No target process or network is accessed.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
class Pointer {
  constructor(buffer, offset=0) { this.buffer=buffer; this.offset=offset; }
  add(n){return new Pointer(this.buffer,this.offset+n)}
  isNull(){return false}
  readU8(){return this.buffer.readUInt8(this.offset)}
  writeU8(n){this.buffer.writeUInt8(n,this.offset)}
  readU16(){return this.buffer.readUInt16LE(this.offset)}
  writeU16(n){this.buffer.writeUInt16LE(n,this.offset)}
  readU32(){return this.buffer.readUInt32LE(this.offset)}
  readS32(){return this.buffer.readInt32LE(this.offset)}
  writeS32(n){this.buffer.writeInt32LE(n,this.offset)}
}
const messages=[], interceptors={}, lookups=[];
let socketType=1, socketError=0;
const context={
  send:m=>messages.push(JSON.parse(JSON.stringify(m))),
  setInterval:()=>0,
  Process:{getModuleByName(name){return {findExportByName(symbol){lookups.push(symbol);return name==='mswsock.dll'?null:{name:symbol,toString(){return symbol}}}}}},
  Module:{},
  Memory:{alloc:n=>new Pointer(Buffer.alloc(n))},
  NativeFunction:function(){return function(socket,level,opt,value,len){value.writeS32(socketType);return socketError}},
  Interceptor:{attach(address,callbacks){interceptors[address.name]=callbacks}},
};
vm.createContext(context);vm.runInContext(source,context);
assert(messages.some(m=>m.stage==='ready' && m.hooks.includes('connect')));
assert.equal(context.redirectedCount,0,'initialization must not touch existing sockets');
assert(!lookups.some(s=>/closesocket|shutdown|certificate|verify|ssl/i.test(s)));
function address(family,port,ip){
  const buf=Buffer.alloc(family===23?28:16,0xcd);const p=new Pointer(buf);
  p.writeU16(family);p.add(2).writeU8(port>>>8);p.add(3).writeU8(port&255);
  if(family===2) ip.split('.').forEach((n,i)=>p.add(4+i).writeU8(Number(n)));
  return p;
}
const port=p=>(p.add(2).readU8()<<8)|p.add(3).readU8();
const original=address(2,443,'203.0.113.10'), bytes=Buffer.from(original.buffer);
const direct=context.redirectedAddress({},original,16);
assert.equal(direct.readU16(),2);assert.equal(port(direct),18443);
assert.deepEqual([...direct.buffer.subarray(4,8)],[127,0,0,1]);
assert.deepEqual(original.buffer,bytes,'original sockaddr was modified');
assert.deepEqual(direct.buffer.subarray(8),bytes.subarray(8),'sockaddr padding/length changed');
const upstream=address(2,7897,'127.0.0.1');
const explicit=context.redirectedAddress({},upstream,16);
assert.equal(port(explicit),18444,'original HTTP proxy must use explicit listener, not transparent');
assert.equal(port(upstream),7897);
assert.equal(context.redirectedAddress({},address(2,7897,'127.0.0.2'),16),null,'other local proxy was captured');
assert.equal(context.redirectedAddress({},address(2,7898,'127.0.0.1'),16),null);
assert.equal(context.redirectedAddress({},address(2,443,'127.0.0.1'),16),null);
assert.equal(context.redirectedAddress({},address(2,8443,'203.0.113.10'),16),null);
socketType=2;assert.equal(context.redirectedAddress({},original,16),null,'UDP was rewritten');socketType=1;
socketError=-1;assert.equal(context.redirectedAddress({},original,16),null,'unknown socket type was rewritten');socketError=0;
const ipv6=address(23,443),v6bytes=Buffer.from(ipv6.buffer);
assert.equal(context.redirectedAddress({},ipv6,28),null);
assert.equal(context.redirectedAddress({},ipv6,28),null);
assert.deepEqual(ipv6.buffer,v6bytes,'IPv6 sockaddr was coerced to IPv4');
assert.equal(messages.filter(m=>m.stage==='diagnostic' && /IPv6/.test(m.msg)).length,1);
assert.equal(context.redirectedAddress({},original,8),null,'short sockaddr was rewritten');
const args=[{},upstream,{toInt32:()=>16}];
const invocation={};interceptors.connect.onEnter.call(invocation,args);
assert.equal(port(args[1]),18444);assert.equal(args[2].toInt32(),16);
assert.equal(invocation.redirected,args[1],'redirect address lifetime was not retained');
assert.equal(context.redirectedCount,3);
assert(messages.some(m=>m.stage==='redirect' && m.transport==='explicit-http-proxy'));
console.log('PASS redirect mock: direct, explicit HTTP proxy, TCP guard, IPv6 rejection, existing sockets unchanged');
