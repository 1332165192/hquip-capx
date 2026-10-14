/* Authenticated desktop transport. The token stays in the Wails backend. */
(() => {
  'use strict';
  const query=new URLSearchParams(location.search);
  if(window.parent===window||query.get('embed')!=='1'||query.get('desktop_bridge')!=='1')return;
  let parentOrigin;
  try{parentOrigin=new URL(query.get('parent_origin')).origin;}catch(_){return;}
  if(!parentOrigin||parentOrigin==='null')return;
  const nativeFetch=window.fetch.bind(window), NativeEventSource=window.EventSource;
  const pending=new Map(),streams=new Set(),prefix=crypto.randomUUID();let sequence=0;
  window.addEventListener('message',event=>{
    if(event.source!==window.parent||event.origin!==parentOrigin)return;
    const data=event.data;if(!data||typeof data!=='object')return;
    if(data.type==='capx:api-response'){
      const entry=pending.get(data.id);if(!entry)return;pending.delete(data.id);clearTimeout(entry.timer);entry.signal?.removeEventListener('abort',entry.abort);
      if(data.error){entry.reject(new Error(data.error));return;}
      try{const result=data.result;const bytes=Uint8Array.from(atob(result.data||''),ch=>ch.charCodeAt(0));entry.resolve(new Response([204,205,304].includes(result.status)?null:bytes,{status:result.status,headers:{...result.headers,'Content-Type':result.content_type||'application/json'}}));}
      catch(error){entry.reject(error);}
    }else if(data.type==='capx:stream-state'){streams.forEach(stream=>stream.state(data.state));}
    else if(data.type==='capx:stream-event'&&typeof data.event==='string'&&typeof data.data==='string'){streams.forEach(stream=>stream.event(data.event,data.data));}
  });
  window.fetch=async(input,options)=>{
    const request=input instanceof Request?new Request(input.clone(),options):new Request(new URL(String(input),location.href),options);
    const url=new URL(request.url);
    if(url.origin!==location.origin||(!url.pathname.startsWith('/api/')&&url.pathname!=='/health'))return nativeFetch(input,options);
    if(request.signal.aborted)throw new DOMException('Request aborted','AbortError');
    const body=['GET','HEAD'].includes(request.method)?'':await request.text();
    return new Promise((resolve,reject)=>{
      const id=prefix+'-'+(++sequence);const signal=request.signal;
      const abort=()=>{const entry=pending.get(id);if(entry){clearTimeout(entry.timer);pending.delete(id);signal.removeEventListener('abort',abort);reject(new DOMException('Request aborted','AbortError'));}};
      const timer=setTimeout(()=>{pending.delete(id);signal.removeEventListener('abort',abort);reject(new Error('桌面请求超时，请刷新连接状态'));},115000);
      pending.set(id,{resolve,reject,timer,signal,abort});signal.addEventListener('abort',abort,{once:true});
      window.parent.postMessage({type:'capx:api-request',id,path:url.pathname+url.search,method:request.method,body},parentOrigin);
    });
  };
  class DesktopStream extends EventTarget {
    static CONNECTING=0;static OPEN=1;static CLOSED=2;
    constructor(url){super();this.url=new URL(url,location.href).href;this.readyState=0;this.withCredentials=false;streams.add(this);window.parent.postMessage({type:'capx:stream-request'},parentOrigin);}
    state(value){if(this.readyState===2)return;this.readyState=value==='up'?1:0;const type=value==='up'?'open':'error';const event=new Event(type);this.dispatchEvent(event);this['on'+type]?.(event);}
    event(type,data){if(this.readyState===2)return;const event=new MessageEvent(type,{data});this.dispatchEvent(event);if(type==='message')this.onmessage?.(event);}
    close(){this.readyState=2;streams.delete(this);}
  }
  window.EventSource=function(url,options){const parsed=new URL(url,location.href);return parsed.origin===location.origin&&parsed.pathname==='/api/stream'?new DesktopStream(url):new NativeEventSource(url,options);};
  for(const name of ['CONNECTING','OPEN','CLOSED'])window.EventSource[name]=DesktopStream[name];
})();
