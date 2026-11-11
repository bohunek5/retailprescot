'use strict';
const CONFIG = {"version":1,"build":"m00e4cfd6eb5fce2d17fc7993","salt":"3YAnYQcrXyhBXPuRgSaM54MYW4kcOCO8QsaFF3he4FM=","iterations":600000,"manifest":"payload/6f125ce3e90d0b509c1eccad03d4543a7aed124d393196bab6e124f3fe9a3922.bin","scope":"/retailprescot/mailing-preview/01/"};
const PUBLIC = new Set(['gate.js','gate.css','preview-config.json','sw.js','robots.txt','.nojekyll','gate-logo.svg','gate-manrope.woff2']);
const BASE = new URL(CONFIG.scope, self.location.origin);
const encoder = new TextEncoder();
const authorized = new Set();
let context = null, recovering = null, lockEpoch = 0, explicitlyLocked = false;
const decodeKey = raw => Uint8Array.from(atob(raw), c => c.charCodeAt(0));
const scopePath = pathname => pathname.startsWith(BASE.pathname);
const noStore = {'Cache-Control':'no-store, private','X-Robots-Tag':'noindex, nofollow, noarchive','X-Content-Type-Options':'nosniff'};

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

async function decrypt(file, key, epoch = lockEpoch, aadBuild = CONFIG.build, timeoutMs = 15000) {
  // Retry only transport failures. Authentication/decryption runs once, below.
  const delays = [250,750], transient = new Set([408,500,502,503,504]);
  let sealed;
  for (let attempt = 0; attempt <= delays.length; attempt += 1) {
    if (epoch !== lockEpoch) throw new Error('locked');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(),timeoutMs);
    let retryable = true;
    try {
      const response = await fetch(new URL(file, BASE), {cache:'no-store',credentials:'omit',signal:controller.signal});
      if (response.ok) sealed = new Uint8Array(await response.arrayBuffer());
      else {
        retryable = transient.has(response.status);
        await response.body?.cancel().catch(() => {});
      }
    } catch { /* Network rejection, body interruption or timeout. */ }
    finally { clearTimeout(timer); }
    if (epoch !== lockEpoch) throw new Error('locked');
    if (sealed) break;
    if (!retryable || attempt === delays.length) throw new Error('network');
    await new Promise(resolve => setTimeout(resolve,delays[attempt]));
  }
  const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:sealed.slice(0,12),additionalData:encoder.encode(aadBuild)}, key, sealed.slice(12));
  if (epoch !== lockEpoch) throw new Error('locked');
  return plain;
}
async function openKey(raw) {
  const epoch = lockEpoch;
  let key;
  try { key = await crypto.subtle.importKey('raw', decodeKey(raw), {name:'AES-GCM'}, false, ['decrypt']); }
  catch { throw new Error('password'); }
  let plain;
  try { plain = await decrypt(CONFIG.manifest, key, epoch); }
  catch (error) { throw new Error(error.message === 'network' ? 'network' : 'password'); }
  const manifest = JSON.parse(new TextDecoder().decode(plain));
  if (manifest.build !== CONFIG.build || !manifest.files?.['index.html']) throw new Error('password');
  return {key,manifest,raw,buffers:new Map(),pending:new Map(),memoryBytes:0};
}
async function readFile(entry, active) {
  if (active.buffers.has(entry.file)) {
    const existing = active.buffers.get(entry.file);
    active.buffers.delete(entry.file);
    active.buffers.set(entry.file,existing);
    return existing;
  }
  if (active.pending.has(entry.file)) return active.pending.get(entry.file);
  const task = decrypt(entry.file,active.key,lockEpoch,entry.aad || CONFIG.build,Math.min(300000,Math.max(30000,Math.ceil(entry.size / 131072) * 1000))).then(plain => {
    const limit = 48 * 1024 * 1024;
    if (plain.byteLength <= limit) {
      while (active.memoryBytes + plain.byteLength > limit && active.buffers.size) {
        const oldest = active.buffers.keys().next().value;
        active.memoryBytes -= active.buffers.get(oldest).byteLength;
        active.buffers.delete(oldest);
      }
      active.buffers.set(entry.file,plain);
      active.memoryBytes += plain.byteLength;
    }
    return plain;
  }).finally(() => active.pending.delete(entry.file));
  active.pending.set(entry.file,task);
  return task;
}
async function controlledWindows() {
  return (await self.clients.matchAll({type:'window',includeUncontrolled:true})).filter(client => {
    try { const u = new URL(client.url); return u.origin === BASE.origin && scopePath(u.pathname); } catch { return false; }
  });
}
function askKey(client) {
  return new Promise(resolve => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => { channel.port1.close(); resolve(null); }, 1200);
    channel.port1.onmessage = event => { clearTimeout(timer); channel.port1.close(); resolve(event.data?.key || null); };
    try { client.postMessage({type:'RETAIL_REQUEST_KEY',build:CONFIG.build}, [channel.port2]); }
    catch { clearTimeout(timer); resolve(null); }
  });
}
async function recover() {
  const epoch = lockEpoch;
  const windows = await controlledWindows();
  if (context && windows.some(client => authorized.has(client.id))) return context;
  context = null;
  authorized.clear();
  const candidates = await Promise.all(windows.map(async client => ({client,raw:await askKey(client)})));
  for (const {client,raw} of candidates) {
    if (!raw) continue;
    try {
      const opened = await openKey(raw);
      if (epoch !== lockEpoch || explicitlyLocked) return null;
      context = opened;
      authorized.add(client.id);
      return context;
    } catch {}
  }
  return null;
}
async function getContext(event) {
  if (explicitlyLocked) return null;
  // A terminated worker recovers only from a live tab holding the session key.
  if (context && ((event.clientId && authorized.has(event.clientId)) || (event.replacesClientId && authorized.has(event.replacesClientId)))) {
    if (event.resultingClientId) authorized.add(event.resultingClientId);
    return context;
  }
  if (!recovering) recovering = recover().finally(() => { recovering = null; });
  const found = await recovering;
  if (found) {
    if (event.clientId) authorized.add(event.clientId);
    if (event.resultingClientId) authorized.add(event.resultingClientId);
  }
  return found;
}
self.addEventListener('message', event => {
  const data = event.data || {};
  if (data.type === 'RETAIL_SESSION' && data.build === CONFIG.build && context && authorized.has(event.source?.id)) {
    event.ports[0]?.postMessage({key:context.raw});
  }
  if (data.type === 'RETAIL_UNLOCK') event.waitUntil((async () => {
    try {
      if (data.build !== CONFIG.build) throw new Error('updated');
      context = await openKey(data.key);
      explicitlyLocked = false;
      if (event.source?.id) authorized.add(event.source.id);
      event.ports[0]?.postMessage({ok:true});
    } catch (error) { event.ports[0]?.postMessage({ok:false,reason:error.message}); }
  })());
  if (data.type === 'RETAIL_LOCK') event.waitUntil((async () => {
    explicitlyLocked = true;
    lockEpoch += 1;
    context = null;
    authorized.clear();
    for (const client of await controlledWindows()) client.postMessage({type:'RETAIL_LOCKED'});
    event.ports[0]?.postMessage({ok:true});
  })());
});
async function gate() {
  const response = await fetch(new URL('index.html', BASE), {cache:'no-store'});
  return new Response(await response.arrayBuffer(), {status:200,headers:{...noStore,'Content-Type':'text/html; charset=utf-8'}});
}
async function serve(event, path) {
  const active = await getContext(event);
  if (!active) {
    if (event.request.mode === 'navigate') return gate();
    return new Response('Preview locked', {status:401,headers:{...noStore,'Content-Type':'text/plain; charset=utf-8'}});
  }
  // An iframe often navigates to shows/strips/model-smd-2835/?family=delux.
  // Resolve its own directory index instead of returning the retail shell.
  const normalized = !path || path === 'index.html' || path === '404.html' ? 'index.html' : path.endsWith('/') ? path + 'index.html' : path;
  const entry = active.manifest.files[normalized];
  if (!entry) return new Response('Not found', {status:404,headers:noStore});
  try {
    const plain = await readFile(entry, active);
    if (explicitlyLocked || active !== context) return new Response('Preview locked',{status:401,headers:noStore});
    const headers = {...noStore,'Content-Type':entry.mime,'Accept-Ranges':'bytes'};
    const range = event.request.headers.get('range');
    if (range) {
      const match = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (!match || (!match[1] && !match[2])) return new Response(null,{status:416,headers:{...headers,'Content-Range':`bytes */${plain.byteLength}`}});
      let start = match[1] ? Number(match[1]) : Math.max(0,plain.byteLength - Number(match[2]));
      let end = match[1] && match[2] ? Number(match[2]) : plain.byteLength - 1;
      end = Math.min(end,plain.byteLength - 1);
      if (start > end || start >= plain.byteLength) return new Response(null,{status:416,headers:{...headers,'Content-Range':`bytes */${plain.byteLength}`}});
      const slice = plain.slice(start,end+1);
      return new Response(event.request.method === 'HEAD' ? null : slice,{status:206,headers:{...headers,'Content-Range':`bytes ${start}-${end}/${plain.byteLength}`,'Content-Length':String(slice.byteLength)}});
    }
    return new Response(event.request.method === 'HEAD' ? null : plain,{headers:{...headers,'Content-Length':String(plain.byteLength)}});
  } catch {
    if (explicitlyLocked || active !== context) return new Response('Preview locked',{status:401,headers:noStore});
    if (event.request.mode === 'navigate') return gate();
    if (event.clientId) (await self.clients.get(event.clientId))?.postMessage({type:'RETAIL_REFRESH_BUILD'});
    return new Response('Unable to load preview file. Refresh the page.',{status:503,headers:noStore});
  }
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== BASE.origin || !scopePath(url.pathname) || !['GET','HEAD'].includes(event.request.method)) return;
  let path;
  try { path = decodeURIComponent(url.pathname.slice(BASE.pathname.length)); } catch { return; }
  if (PUBLIC.has(path) || path.startsWith('payload/')) return;
  event.respondWith(serve(event,path));
});
