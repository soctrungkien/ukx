// ukx.js
// Browser: AES-GCM + PBKDF2 + HMAC + 20 reversible layers
const DEFAULT_ITER = 200000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_MATERIAL_BYTES = 64; // 32B AES + 32B HMAC
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------- utils ----------
function rndBytes(n){ const b=new Uint8Array(n); crypto.getRandomValues(b); return b; }
function bufToB64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBuf(str){ return Uint8Array.from(atob(str), c=>c.charCodeAt(0)); }
function strToHex(s){ return Array.from(s).map(ch=>ch.charCodeAt(0).toString(16).padStart(2,'0')).join(''); }
function hexToStr(hex){
  if (hex.length % 2) throw new Error('Invalid hex');
  const out=[];
  for(let i=0;i<hex.length;i+=2) out.push(String.fromCharCode(parseInt(hex.slice(i,i+2),16)));
  return out.join('');
}
function rot13(s) {
  return s.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
  });
}

// ---------- derive AES + HMAC keys ----------
async function deriveKeys(password, salt, iterations){
  const pwKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, pwKey, KEY_MATERIAL_BYTES*8);
  const arr = new Uint8Array(bits);
  const aesRaw = arr.slice(0,32);
  const hmacRaw = arr.slice(32,64);
  const aesKey = await crypto.subtle.importKey('raw', aesRaw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  return { aesKey, hmacRaw, aesRaw };
}
async function importHmac(raw){ return crypto.subtle.importKey('raw', raw, {name:'HMAC', hash:'SHA-256'}, false, ['sign','verify']); }
async function hmacSign(rawKey, dataUint8){
  const k = await importHmac(rawKey);
  const sig = await crypto.subtle.sign('HMAC', k, dataUint8);
  return new Uint8Array(sig);
}

// ---------- PRNG from seed (for noise positions) ----------
function xs128plus(seed16){
  if (seed16.length < 16) throw new Error('seed too short');
  function read64(off){
    let v = 0n;
    for(let i=0;i<8;i++) v = (v<<8n) | BigInt(seed16[off+i]);
    return v;
  }
  let s0 = read64(0), s1 = read64(8);
  if (s0===0n && s1===0n) s1 = 1n;
  const next = ()=> {
    let x = s0, y = s1;
    s0 = y;
    x ^= (x << 23n) & ((1n<<64n)-1n);
    x ^= (x >> 17n);
    x ^= y ^ (y >> 26n);
    s1 = x;
    return (x + y) & ((1n<<64n)-1n);
  };
  return {
    nextInt: (n) => Number(next() % BigInt(n)),
    nextByte: ()=> Number(next() & 0xFFn)
  };
}

// ---------- reversible layer functions (forward / reverse) ----------
const Layers = {
  b64: { f: s => s, r: s => s },
  rev: { f: s => s.split('').reverse().join(''), r: s => s.split('').reverse().join('') },
  enc_uri: { f: s => encodeURIComponent(s), r: s => decodeURIComponent(s) },
  saml_wrap: {
    f: s => `<saml:Assertion>${s}</saml:Assertion>`,
    r: s => {
      const m = s.match(/<saml:Assertion>([\s\S]*)<\/saml:Assertion>/);
      if(!m) throw new Error('SAML wrapper missing');
      return m[1];
    }
  },
  rot13: { f: s => rot13(s), r: s => rot13(s) },
  hex: { f: s => strToHex(s), r: s => hexToStr(s) },
  b64enc: { f: s => btoa(s), r: s => atob(s) },
  addNoise: {
    f: (s, ctx) => {
      if(!ctx || !ctx.seedUint8) return s.split('').map((ch,i)=> ch + String.fromCharCode(33 + (i%15))).join('');
      const prng = xs128plus(ctx.seedUint8.slice(0,16));
      const T = Math.max(s.length + Math.floor(s.length * (ctx.blowup||0.5)), s.length+4);
      const arr = new Array(T).fill(null);
      for(let i=0;i<T;i++) arr[i] = String.fromCharCode(33 + prng.nextInt(94));
      const idx = Array.from({length:T}, (_,i)=>i);
      for(let i=T-1;i>0;i--){ const j=prng.nextInt(i+1); [idx[i],idx[j]]=[idx[j],idx[i]]; }
      for(let k=0;k<s.length;k++) arr[idx[k]] = s[k];
      return arr.join('');
    },
    r: (s, ctx) => {
      if(!ctx || !ctx.seedUint8) throw new Error('Missing seed for noise removal');
      const prng = xs128plus(ctx.seedUint8.slice(0,16));
      const T = s.length;
      const idx = Array.from({length:T}, (_,i)=>i);
      for(let i=T-1;i>0;i--){ const j=prng.nextInt(i+1); [idx[i],idx[j]]=[idx[j],idx[i]]; }
      const L = ctx.realLen;
      if(!L) throw new Error('Missing real length in context');
      const out = new Array(L);
      for(let k=0;k<L;k++) out[k] = s[idx[k]];
      return out.join('');
    }
  },
  swapPairs: {
    f: s => {
      const a = s.split('');
      for(let i=0;i+1<a.length;i+=2) [a[i],a[i+1]]=[a[i+1],a[i]];
      return a.join('');
    },
    r: s => {
      const a = s.split('');
      for(let i=0;i+1<a.length;i+=2) [a[i],a[i+1]]=[a[i+1],a[i]];
      return a.join('');
    }
  },
  json_wrap: { f: s => JSON.stringify({d:s}), r: s => { try { return JSON.parse(s).d; } catch { throw new Error('JSON unwrap fail'); } } },
  simple_xor: {
    f: (s, ctx) => {
      const key = ctx && ctx.xorKey ? ctx.xorKey : [0x55,0xAA];
      const bytes = Array.from(s).map(ch=>ch.charCodeAt(0));
      const out = bytes.map((b,i)=> b ^ key[i % key.length]);
      return btoa(String.fromCharCode(...out));
    },
    r: (s, ctx) => {
      const key = ctx && ctx.xorKey ? ctx.xorKey : [0x55,0xAA];
      const bytes = Array.from(atob(s)).map(c=>c.charCodeAt(0));
      const out = bytes.map((b,i)=> b ^ key[i % key.length]);
      return String.fromCharCode(...out);
    }
  }
};

// choose sequence of 20 layers (forward order)
const LAYER_SEQUENCE = [
  'b64', 'rev', 'enc_uri', 'saml_wrap', 'rot13',
  'hex', 'b64enc', 'addNoise', 'swapPairs', 'b64enc',
  'json_wrap', 'rev', 'b64enc', 'rot13', 'hex',
  'enc_uri', 'rev', 'saml_wrap', 'addNoise', 'b64enc'
];

// ---------- high-level encrypt/decrypt that use AES-GCM then layers ----------
export async function encryptSuper(plainText, password, opts = {}) {
  const iterations = opts.iterations ?? DEFAULT_ITER;
  const blowup = opts.blowup ?? 1.8;

  // 1) derive keys
  const salt = rndBytes(SALT_BYTES);
  const nonce = rndBytes(NONCE_BYTES);
  const { aesKey, hmacRaw } = await deriveKeys(password, salt, iterations);

  // 2) AES-GCM encrypt (salt as additionalData)
  const ctBuf = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce, additionalData: salt, tagLength:128}, aesKey, encoder.encode(plainText));
  const ctBytes = new Uint8Array(ctBuf);

  // 3) base64 initial payload (ciphertext + tag already included)
  const base = bufToB64(ctBytes);

  // 4) prepare context for layers
  const seedFull = await hmacSign(hmacRaw, encoder.encode('seed|' + bufToB64(salt) + '|' + bufToB64(nonce)));
  const seedUint8 = seedFull.slice(0,16);
  const ctx = { seedUint8, blowup, realLen: ctBytes.length, xorKey: Array.from(seedFull.slice(0,4)) };

  // 5) apply layers sequentially
  let s = base;
  for (const name of LAYER_SEQUENCE) {
    const layer = Layers[name];
    if (!layer) throw new Error('Unknown layer ' + name);
    s = layer.f.length >= 2 ? layer.f(s, ctx) : layer.f(s);
  }

  // 6) build header and HMAC over header + final string (include blowup B)
  const header = `UKX_SUPER|i=${iterations}|S=${bufToB64(salt)}|N=${bufToB64(nonce)}|B=${blowup}|L=${ctBytes.length}|SEQ=${LAYER_SEQUENCE.join(',')}`;
  const macRaw = await hmacSign(hmacRaw, encoder.encode(header + '|' + s));
  const macB64 = bufToB64(macRaw);

  // 7) final token
  return `<<<UKXS>>>${header}<<<MAC>>>${macB64}<<<DATA>>>${s}<<<END>>>`;
}

export async function decryptSuper(token, password) {
  const m = token.match(/<<<UKXS>>>(.*?)<<<MAC>>>(.*?)<<<DATA>>>(.*?)<<<END>>>/s);
  if (!m) throw new Error('Token invalid / missing markers');
  const header = m[1];
  const macB64 = m[2];
  let payload = m[3];

  // parse header kv
  const kv = {};
  header.split('|').slice(1).forEach(p=>{
    const [k,v] = p.split('=');
    if (k) kv[k]=v;
  });
  const iterations = parseInt(kv['i'],10);
  const salt = b64ToBuf(kv['S']);
  const nonce = b64ToBuf(kv['N']);
  const blowup = parseFloat(kv['B'] ?? '1.8');
  const L = parseInt(kv['L'],10);

  const { aesKey, hmacRaw } = await deriveKeys(password, salt, iterations);
  // verify mac
  const expectedMac = await hmacSign(hmacRaw, encoder.encode(header + '|' + payload));
  const mac = b64ToBuf(macB64);
  if (expectedMac.length !== mac.length || !expectedMac.every((b,i)=>b===mac[i])) throw new Error('MAC mismatch — wrong password or tampered');

  // rebuild ctx (seed) with blowup from header
  const seedFull = await hmacSign(hmacRaw, encoder.encode('seed|' + bufToB64(salt) + '|' + bufToB64(nonce)));
  const ctx = { seedUint8: seedFull.slice(0,16), blowup, realLen: L, xorKey: Array.from(seedFull.slice(0,4)) };

  // reverse layers
  for (let i = LAYER_SEQUENCE.length - 1; i >= 0; i--) {
    const name = LAYER_SEQUENCE[i];
    const layer = Layers[name];
    if (!layer) throw new Error('Unknown layer ' + name);
    payload = layer.r.length >= 2 ? layer.r(payload, ctx) : layer.r(payload);
  }

  // final payload should be base64 of ciphertext
  const ctBytes = b64ToBuf(payload);
  try {
    const ptBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv: nonce, additionalData: salt, tagLength:128}, aesKey, ctBytes);
    return decoder.decode(ptBuf);
  } catch (e) {
    throw new Error('Decrypt failed: ' + e.message);
  }
}

export { encryptSuper, decryptSuper };
export default { encryptSuper, decryptSuper };
