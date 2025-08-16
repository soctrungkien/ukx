// ukx.js
// Browser: AES-GCM + PBKDF2 + HMAC + reversible layers with noise
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

// ---------- PRNG from seed ----------
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

// ---------- reversible layers ----------
const Layers = {
  rev: { f: s=>s.split('').reverse().join(''), r: s=>s.split('').reverse().join('') },
  enc_uri: { f: s=>encodeURIComponent(s), r: s=>decodeURIComponent(s) },
  rot13: { f: s=>rot13(s), r: s=>rot13(s) },
  hex: { f: s=>strToHex(s), r: s=>hexToStr(s) },
  b64enc: { f: s=>btoa(s), r: s=>atob(s) },
  addNoise: {
    f: (s, ctx)=>{
      if(!ctx?.seedUint8) return s;
      const prng = xs128plus(ctx.seedUint8.slice(0,16));
      const arr = s.split('');
      for(let i=0;i<arr.length;i++) arr[i] += String.fromCharCode(33 + prng.nextInt(94));
      return arr.join('');
    },
    r: (s, ctx)=>{
      if(!ctx?.seedUint8 || !ctx?.realLen) throw new Error('Missing seed or realLen for noise removal');
      const prng = xs128plus(ctx.seedUint8.slice(0,16));
      const arr = s.split('');
      const out = new Array(ctx.realLen);
      for(let i=0;i<ctx.realLen;i++) out[i] = arr[i][0]; // chỉ lấy ký tự gốc
      return out.join('');
    }
  }
};

// ---------- layer sequence ----------
const LAYER_SEQUENCE = ['b64enc','rev','enc_uri','rot13','hex','addNoise'];

// ---------- encrypt ----------
export async function encrypt(plainText, password, opts={}){
  const iterations = opts.iterations ?? DEFAULT_ITER;
  const blowup = opts.blowup ?? 1.5;

  const salt = rndBytes(SALT_BYTES);
  const nonce = rndBytes(NONCE_BYTES);
  const { aesKey, hmacRaw } = await deriveKeys(password, salt, iterations);

  const ctBuf = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce, additionalData: salt, tagLength:128}, aesKey, encoder.encode(plainText));
  const ctBytes = new Uint8Array(ctBuf);
  const base = bufToB64(ctBytes);

  const seedFull = await hmacSign(hmacRaw, encoder.encode('seed|' + bufToB64(salt) + '|' + bufToB64(nonce)));
  const ctx = { seedUint8: seedFull.slice(0,16), blowup, realLen: ctBytes.length };

  let s = base;
  for(const name of LAYER_SEQUENCE){
    const layer = Layers[name];
    s = layer.f.length>=2 ? layer.f(s, ctx) : layer.f(s);
  }

  const header = `i=${iterations}|S=${bufToB64(salt)}|N=${bufToB64(nonce)}|B=${blowup}|L=${ctBytes.length}|SEQ=${LAYER_SEQUENCE.join(',')}`;
  const macRaw = await hmacSign(hmacRaw, encoder.encode(header+'|'+s));
  const macB64 = bufToB64(macRaw);

  return `<<<HEADER>>>${header}<<<MAC>>>${macB64}<<<DATA>>>${s}<<<END>>>`;
}

// ---------- decrypt ----------
export async function decrypt(token, password){
  const m = token.match(/<<<HEADER>>>(.*?)<<<MAC>>>(.*?)<<<DATA>>>(.*?)<<<END>>>/s);
  if(!m) throw new Error('Token invalid / missing markers');
  const header = m[1], macB64 = m[2], payload = m[3];

  const kv = {};
  header.split('|').forEach(p=>{
    const [k,v] = p.split('=');
    if(k) kv[k]=v;
  });
  const iterations = parseInt(kv['i'],10);
  const salt = b64ToBuf(kv['S']);
  const nonce = b64ToBuf(kv['N']);
  const blowup = parseFloat(kv['B']);
  const L = parseInt(kv['L'],10);

  const { aesKey, hmacRaw } = await deriveKeys(password, salt, iterations);

  const expectedMac = await hmacSign(hmacRaw, encoder.encode(header+'|'+payload));
  const mac = b64ToBuf(macB64);
  if(expectedMac.length!==mac.length || !expectedMac.every((b,i)=>b===mac[i])) throw new Error('MAC mismatch');

  const seedFull = await hmacSign(hmacRaw, encoder.encode('seed|' + bufToB64(salt) + '|' + bufToB64(nonce)));
  const ctx = { seedUint8: seedFull.slice(0,16), blowup, realLen: L };

  let s = payload;
  for(let i=LAYER_SEQUENCE.length-1;i>=0;i--){
    const layer = Layers[LAYER_SEQUENCE[i]];
    s = layer.r.length>=2 ? layer.r(s, ctx) : layer.r(s);
  }

  const ctBytes = b64ToBuf(s);
  const ptBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv:nonce, additionalData:salt, tagLength:128}, aesKey, ctBytes);
  return decoder.decode(ptBuf);
}

export { encrypt, decrypt };
