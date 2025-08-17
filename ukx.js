// ukx.js
// Browser-safe: iterative only, avoids call-stack overflow.
// Exports: encrypt(plaintext, password) -> base64PackedString
//          decrypt(base64PackedString, password) -> plaintext

const DEFAULT_ITER = 200000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_MATERIAL_BYTES = 64;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------- safe helpers to avoid call-stack issues ----------
function _u8ToStrSafe(u8){
  const CH = 0x8000;
  let str = '';
  for(let i=0;i<u8.length;i+=CH){
    const slice = u8.subarray(i, i+CH);
    str += String.fromCharCode.apply(null, Array.from(slice));
  }
  return str;
}
function _strToU8Safe(s){
  return encoder.encode(s);
}

function bytesToBase64(bytes){
  return btoa(_u8ToStrSafe(bytes));
}
function base64ToBytes(b64){
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// hex helpers
function strToHex(s){
  let out = '';
  for(let i=0;i<s.length;i++){
    out += s.charCodeAt(i).toString(16).padStart(2,'0');
  }
  return out;
}
function hexToStr(hex){
  if(hex.length % 2) throw new Error('Invalid hex');
  let out = '';
  for(let i=0;i<hex.length;i+=2) out += String.fromCharCode(parseInt(hex.slice(i,i+2),16));
  return out;
}
function rot13(s){
  return s.replace(/[a-zA-Z]/g, c=>{
    const base = (c <= 'Z') ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0)-base+13)%26 + base);
  });
}

// ---------- PRNG (xs128plus) ----------
function xs128plus(seed16){
  if(!(seed16 instanceof Uint8Array) || seed16.length < 16) throw new Error('seed too short');
  function read64(off){
    let v = 0n;
    for(let i=0;i<8;i++) v = (v<<8n) | BigInt(seed16[off+i]);
    return v;
  }
  let s0 = read64(0), s1 = read64(8);
  if(s0 === 0n && s1 === 0n) s1 = 1n;
  const next = ()=>{
    let x = s0, y = s1;
    s0 = y;
    x ^= (x << 23n) & ((1n<<64n)-1n);
    x ^= (x >> 17n);
    x ^= y ^ (y >> 26n);
    s1 = x;
    return (x + y) & ((1n<<64n)-1n);
  };
  return {
    nextByte: ()=> Number(next() & 0xFFn),
    nextInt: (n)=> Number(next() % BigInt(n))
  };
}

// ---------- crypto helpers ----------
async function deriveKeys(password, salt, iterations){
  const pwKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, pwKey, KEY_MATERIAL_BYTES*8);
  const arr = new Uint8Array(bits);
  const aesRaw = arr.slice(0,32);
  const hmacRaw = arr.slice(32,64);
  const aesKey = await crypto.subtle.importKey('raw', aesRaw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  return { aesKey, hmacRaw, aesRaw };
}
async function hmacSign(rawKey, dataUint8){
  const k = await crypto.subtle.importKey('raw', rawKey, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, dataUint8);
  return new Uint8Array(sig);
}

// ---------- safe XOR-noise that preserves base64 validity ----------
function xorBytesWithPRNG(bytes, seedUint8){
  const prng = xs128plus(seedUint8.slice(0,16));
  const out = new Uint8Array(bytes.length);
  for(let i=0;i<bytes.length;i++) out[i] = bytes[i] ^ prng.nextByte();
  return out;
}

// ---------- pipeline config (fixed, iterative) ----------
const LAYER_SEQUENCE = ['rot13','hex','xor','rev','enc_uri'];
const MAX_LAYERS = 50;

// forward transformations
function layer_rot13_f(s){ return rot13(s); }
function layer_rot13_r(s){ return rot13(s); }

function layer_hex_f(s){ return strToHex(s); }
function layer_hex_r(s){ return hexToStr(s); }

function layer_xor_f(s, ctx){
  const bytes = _strToU8Safe(s);
  const out = xorBytesWithPRNG(bytes, ctx.seedUint8);
  return bytesToBase64(out);
}
function layer_xor_r(s, ctx){
  const bytes = base64ToBytes(s);
  const orig = xorBytesWithPRNG(bytes, ctx.seedUint8);
  return _u8ToStrSafe(orig);
}

function layer_rev_f(s){ return s.split('').reverse().join(''); }
function layer_rev_r(s){ return s.split('').reverse().join(''); }

function layer_enc_uri_f(s){ return encodeURIComponent(s); }
function layer_enc_uri_r(s){ return decodeURIComponent(s); }

const LAYER_MAP_F = {
  'rot13': layer_rot13_f,
  'hex': layer_hex_f,
  'xor': layer_xor_f,
  'rev': layer_rev_f,
  'enc_uri': layer_enc_uri_f
};
const LAYER_MAP_R = {
  'rot13': layer_rot13_r,
  'hex': layer_hex_r,
  'xor': layer_xor_r,
  'rev': layer_rev_r,
  'enc_uri': layer_enc_uri_r
};

// pack helpers
function buildPackString(saltB64, nonceB64, dataB64){
  return `S=${saltB64}|N=${nonceB64}|DATA=${dataB64}`;
}
function parsePackString(pack){
  const parts = pack.split('|');
  const kv = {};
  for(const p of parts){
    const idx = p.indexOf('=');
    if(idx>0) kv[p.slice(0,idx)] = p.slice(idx+1);
  }
  return kv;
}

// ---------- public: encrypt / decrypt ----------
export async function encrypt(plainText, password, opts = {}){
  try{
    if(typeof plainText !== 'string' || typeof password !== 'string') throw new Error('Invalid args');
    const iterations = opts.iterations ?? DEFAULT_ITER;
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const { aesKey, hmacRaw } = await deriveKeys(password, salt, iterations);

    // AES-GCM encrypt (salt as additionalData)
    const ctBuf = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce, additionalData: salt, tagLength:128}, aesKey, encoder.encode(plainText));
    const ctBytes = new Uint8Array(ctBuf);
    let s = bytesToBase64(ctBytes);

    // prepare ctx seed
    const seedFull = await hmacSign(hmacRaw, encoder.encode('seed|' + bytesToBase64(salt) + '|' + bytesToBase64(nonce)));
    const seedUint8 = seedFull.slice(0,16);
    const ctx = { seedUint8 };

    if(LAYER_SEQUENCE.length > MAX_LAYERS) throw new Error('Layer count too large');
    for(const name of LAYER_SEQUENCE){
      const fn = LAYER_MAP_F[name];
      if(!fn) throw new Error('Unknown layer ' + name);
      s = fn.length >= 2 ? fn(s, ctx) : fn(s);
    }

    const dataB64 = btoa(s);                 // final string base64-wrapped for ASCII safety
    const saltB64 = bytesToBase64(salt);
    const nonceB64 = bytesToBase64(nonce);
    const pack = buildPackString(saltB64, nonceB64, dataB64);

    return btoa(pack); // final packed base64 string
  }catch(e){
    throw new Error('Encrypt failed: ' + e.message);
  }
}

export async function decrypt(packedBase64, password, opts = {}){
  try{
    if(typeof packedBase64 !== 'string' || typeof password !== 'string') throw new Error('Invalid args');
    let pack;
    try { pack = atob(packedBase64); } catch(_) { throw new Error('Packed string not base64'); }

    const kv = parsePackString(pack);
    if(!kv.S || !kv.N || !kv.DATA) throw new Error('Packed fields missing');

    const salt = base64ToBytes(kv.S);
    const nonce = base64ToBytes(kv.N);
    if(nonce.length !== NONCE_BYTES) throw new Error('Nonce length mismatch');

    const dataFinalString = atob(kv.DATA);

    const iterations = opts.iterations ?? DEFAULT_ITER;
    const { aesKey, hmacRaw } = await deriveKeys(password, salt, iterations);

    const seedFull = await hmacSign(hmacRaw, encoder.encode('seed|' + kv.S + '|' + kv.N));
    const seedUint8 = seedFull.slice(0,16);
    const ctx = { seedUint8 };

    let s = dataFinalString;
    for(let i = LAYER_SEQUENCE.length - 1; i >= 0; i--){
      const name = LAYER_SEQUENCE[i];
      const fn = LAYER_MAP_R[name];
      if(!fn) throw new Error('Unknown layer ' + name);
      s = fn.length >= 2 ? fn(s, ctx) : fn(s);
    }

    const ctBytes = base64ToBytes(s);
    const ptBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv:nonce, additionalData: salt, tagLength:128}, aesKey, ctBytes);
    return decoder.decode(ptBuf);
  }catch(e){
    throw new Error('Decrypt failed: ' + e.message);
  }
}

//thg ngu nao code 'export default { encrypt, decrypt };'
