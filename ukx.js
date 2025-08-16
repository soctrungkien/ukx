// ukx.browser.js
// Browser-only UKX: AES-GCM + PBKDF2 + HMAC + junk+perm + emoji encoding

const DEFAULT_ITER = 200000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_MATERIAL_BYTES = 64; // 32B AES + 32B HMAC

// ---------- emoji alphabet (tập ký tự đầu ra) ----------
// Mình dùng 128 emoji (vừa đẹp vừa đa dạng). Bạn có thể mở rộng.
const EMOJI_ALPH = [
  "🔒","❤️","🔥","✨","🎯","❌","🤣","🍪","🔧","🌟","🛡️","💎","🔑","🧠","⚡",
  "🌍","📦","🧪","🧩","🎲","🎮","🛰️","🚀","🌈","💥","🕶️","🧿","📡","🧭","⚙️",
  "🥷","👑","🦾","🧨","🔮","📜","🗝️","💡","📌","📎","🧵","🪄","🪪","🖼️","🎵",
  "🎬","📷","📝","📕","📗","📘","📙","📎","🔗","🔍","🧰","🩺","⚖️","🧱","🏷️",
  "🧯","🪓","🔨","🧰","🧲","🧪","🧬","💣","🧨","🛠️","🛎️","🏁","🚩","🧱","🧱",
  "🧸","🪀","🎈","🎁","🧧","🪄","🎗️","🏆","🥇","🥈","🥉","⚽","🏀","🏈","🎳",
  "🎮","🕹️","🧩","♟️","🧭","📡","🔭","🔬","🧪","🩻","🧯","🧰","📦","🧾","📌",
  "📍","📎","🔖","🗳️","✉️","📩","📨","📧","📮","🧾","✅","🈶","🈚","🔰","💠",
  "♻️","⚠️","🚫","⛔","🔞","🔐","🔓","🔔","🔕","📢","📣","🧭","🗺️","🧭","🏔️",
  "🏝️","🏖️","🏜️","🏕️","🏟️","🗼","🏯","🛤️","⛵","🚤","✈️","🚁","🚂","🚆","🚇"
];
// ensure uniqueness (just in case)
const EMOJI_SET = Array.from(new Set(EMOJI_ALPH));
const BASE = EMOJI_SET.length; // base N

// ---------- util bytes/base64 ----------
function rndBytes(n){
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function bufToB64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBuf(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------- deterministic PRNG from 16-byte seed (xorshift128+) ----------
function xs128plus(seed16){
  // seed16: Uint8Array length>=16
  if (seed16.length < 16) throw new Error("seed too short");
  function read64(off){
    let v = 0n;
    for(let i=0;i<8;i++){
      v = (v<<8n) | BigInt(seed16[off+i]);
    }
    return v;
  }
  let s0 = read64(0);
  let s1 = read64(8);
  if (s0 === 0n && s1 === 0n) s1 = 1n;
  const next = ()=> {
    let x = s0; let y = s1;
    s0 = y;
    x ^= (x << 23n) & ((1n<<64n)-1n);
    x ^= (x >> 17n);
    x ^= y ^ (y >> 26n);
    s1 = x;
    const res = (x + y) & ((1n<<64n)-1n);
    return res;
  };
  const nextInt = (n) => Number(next() % BigInt(n));
  const nextByte = ()=> nextInt(256);
  return { next, nextInt, nextByte };
}

// ---------- HMAC-SHA256 helper ----------
async function importHmacKey(rawKeyUint8){
  return await crypto.subtle.importKey('raw', rawKeyUint8, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign','verify']);
}
async function hmacRaw(keyUint8, msgUint8){
  const k = await importHmacKey(keyUint8);
  const sig = await crypto.subtle.sign('HMAC', k, msgUint8);
  return new Uint8Array(sig); // 32 bytes
}

// ---------- derive keys: PBKDF2 -> deriveBits (64 bytes) ----------
async function derive(password, salt, iterations){
  const pwKey = await crypto.subtle.importKey('raw', encoder.encode(password), {name:'PBKDF2'}, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, pwKey, KEY_MATERIAL_BYTES*8);
  const arr = new Uint8Array(bits);
  const aesKeyRaw = arr.slice(0,32);
  const hmacKeyRaw = arr.slice(32,64);
  const aesCryptoKey = await crypto.subtle.importKey('raw', aesKeyRaw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  return { aesCryptoKey, hmacKeyRaw, aesKeyRaw };
}

// ---------- emoji base-N encoder/decoder (bytes <-> emoji string) ----------
// Convert big integer representation (bytes) to base-N using repeated div
function bytesToEmoji(u8){
  // remove leading zeros
  let bytes = Array.from(u8);
  // big integer division by BASE
  if (bytes.length === 0) return "";
  const digits = [];
  while (bytes.length > 0 && !(bytes.length===1 && bytes[0]===0)){
    let carry = 0;
    const newBytes = [];
    for (let b of bytes){
      const acc = (carry << 8) + b;
      const q = Math.floor(acc / BASE);
      carry = acc % BASE;
      if (newBytes.length>0 || q>0) newBytes.push(q);
    }
    digits.push(carry);
    bytes = newBytes;
  }
  // digits holds little-endian base-BASE digits
  return digits.reverse().map(d => EMOJI_SET[d]).join('');
}

function emojiToBytes(str){
  if (!str) return new Uint8Array();
  const digits = [];
  for (const ch of Array.from(str)){
    const idx = EMOJI_SET.indexOf(ch);
    if (idx === -1) throw new Error('Emoji không hợp lệ trong payload');
    digits.push(idx);
  }
  // big-endian digits -> bytes via multiply-add
  let bytes = [0];
  for (let d of digits){
    let carry = d;
    for (let i = bytes.length-1; i>=0; i--){
      const val = bytes[i]*BASE + carry;
      bytes[i] = val & 0xFF;
      carry = val >> 8;
    }
    while (carry > 0){
      bytes.unshift(carry & 0xFF);
      carry = carry >> 8;
    }
  }
  return new Uint8Array(bytes);
}

// ---------- main encrypt/decrypt functions ----------
export async function encrypt(plainText, password, opts = {}) {
  const iterations = opts.iterations ?? DEFAULT_ITER;
  const blowup = Math.max(1.0, Number(opts.blowup ?? 2.0)); // default x2

  // random salt & nonce
  const salt = rndBytes(SALT_BYTES);
  const nonce = rndBytes(NONCE_BYTES);

  // derive keys
  const { aesCryptoKey, hmacKeyRaw } = await derive(password, salt, iterations);

  // AES-GCM encrypt (use salt as additionalData)
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name:'AES-GCM', iv: nonce, additionalData: salt, tagLength: 128 },
    aesCryptoKey,
    encoder.encode(plainText)
  );
  const ciphertext = new Uint8Array(ciphertextBuf); // includes tag

  // compute payload length L and T = floor(L * blowup)
  const L = ciphertext.length;
  const T = Math.max(L, Math.floor(L * blowup));

  // build deterministic permutation using seed = HMAC(hmacKeyRaw, "perm|"+salt+nonce)
  const seedMsg = new Uint8Array([ ...encoder.encode("perm|"), ...salt, ...nonce ]);
  const seedFull = await hmacRaw(hmacKeyRaw, seedMsg); // 32 bytes
  const prng = xs128plus(seedFull.slice(0,16));

  // produce permutation of indices 0..T-1
  const idx = Array.from({length:T}, (_,i)=>i);
  for (let i=T-1;i>0;i--){
    const j = prng.nextInt(i+1);
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  // first L positions in permuted idx are where ciphertext bytes will go
  const realPos = idx.slice(0, L);

  // fill output array length T with junk from PRNG, then place ciphertext
  const out = new Uint8Array(T);
  for (let i=0;i<T;i++) out[i] = prng.nextByte(); // junk
  for (let k=0;k<L;k++){
    out[realPos[k]] = ciphertext[k];
  }

  // emoji-encode payload
  const payloadEmoji = bytesToEmoji(out);

  // header: keep ASCII for parsing: include iterations, salt(b64), nonce(b64), blowup, L(real ct len)
  const saltB64 = bufToB64(salt);
  const nonceB64 = bufToB64(nonce);
  const header = `UKX3|8|aesgcm256|pbkdf2sha256|i=${iterations}|S=${saltB64}|N=${nonceB64}|F=${blowup}|L=${L}`;

  // compute HMAC over header + '|' + payloadEmoji (use hmacKeyRaw)
  const macRaw = await hmacRaw(hmacKeyRaw, encoder.encode(header + '|' + payloadEmoji));
  const macB64 = bufToB64(macRaw);

  // outer junk (short ascii) to confuse
  const outer1 = bufToB64(rndBytes(8)).slice(0,12);
  const outer2 = bufToB64(rndBytes(8)).slice(0,12);

  // final token: markers + emoji payload
  // all ASCII parts are safe; payload is emoji string (no base64)
  const token = `<<<RAC>>>${outer1}<<<HEADER>>>${header}<<<MAC>>>${macB64}<<<DATA>>>${payloadEmoji}<<<END>>>${outer2}<<<RACEND>>>`;
  return token;
}

export async function decrypt(token, password){
  // parse token
  const m = token.match(/<<<HEADER>>>(.*?)<<<MAC>>>(.*?)<<<DATA>>>(.*?)<<<END>>>/s);
  if (!m) throw new Error('Token không hợp lệ (marker thiếu)');
  const header = m[1];
  const macB64 = m[2];
  const payloadEmoji = m[3];

  // parse header kv
  const kv = {};
  header.split('|').slice(4).forEach(p=>{
    const [k,v] = p.split('=');
    if (k) kv[k]=v;
  });
  const iterations = parseInt(kv['i'],10);
  const saltB64 = kv['S'];
  const nonceB64 = kv['N'];
  const L = parseInt(kv['L'],10);
  const blowup = parseFloat(kv['F'] ?? '1.0');

  if (!iterations || !saltB64 || !nonceB64 || !L) throw new Error('Header thiếu thông tin');

  const salt = b64ToBuf(saltB64);
  const nonce = b64ToBuf(nonceB64);
  // derive keys
  const { aesCryptoKey, hmacKeyRaw } = await derive(password, salt, iterations);

  // verify mac (HMAC)
  const expectedMac = await hmacRaw(hmacKeyRaw, encoder.encode(header + '|' + payloadEmoji));
  const mac = b64ToBuf(macB64);
  if (expectedMac.length !== mac.length || !expectedMac.every((b,i)=>b===mac[i])){
    throw new Error('❌ Sai pass hoặc token bị chỉnh sửa (MAC mismatch)');
  }

  // decode emoji -> bytes (out)
  const out = emojiToBytes(payloadEmoji);
  const T = out.length;
  if (L > T) throw new Error('Payload quá ngắn');
  // rebuild permutation same as encrypt
  const seedMsg = new Uint8Array([ ...encoder.encode("perm|"), ...salt, ...nonce ]);
  const seedFull = await hmacRaw(hmacKeyRaw, seedMsg);
  const prng = xs128plus(seedFull.slice(0,16));
  const idx = Array.from({length:T}, (_,i)=>i);
  for (let i=T-1;i>0;i--){
    const j = prng.nextInt(i+1);
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  const realPos = idx.slice(0, L);

  // extract ciphertext bytes
  const ct = new Uint8Array(L);
  for (let k=0;k<L;k++) ct[k] = out[realPos[k]];

  // now decrypt AES-GCM (salt used as additionalData)
  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name:'AES-GCM', iv: nonce, additionalData: salt, tagLength: 128 },
      aesCryptoKey,
      ct
    );
    return decoder.decode(plainBuf);
  } catch (e){
    throw new Error('❌ Giải mã thất bại (sai pass/đã bị chỉnh sửa hoặc tag invalid)');
  }
}

export default { encrypt, decrypt };
