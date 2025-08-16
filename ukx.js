// ukx.browser.js
// Browser version: dùng window.crypto.subtle, không cần import 'crypto'

const DEFAULT_ITER = 250000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_MATERIAL_BYTES = 64; // 32B AES + 32B HMAC

function randBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}
function toBase64(b) { return btoa(String.fromCharCode(...b)); }
function fromBase64(s) { return new Uint8Array([...atob(s)].map(c => c.charCodeAt(0))); }

function buildHeader(iterations, saltB64, nonceB64, blowup, ctLen) {
  return `UKX2|8|aesgcm256|pbkdf2sha256|i=${iterations}|S=${saltB64}|N=${nonceB64}|F=${blowup}|L=${ctLen}`;
}

async function deriveKeys(password, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    KEY_MATERIAL_BYTES * 8
  );
  const derived = new Uint8Array(bits);
  return { aesKey: derived.slice(0,32), hmacKey: derived.slice(32,64) };
}

async function importHmacKey(rawKey) {
  return crypto.subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function hmacSha256(key, data) {
  const hKey = await importHmacKey(key);
  const sig = await crypto.subtle.sign("HMAC", hKey, data);
  return new Uint8Array(sig);
}

export async function encrypt(plainText, password, opts = {}) {
  const iterations = opts.iterations ?? DEFAULT_ITER;
  const blowup = Math.max(1.0, Number(opts.blowup ?? 1.5));
  const salt = randBytes(SALT_BYTES);
  const nonce = randBytes(NONCE_BYTES);
  const { aesKey, hmacKey } = await deriveKeys(password, salt, iterations);

  const aesCryptoKey = await crypto.subtle.importKey("raw", aesKey, "AES-GCM", false, ["encrypt"]);
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 },
    aesCryptoKey,
    new TextEncoder().encode(plainText)
  );
  const ciphertext = new Uint8Array(ctBuf);

  // Junk bytes
  const L = ciphertext.length;
  const J = Math.floor(L * (blowup - 1.0));
  const junk = randBytes(J);
  const payload = new Uint8Array(L + J);
  payload.set(ciphertext, 0);
  payload.set(junk, L);

  const saltB64 = toBase64(salt);
  const nonceB64 = toBase64(nonce);
  const payloadB64 = toBase64(payload);

  const header = buildHeader(iterations, saltB64, nonceB64, blowup, L);
  const mac = await hmacSha256(hmacKey, new TextEncoder().encode(header + '|' + payloadB64));
  const macB64 = toBase64(mac);

  const outerJunk1 = toBase64(randBytes(12)).slice(0,16);
  const outerJunk2 = toBase64(randBytes(12)).slice(0,16);

  return `<<<RAC>>>${outerJunk1}<<<HEADER>>>${header}<<<MAC>>>${macB64}<<<DATA>>>${payloadB64}<<<END>>>${outerJunk2}<<<RACEND>>>`;
}

export async function decrypt(token, password) {
  const m = token.match(/<<<HEADER>>>(.*?)<<<MAC>>>(.*?)<<<DATA>>>(.*?)<<<END>>>/s);
  if (!m) throw new Error('❌ Token không hợp lệ (thiếu marker)');
  const header = m[1];
  const macB64 = m[2];
  const payloadB64 = m[3];

  const kv = {};
  header.split('|').slice(4).forEach(p => {
    const [k,v] = p.split('=');
    if (k && v) kv[k] = v;
  });
  const iterations = parseInt(kv['i'],10);
  const saltB64 = kv['S'];
  const nonceB64 = kv['N'];
  const ctLen = parseInt(kv['L'],10);

  if (!iterations || !saltB64 || !nonceB64 || !ctLen) throw new Error('❌ Header thiếu thông tin');

  const salt = fromBase64(saltB64);
  const nonce = fromBase64(nonceB64);
  const payload = fromBase64(payloadB64);
  const mac = fromBase64(macB64);

  const { aesKey, hmacKey } = await deriveKeys(password, salt, iterations);

  // Verify HMAC
  const expectedMac = await hmacSha256(hmacKey, new TextEncoder().encode(header + '|' + payloadB64));
  if (expectedMac.length !== mac.length || !expectedMac.every((b,i)=>b===mac[i])) {
    throw new Error('❌ Sai pass hoặc token bị chỉnh sửa');
  }

  const ctCandidate = payload.slice(0, ctLen);
  const authTag = ctCandidate.slice(-16);
  const ciphertextOnly = ctCandidate.slice(0, -16);

  const aesCryptoKey = await crypto.subtle.importKey("raw", aesKey, "AES-GCM", false, ["decrypt"]);
  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128, additionalData: undefined },
    aesCryptoKey,
    new Uint8Array([...ciphertextOnly, ...authTag])
  );
  return new TextDecoder().decode(ptBuf);
}

export default { encrypt, decrypt };
