// ukx.js
// Node.js v18+ (works on your Node 20)
// Usage:
// const { encrypt, decrypt } = require('./ukx');
// const token = await encrypt("Xin chào 👋", "mật-khẩu-dài", { iterations: 200000, blowup: 2.0 });
// const text = await decrypt(token, "mật-khẩu-dài");

import crypto from 'crypto';

const DEFAULT_ITER = 200000;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_MATERIAL_BYTES = 64; // 32B AES key + 32B HMAC key

function randBytes(n) { return crypto.randomBytes(n); }
function toBase64(b) { return Buffer.from(b).toString('base64'); }
function fromBase64(s) { return Buffer.from(s, 'base64'); }

function buildHeader(iterations, saltB64, nonceB64, blowup) {
  // Header string used in HMAC and to bind parameters
  return `UKX1|8|aesgcm256|pbkdf2sha256|i=${iterations}|S=${saltB64}|N=${nonceB64}|F=${blowup}`;
}

function deriveKeys(password, salt, iterations) {
  // Returns { aesKey: Buffer(32), hmacKey: Buffer(32) }
  const derived = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, KEY_MATERIAL_BYTES, 'sha256');
  return { aesKey: derived.slice(0,32), hmacKey: derived.slice(32,64) };
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

// encrypt: async API signature for parity with earlier code (returns Promise)
export async function encrypt(plainText, password, opts = {}) {
  const iterations = opts.iterations ?? DEFAULT_ITER;
  const blowup = Math.max(1.0, Number(opts.blowup ?? 1.5)); // chỉ điều chỉnh rác tổng
  // Generate salt + nonce
  const salt = randBytes(SALT_BYTES);
  const nonce = randBytes(NONCE_BYTES);
  const { aesKey, hmacKey } = deriveKeys(password, salt, iterations);

  // AES-GCM encrypt
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: 16 });
  const ct1 = cipher.update(plainText, 'utf8');
  const ct2 = cipher.final();
  const authTag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([ct1, ct2, authTag]); // ciphertext||tag

  // Optionally add internal "junk bytes" inside payload order?
  // Simpler: we will place ciphertext as payload and surround by random junk markers outside the payload.
  // But to make length longer, we can append random bytes to payload before base64 with deterministic approach:
  // We'll append J random bytes where J = floor(len(ciphertext)*(blowup-1)).
  const L = ciphertext.length;
  const J = Math.floor(L * (blowup - 1.0));
  const junk = randBytes(J);
  const payload = Buffer.concat([ciphertext, junk]); // payload = real ct + junk

  const saltB64 = toBase64(salt);
  const nonceB64 = toBase64(nonce);
  const payloadB64 = toBase64(payload);

  // Build header and compute HMAC over header + payload
  const header = buildHeader(iterations, saltB64, nonceB64, blowup);
  const mac = hmacSha256(hmacKey, Buffer.from(header + '|' + payloadB64, 'utf8'));
  const macB64 = toBase64(mac);

  // Package with explicit markers so safe when copy/paste with other text
  // Keep some random junk outside markers too (to confuse)
  const outerJunk1 = toBase64(randBytes(12)).slice(0,16); // small printable chunk
  const outerJunk2 = toBase64(randBytes(12)).slice(0,16);

  const token = [
    `<<<RAC>>>${outerJunk1}<<<HEADER>>>${header}<<<MAC>>>${macB64}<<<DATA>>>${payloadB64}<<<END>>>${outerJunk2}<<<RACEND>>>`
  ].join('');

  return token;
}

// decrypt: async API
export async function decrypt(token, password) {
  try {
    // Extract header, mac, payload via markers
    const m = token.match(/<<<HEADER>>>(.*?)<<<MAC>>>(.*?)<<<DATA>>>(.*?)<<<END>>>/s);
    if (!m) throw new Error('Dữ liệu không hợp lệ hoặc đã bị cắt mất (marker thiếu)');
    const header = m[1];
    const macB64 = m[2];
    const payloadB64 = m[3];

    // parse header for iterations, salt, nonce, blowup
    // header format: UKX1|8|aesgcm256|pbkdf2sha256|i=...|S=...|N=...|F=...
    const parts = header.split('|');
    const kv = {};
    for (const p of parts.slice(4)) { // from i=... onwards
      const idx = p.indexOf('=');
      if (idx !== -1) kv[p.slice(0,idx)] = p.slice(idx+1);
    }
    const iterations = parseInt(kv['i'], 10);
    const saltB64 = kv['S'];
    const nonceB64 = kv['N'];
    const blowup = parseFloat(kv['F'] ?? '1.0');

    if (!iterations || !saltB64 || !nonceB64) throw new Error('Header thiếu tham số');

    const salt = fromBase64(saltB64);
    const nonce = fromBase64(nonceB64);
    const payload = fromBase64(payloadB64);
    const mac = fromBase64(macB64);

    // derive keys
    const { aesKey, hmacKey } = deriveKeys(password, salt, iterations);

    // verify HMAC (constant time)
    const expectedMac = hmacSha256(hmacKey, Buffer.from(header + '|' + payloadB64, 'utf8'));
    if (!crypto.timingSafeEqual(expectedMac, mac)) {
      throw new Error('HMAC không khớp — có thể sai pass hoặc dữ liệu đã bị chỉnh sửa');
    }

    // Now recover ciphertext (we know ciphertext length >= 16 tag). But we don't know original plaintext length.
    // Because we appended junk after ciphertext, ciphertext is at the front of payload.
    // We need to find where ciphertext stops: but we know AES-GCM appended tag of 16 bytes; ciphertext length = real_ciphertext_len + 16.
    // However without original plaintext length we can't separate junk if it's appended — so we must attempt plausible ciphertext lengths.
    // Strategy: try candidate ctLen from minimal (16) to payload.length inclusive, but in practice ciphertext >= 16 and <= payload.length.
    // To speed up, we can attempt plausible ctLen values: from (payload.length - maxJunk) to payload.length.
    // For simplicity, we'll try ctLen candidates from payload.length downwards until decryption works.
    const T = payload.length;
    // For performance limit attempts to reasonable number
    const maxAttempts = Math.min(50, T); // cap trial attempts
    let tried = 0;
    // prefer larger ctLen (less junk) first
    for (let ctLen = T; ctLen >= Math.max(16, T - 1000); ctLen--) {
      if (++tried > maxAttempts) break;
      // extract candidate ciphertext+tag
      const ctCandidate = payload.slice(0, ctLen);
      // For AES-GCM we expect last 16 bytes of ctCandidate is tag
      if (ctCandidate.length < 16) continue;
      const authTag = ctCandidate.slice(ctCandidate.length - 16);
      const ciphertextOnly = ctCandidate.slice(0, ctCandidate.length - 16);
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: 16 });
        decipher.setAuthTag(authTag);
        const pt1 = decipher.update(ciphertextOnly);
        const pt2 = decipher.final();
        const plain = Buffer.concat([pt1, pt2]).toString('utf8');
        // success
        return plain;
      } catch (e) {
        // continue trying
      }
    }

    // If we reach here, failed to decrypt
    throw new Error('Giải mã thất bại (sai pass/đã bị chỉnh sửa hoặc không tìm được vị trí ciphertext)');
  } catch (err) {
    // Re-throw friendly message
    throw new Error(err.message);
  }
}

// For CommonJS compatibility:
export default { encrypt, decrypt };
