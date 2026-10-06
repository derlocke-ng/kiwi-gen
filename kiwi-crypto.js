// Kiwi crypto core: OpenSSH keys, X.509 certificates and PKCS#8 on top of WebCrypto.
// No DOM access in here, so it can be exercised outside the browser.
const Kiwi = (() => {
  'use strict';

  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  const utf8 = new TextEncoder();

  // ---------------------------------------------------------------- bytes

  function concat(...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }

  const randomBytes = n => crypto.getRandomValues(new Uint8Array(n));
  const bytes = buf => new Uint8Array(buf);

  function toBase64(data) {
    let s = '';
    for (let i = 0; i < data.length; i += 0x8000) s += String.fromCharCode(...data.subarray(i, i + 0x8000));
    return btoa(s);
  }

  const fromBase64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const fromBase64Url = s => fromBase64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));

  function equalBytes(a, b) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }

  function stripLeadingZeros(b) {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
  }

  // ---------------------------------------------------------------- PEM

  function toPem(label, der, width = 64) {
    const lines = toBase64(der).match(new RegExp(`.{1,${width}}`, 'g'));
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
  }

  function parsePem(text) {
    const blocks = [];
    text = text.replace(/\r/g, '');
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    let m;
    while ((m = re.exec(text))) {
      const body = m[2].trim();
      const headerEnd = body.indexOf('\n\n');
      const headers = /^[A-Za-z-]+:/.test(body) && headerEnd > 0 ? body.slice(0, headerEnd) : '';
      const b64 = (headers ? body.slice(headerEnd) : body).replace(/\s+/g, '');
      blocks.push({ label: m[1], headers, der: fromBase64(b64) });
    }
    return blocks;
  }

  // ---------------------------------------------------------------- DER

  function derLength(n) {
    if (n < 0x80) return Uint8Array.of(n);
    const out = [];
    for (; n > 0; n = Math.floor(n / 256)) out.unshift(n & 0xff);
    return Uint8Array.of(0x80 | out.length, ...out);
  }

  const tlv = (tag, ...content) => {
    const body = concat(...content);
    return concat(Uint8Array.of(tag), derLength(body.length), body);
  };
  const seq = (...c) => tlv(0x30, ...c);
  const set = (...c) => tlv(0x31, ...c);
  const octets = (...c) => tlv(0x04, ...c);
  const bitString = b => tlv(0x03, Uint8Array.of(0), b);
  const utf8String = s => tlv(0x0c, utf8.encode(s));
  const boolTrue = () => tlv(0x01, Uint8Array.of(0xff));
  const derNull = () => tlv(0x05);
  const explicit = (n, ...c) => tlv(0xa0 | n, ...c);

  function integer(b) {
    b = stripLeadingZeros(b);
    return tlv(0x02, b[0] & 0x80 ? concat(Uint8Array.of(0), b) : b);
  }

  function smallInt(n) {
    const out = [];
    do { out.unshift(n & 0xff); n = Math.floor(n / 256); } while (n > 0);
    return integer(Uint8Array.from(out));
  }

  function oid(str) {
    const arcs = str.split('.').map(Number);
    const out = [40 * arcs[0] + arcs[1]];
    for (const arc of arcs.slice(2)) {
      const chunk = [arc & 0x7f];
      for (let v = Math.floor(arc / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift(0x80 | (v & 0x7f));
      out.push(...chunk);
    }
    return tlv(0x06, Uint8Array.from(out));
  }

  function time(date) {
    const p = n => String(n).padStart(2, '0');
    const y = date.getUTCFullYear();
    const rest = p(date.getUTCMonth() + 1) + p(date.getUTCDate()) + p(date.getUTCHours()) +
      p(date.getUTCMinutes()) + p(date.getUTCSeconds()) + 'Z';
    // RFC 5280: UTCTime through 2049, GeneralizedTime from 2050 on
    return y < 2050 ? tlv(0x17, utf8.encode(p(y % 100) + rest)) : tlv(0x18, utf8.encode(y + rest));
  }

  // Parses one TLV at `off`; returns { tag, content, raw, end }.
  function parseDer(der, off = 0) {
    const tag = der[off];
    let len = der[off + 1], start = off + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error('Unsupported DER length');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + der[start + i];
      start += n;
    }
    const end = start + len;
    if (end > der.length) throw new Error('Truncated DER');
    return { tag, content: der.subarray(start, end), raw: der.subarray(off, end), end };
  }

  function children(node) {
    const out = [];
    for (let off = 0; off < node.content.length;) {
      const child = parseDer(node.content, off);
      out.push(child);
      off = child.end;
    }
    return out;
  }

  function oidToString(node) {
    const b = node.content, arcs = [Math.floor(b[0] / 40), b[0] % 40];
    for (let i = 1, v = 0; i < b.length; i++) {
      v = v * 128 + (b[i] & 0x7f);
      if (!(b[i] & 0x80)) { arcs.push(v); v = 0; }
    }
    return arcs.join('.');
  }

  function parseTime(node) {
    let s = new TextDecoder().decode(node.content);
    if (node.tag === 0x17) s = (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s;
    return new Date(Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14)));
  }

  // ---------------------------------------------------------------- key types

  const OID = {
    rsaEncryption: '1.2.840.113549.1.1.1',
    sha256WithRSA: '1.2.840.113549.1.1.11',
    ecPublicKey: '1.2.840.10045.2.1',
    ecdsaSha256: '1.2.840.10045.4.3.2',
    ecdsaSha384: '1.2.840.10045.4.3.3',
    ecdsaSha512: '1.2.840.10045.4.3.4',
    ed25519: '1.3.101.112',
    commonName: '2.5.4.3',
    organization: '2.5.4.10',
    subjectKeyId: '2.5.29.14',
    keyUsage: '2.5.29.15',
    subjectAltName: '2.5.29.17',
    basicConstraints: '2.5.29.19',
    authorityKeyId: '2.5.29.35',
    extKeyUsage: '2.5.29.37',
    serverAuth: '1.3.6.1.5.5.7.3.1',
    pbes2: '1.2.840.113549.1.5.13',
    pbkdf2: '1.2.840.113549.1.5.12',
    hmacSha1: '1.2.840.113549.2.7',
    hmacSha256: '1.2.840.113549.2.9',
    hmacSha384: '1.2.840.113549.2.10',
    hmacSha512: '1.2.840.113549.2.11',
    aes128Cbc: '2.16.840.1.101.3.4.1.2',
    aes192Cbc: '2.16.840.1.101.3.4.1.22',
    aes256Cbc: '2.16.840.1.101.3.4.1.42',
  };

  const CURVES = {
    'P-256': { oid: '1.2.840.10045.3.1.7', ssh: 'nistp256', hash: 'SHA-256', sigOid: OID.ecdsaSha256 },
    'P-384': { oid: '1.3.132.0.34', ssh: 'nistp384', hash: 'SHA-384', sigOid: OID.ecdsaSha384 },
    'P-521': { oid: '1.3.132.0.35', ssh: 'nistp521', hash: 'SHA-512', sigOid: OID.ecdsaSha512 },
  };

  // Key spec strings used by the UI: "ed25519", "ecdsa-P-256", "rsa-4096", ...
  function webCryptoAlgorithm(spec) {
    if (spec === 'ed25519') return { name: 'Ed25519' };
    if (spec.startsWith('ecdsa-')) return { name: 'ECDSA', namedCurve: spec.slice(6) };
    if (spec.startsWith('rsa-')) {
      return { name: 'RSASSA-PKCS1-v1_5', modulusLength: Number(spec.slice(4)),
        publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' };
    }
    throw new Error(`Unknown key type ${spec}`);
  }

  function describeKey(algorithm) {
    if (algorithm.name === 'Ed25519') return 'Ed25519';
    if (algorithm.name === 'ECDSA') return `ECDSA ${algorithm.namedCurve}`;
    return `RSA ${algorithm.modulusLength}`;
  }

  async function generateKey(spec) {
    if (!subtle) throw new Error('WebCrypto is unavailable. Open this page via https://, localhost or file://.');
    try {
      return await subtle.generateKey(webCryptoAlgorithm(spec), true, ['sign', 'verify']);
    } catch (e) {
      if (spec === 'ed25519') throw new Error('This browser does not support Ed25519 yet. Update it or pick ECDSA.');
      throw e;
    }
  }

  // ---------------------------------------------------------------- OpenSSH

  const u32 = n => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const sshString = data => {
    const b = typeof data === 'string' ? utf8.encode(data) : data;
    return concat(u32(b.length), b);
  };
  const mpint = b => {
    b = stripLeadingZeros(b);
    if (b.length === 1 && b[0] === 0) return u32(0);
    return sshString(b[0] & 0x80 ? concat(Uint8Array.of(0), b) : b);
  };

  // Public key blob and the private-key fields of the openssh-key-v1 format (PROTOCOL.key).
  async function sshKeyParts(keyPair) {
    const jwk = await subtle.exportKey('jwk', keyPair.privateKey);
    const alg = keyPair.privateKey.algorithm;
    if (alg.name === 'Ed25519') {
      const pub = fromBase64Url(jwk.x), seed = fromBase64Url(jwk.d);
      const blob = concat(sshString('ssh-ed25519'), sshString(pub));
      return { name: 'ssh-ed25519', blob, priv: concat(blob, sshString(concat(seed, pub))) };
    }
    if (alg.name === 'ECDSA') {
      const curve = CURVES[alg.namedCurve].ssh, name = `ecdsa-sha2-${curve}`;
      const point = concat(Uint8Array.of(4), fromBase64Url(jwk.x), fromBase64Url(jwk.y));
      const blob = concat(sshString(name), sshString(curve), sshString(point));
      return { name, blob, priv: concat(blob, mpint(fromBase64Url(jwk.d))) };
    }
    const [n, e, d, p, q, qi] = ['n', 'e', 'd', 'p', 'q', 'qi'].map(k => fromBase64Url(jwk[k]));
    return {
      name: 'ssh-rsa',
      blob: concat(sshString('ssh-rsa'), mpint(e), mpint(n)),
      priv: concat(sshString('ssh-rsa'), mpint(n), mpint(e), mpint(d), mpint(qi), mpint(p), mpint(q)),
    };
  }

  async function generateSshKey(spec, comment, passphrase) {
    const keyPair = await generateKey(spec);
    const { name, blob, priv } = await sshKeyParts(keyPair);
    const digest = bytes(await subtle.digest('SHA-256', blob));

    const check = randomBytes(4);
    let section = concat(check, check, priv, sshString(comment));
    const blockSize = passphrase ? 16 : 8;
    const pad = [];
    for (let i = 1; (section.length + pad.length) % blockSize; i++) pad.push(i);
    section = concat(section, Uint8Array.from(pad));

    let cipher = 'none', kdf = 'none', kdfOptions = new Uint8Array(0);
    if (passphrase) {
      // Same as ssh-keygen's default: bcrypt_pbkdf with 16 rounds, aes256-ctr
      const salt = randomBytes(16), rounds = 16;
      const km = await bcryptPbkdf(utf8.encode(passphrase), salt, rounds, 48);
      const aesKey = await subtle.importKey('raw', km.subarray(0, 32), 'AES-CTR', false, ['encrypt']);
      section = bytes(await subtle.encrypt({ name: 'AES-CTR', counter: km.subarray(32), length: 128 }, aesKey, section));
      cipher = 'aes256-ctr';
      kdf = 'bcrypt';
      kdfOptions = concat(sshString(salt), u32(rounds));
    }

    const file = concat(utf8.encode('openssh-key-v1\0'), sshString(cipher), sshString(kdf), sshString(kdfOptions),
      u32(1), sshString(blob), sshString(section));
    return {
      description: describeKey(keyPair.privateKey.algorithm),
      privateKey: toPem('OPENSSH PRIVATE KEY', file, 70),
      publicKey: `${name} ${toBase64(blob)}${comment ? ' ' + comment : ''}\n`,
      fingerprint: 'SHA256:' + toBase64(digest).replace(/=+$/, ''),
    };
  }

  // bcrypt_pbkdf as used by OpenSSH (openbsd-compat/bcrypt_pbkdf.c).
  let blowfishInit;
  function blowfishInitialState() {
    if (!blowfishInit) {
      // Blowfish's initial P-array and S-boxes are the fractional hex digits of pi.
      // pi = 16·atan(1/5) − 4·atan(1/239), computed in fixed point.
      const bits = 1042n * 32n + 64n, one = 1n << bits;
      const atanInv = x => {
        let sum = one / x, term = sum, sign = -1n;
        for (let n = 3n; term; n += 2n, sign = -sign) { term /= x * x; sum += sign * term / n; }
        return sum;
      };
      const frac = 16n * atanInv(5n) - 4n * atanInv(239n) - 3n * one;
      blowfishInit = new Uint32Array(1042);
      for (let i = 0; i < 1042; i++) blowfishInit[i] = Number((frac >> (bits - 32n * BigInt(i + 1))) & 0xffffffffn);
    }
    return blowfishInit;
  }

  function bcryptHash(sha2pass, sha2salt) {
    const init = blowfishInitialState();
    const P = init.slice(0, 18), S = init.slice(18);
    const F = x => ((((S[x >>> 24] + S[256 | ((x >>> 16) & 255)]) ^ S[512 | ((x >>> 8) & 255)]) + S[768 | (x & 255)]) >>> 0);
    const lr = new Uint32Array(2);

    function encipher(block, off) {
      let l = block[off] ^ P[0], r = block[off + 1];
      for (let n = 1; n <= 16; n += 2) {
        r ^= F(l) ^ P[n];
        l ^= F(r) ^ P[n + 1];
      }
      block[off] = r ^ P[17];
      block[off + 1] = l;
    }

    function streamToWord(data, pos) {
      let w = 0;
      for (let i = 0; i < 4; i++) {
        w = (w << 8) | data[pos.j];
        pos.j = (pos.j + 1) % data.length;
      }
      return w;
    }

    // Blowfish_expandstate / Blowfish_expand0state (data === null)
    function expand(data, key) {
      const kp = { j: 0 }, dp = { j: 0 };
      for (let i = 0; i < 18; i++) P[i] ^= streamToWord(key, kp);
      lr[0] = lr[1] = 0;
      for (const box of [P, S]) {
        for (let i = 0; i < box.length; i += 2) {
          if (data) {
            lr[0] ^= streamToWord(data, dp);
            lr[1] ^= streamToWord(data, dp);
          }
          encipher(lr, 0);
          box[i] = lr[0];
          box[i + 1] = lr[1];
        }
      }
    }

    expand(sha2salt, sha2pass);
    for (let i = 0; i < 64; i++) {
      expand(null, sha2salt);
      expand(null, sha2pass);
    }

    const magic = utf8.encode('OxychromaticBlowfishSwatDynamite');
    const cdata = new Uint32Array(8);
    const mp = { j: 0 };
    for (let i = 0; i < 8; i++) cdata[i] = streamToWord(magic, mp);
    for (let i = 0; i < 64; i++) for (let b = 0; b < 8; b += 2) encipher(cdata, b);

    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[4 * i] = cdata[i];
      out[4 * i + 1] = cdata[i] >>> 8;
      out[4 * i + 2] = cdata[i] >>> 16;
      out[4 * i + 3] = cdata[i] >>> 24;
    }
    return out;
  }

  async function bcryptPbkdf(pass, salt, rounds, keyLen) {
    const sha512 = async d => bytes(await subtle.digest('SHA-512', d));
    const stride = Math.ceil(keyLen / 32), amt = Math.ceil(keyLen / stride);
    const key = new Uint8Array(keyLen);
    const sha2pass = await sha512(pass);
    for (let count = 1, remaining = keyLen; remaining > 0; count++) {
      let tmp = bcryptHash(sha2pass, await sha512(concat(salt, u32(count))));
      const out = tmp.slice();
      for (let r = 1; r < rounds; r++) {
        tmp = bcryptHash(sha2pass, await sha512(tmp));
        for (let k = 0; k < 32; k++) out[k] ^= tmp[k];
      }
      let i = 0;
      for (; i < amt; i++) {
        const dest = i * stride + count - 1;
        if (dest >= keyLen) break;
        key[dest] = out[i];
      }
      remaining -= i;
    }
    return key;
  }

  // ---------------------------------------------------------------- PKCS#8

  const PBKDF2_ITERATIONS = 600000;
  const PRF_HASH = { [OID.hmacSha1]: 'SHA-1', [OID.hmacSha256]: 'SHA-256', [OID.hmacSha384]: 'SHA-384', [OID.hmacSha512]: 'SHA-512' };
  const AES_BITS = { [OID.aes128Cbc]: 128, [OID.aes192Cbc]: 192, [OID.aes256Cbc]: 256 };

  async function pbkdf2Key(passphrase, salt, iterations, hash, bits, usage) {
    const base = await subtle.importKey('raw', utf8.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash }, base, { name: 'AES-CBC', length: bits }, false, [usage]);
  }

  // Unencrypted "PRIVATE KEY", or PBES2/PBKDF2-SHA256/AES-256-CBC "ENCRYPTED PRIVATE KEY" when a passphrase is given.
  async function exportPrivateKey(privateKey, passphrase) {
    const pkcs8 = bytes(await subtle.exportKey('pkcs8', privateKey));
    if (!passphrase) return toPem('PRIVATE KEY', pkcs8);
    const salt = randomBytes(16), iv = randomBytes(16);
    const aes = await pbkdf2Key(passphrase, salt, PBKDF2_ITERATIONS, 'SHA-256', 256, 'encrypt');
    const data = bytes(await subtle.encrypt({ name: 'AES-CBC', iv }, aes, pkcs8));
    const algId = seq(oid(OID.pbes2), seq(
      seq(oid(OID.pbkdf2), seq(octets(salt), smallInt(PBKDF2_ITERATIONS), seq(oid(OID.hmacSha256), derNull()))),
      seq(oid(OID.aes256Cbc), octets(iv))));
    return toPem('ENCRYPTED PRIVATE KEY', seq(algId, octets(data)));
  }

  async function decryptPkcs8(der, passphrase) {
    if (!passphrase) throw new Error('The private key is encrypted. Enter its passphrase.');
    const [algId, data] = children(parseDer(der));
    const [scheme, params] = children(algId);
    if (oidToString(scheme) !== OID.pbes2) throw new Error('Unsupported key encryption (only PBES2 is supported).');
    const [kdf, encScheme] = children(params);
    const [kdfOid, kdfParams] = children(kdf);
    if (oidToString(kdfOid) !== OID.pbkdf2) throw new Error('Unsupported key derivation (only PBKDF2 is supported).');
    const kp = children(kdfParams);
    const salt = kp[0].content;
    const iterations = kp[1].content.reduce((n, b) => n * 256 + b, 0);
    const prf = kp.find((n, i) => i >= 2 && n.tag === 0x30);
    const hash = PRF_HASH[prf ? oidToString(children(prf)[0]) : OID.hmacSha1];
    const [cipherOid, iv] = children(encScheme);
    const bits = AES_BITS[oidToString(cipherOid)];
    if (!hash || !bits) throw new Error('Unsupported key encryption parameters.');
    const aes = await pbkdf2Key(passphrase, salt, iterations, hash, bits, 'decrypt');
    try {
      return bytes(await subtle.decrypt({ name: 'AES-CBC', iv: iv.content }, aes, data.content));
    } catch {
      throw new Error('Wrong passphrase for the private key.');
    }
  }

  // Accepts PKCS#8 (plain or encrypted), PKCS#1 RSA and SEC1 EC keys in PEM form.
  async function importPrivateKey(pemText, passphrase) {
    const block = parsePem(pemText).find(b => /PRIVATE KEY$/.test(b.label));
    if (!block) throw new Error('No PEM private key found in the key file.');
    if (/ENCRYPTED/.test(block.headers)) {
      throw new Error('Legacy encrypted PEM keys are not supported. Convert it first: ' +
        'openssl pkey -in old.key -out new.key -aes256');
    }

    let pkcs8;
    switch (block.label) {
      case 'PRIVATE KEY': pkcs8 = block.der; break;
      case 'ENCRYPTED PRIVATE KEY': pkcs8 = await decryptPkcs8(block.der, passphrase); break;
      case 'RSA PRIVATE KEY':
        pkcs8 = seq(smallInt(0), seq(oid(OID.rsaEncryption), derNull()), octets(block.der));
        break;
      case 'EC PRIVATE KEY': {
        const params = children(parseDer(block.der)).find(n => n.tag === 0xa0);
        if (!params) throw new Error('EC private key does not name its curve.');
        pkcs8 = seq(smallInt(0), seq(oid(OID.ecPublicKey), children(params)[0].raw), octets(block.der));
        break;
      }
      default: throw new Error(`Unsupported key format: ${block.label}`);
    }

    const algorithm = algorithmFromAlgId(children(parseDer(pkcs8))[1]);
    return subtle.importKey('pkcs8', pkcs8, algorithm, true, ['sign']);
  }

  // WebCrypto signing algorithm for an AlgorithmIdentifier from a PKCS#8 or SPKI structure.
  function algorithmFromAlgId(algId) {
    const [id, params] = children(algId);
    switch (oidToString(id)) {
      case OID.rsaEncryption: return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      case OID.ed25519: return { name: 'Ed25519' };
      case OID.ecPublicKey: {
        const curveOid = params && oidToString(params);
        const curve = Object.keys(CURVES).find(c => CURVES[c].oid === curveOid);
        if (curve) return { name: 'ECDSA', namedCurve: curve };
        throw new Error('Unsupported EC curve.');
      }
      default: throw new Error('Unsupported key algorithm.');
    }
  }

  // ---------------------------------------------------------------- X.509

  function signatureAlgorithm(key) {
    const alg = key.algorithm;
    if (alg.name === 'Ed25519') return { id: seq(oid(OID.ed25519)), params: { name: 'Ed25519' } };
    if (alg.name === 'ECDSA') {
      const c = CURVES[alg.namedCurve];
      return { id: seq(oid(c.sigOid)), params: { name: 'ECDSA', hash: c.hash }, ecdsa: true };
    }
    return { id: seq(oid(OID.sha256WithRSA), derNull()), params: { name: 'RSASSA-PKCS1-v1_5' } };
  }

  // RFC 5280 key identifier: SHA-1 of the subjectPublicKey bits.
  async function keyIdentifier(spki) {
    const keyBits = children(parseDer(spki))[1].content.subarray(1);
    return bytes(await subtle.digest('SHA-1', keyBits));
  }

  function distinguishedName(commonName, organization) {
    const rdn = (id, value) => set(seq(oid(id), utf8String(value)));
    return seq(...(organization ? [rdn(OID.organization, organization)] : []), rdn(OID.commonName, commonName));
  }

  const extension = (id, critical, value) => seq(oid(id), ...(critical ? [boolTrue()] : []), octets(value));

  // KeyUsage BIT STRING (bit 0 = digitalSignature ... bit 6 = cRLSign), minimally encoded.
  function keyUsage(...bitsSet) {
    let v = 0;
    for (const b of bitsSet) v |= 0x80 >> b;
    let unused = 0;
    while (!((v >> unused) & 1)) unused++;
    return tlv(0x03, Uint8Array.of(unused, v));
  }
  const KU = { digitalSignature: 0, keyEncipherment: 2, keyCertSign: 5, cRLSign: 6 };

  function serialNumber() {
    const s = randomBytes(16);
    s[0] = (s[0] & 0x7f) | 0x40; // positive, fixed length
    return s;
  }

  async function signCertificate({ subject, issuer, spki, signer, notBefore, notAfter, extensions }) {
    const sig = signatureAlgorithm(signer);
    const tbs = seq(explicit(0, smallInt(2)), integer(serialNumber()), sig.id, issuer,
      seq(time(notBefore), time(notAfter)), subject, spki, explicit(3, seq(...extensions)));
    let signature = bytes(await subtle.sign(sig.params, signer, tbs));
    if (sig.ecdsa) {
      // WebCrypto returns r||s; X.509 wants SEQUENCE { INTEGER r, INTEGER s }
      const half = signature.length / 2;
      signature = seq(integer(signature.subarray(0, half)), integer(signature.subarray(half)));
    }
    return seq(tbs, sig.id, bitString(signature));
  }

  const addDays = (date, days) => new Date(date.getTime() + days * 86400000);

  async function createCA({ keySpec, commonName, organization, days }) {
    const keyPair = await generateKey(keySpec);
    const spki = bytes(await subtle.exportKey('spki', keyPair.publicKey));
    const keyId = await keyIdentifier(spki);
    const name = distinguishedName(commonName, organization);
    const now = new Date();
    const der = await signCertificate({
      subject: name, issuer: name, spki, signer: keyPair.privateKey,
      notBefore: now, notAfter: addDays(now, days),
      extensions: [
        extension(OID.basicConstraints, true, seq(boolTrue(), smallInt(0))),
        extension(OID.keyUsage, true, keyUsage(KU.digitalSignature, KU.keyCertSign, KU.cRLSign)),
        extension(OID.subjectKeyId, false, octets(keyId)),
      ],
    });
    return { privateKey: keyPair.privateKey, der, ...certificateInfo(der) };
  }

  // Split "example.com, *.example.com 10.0.0.1 ::1" into SAN entries.
  function parseSubjectAltNames(input) {
    const names = input.split(/[\s,]+/).filter(Boolean);
    if (!names.length) throw new Error('Enter at least one hostname or IP address.');
    return names.map(raw => {
      const name = raw.replace(/^\[(.*)\]$/, '$1');
      const v4 = name.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      if (v4) {
        const parts = v4.slice(1).map(Number);
        if (parts.every(p => p <= 255)) return { type: 'ip', value: name, bytes: Uint8Array.from(parts) };
        throw new Error(`Invalid IPv4 address: ${raw}`);
      }
      if (name.includes(':')) {
        const v6 = parseIPv6(name);
        if (v6) return { type: 'ip', value: name, bytes: v6 };
        throw new Error(`Invalid IPv6 address: ${raw}`);
      }
      const dns = name.toLowerCase().replace(/\.$/, '');
      const label = '[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?';
      if (!new RegExp(`^(\\*\\.)?(${label}\\.)*${label}$`).test(dns) || dns.length > 253) {
        throw new Error(`Invalid hostname: ${raw} (use punycode for international names)`);
      }
      return { type: 'dns', value: dns };
    });
  }

  function parseIPv6(s) {
    const halves = s.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const fill = 8 - head.length - tail.length;
    if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
    const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
    if (!groups.every(g => /^[0-9a-f]{1,4}$/i.test(g))) return null;
    const out = new Uint8Array(16);
    groups.forEach((g, i) => { const v = parseInt(g, 16); out[2 * i] = v >> 8; out[2 * i + 1] = v & 255; });
    return out;
  }

  async function createServerCertificate(ca, { keySpec, names, days }) {
    const keyPair = await generateKey(keySpec);
    const spki = bytes(await subtle.exportKey('spki', keyPair.publicKey));
    const san = seq(...names.map(n => n.type === 'dns' ? tlv(0x82, utf8.encode(n.value)) : tlv(0x87, n.bytes)));
    const usage = keyPair.privateKey.algorithm.name === 'RSASSA-PKCS1-v1_5'
      ? keyUsage(KU.digitalSignature, KU.keyEncipherment) : keyUsage(KU.digitalSignature);
    const now = new Date();
    const der = await signCertificate({
      subject: distinguishedName(names[0].value), issuer: ca.subject, spki, signer: ca.privateKey,
      notBefore: now, notAfter: addDays(now, days),
      extensions: [
        extension(OID.basicConstraints, true, seq()),
        extension(OID.keyUsage, true, usage),
        extension(OID.extKeyUsage, false, seq(oid(OID.serverAuth))),
        extension(OID.subjectAltName, false, san),
        extension(OID.subjectKeyId, false, octets(await keyIdentifier(spki))),
        extension(OID.authorityKeyId, false, seq(tlv(0x80, ca.keyId || await keyIdentifier(ca.spki)))),
      ],
    });
    return { privateKey: keyPair.privateKey, der, ...certificateInfo(der) };
  }

  // The fields of a certificate this tool cares about.
  function certificateInfo(der) {
    const [tbs] = children(parseDer(der));
    const f = children(tbs);
    const i = f[0].tag === 0xa0 ? 1 : 0;
    const [serial, , , validity, subject, spki] = f.slice(i);
    const [notBefore, notAfter] = children(validity).map(parseTime);

    let isCA = false, keyId = null;
    const exts = f.find(n => n.tag === 0xa3);
    for (const ext of exts ? children(children(exts)[0]) : []) {
      const parts = children(ext);
      const id = oidToString(parts[0]);
      const value = parseDer(parts[parts.length - 1].content);
      if (id === OID.basicConstraints) isCA = children(value).some(n => n.tag === 0x01 && n.content[0]);
      if (id === OID.subjectKeyId) keyId = value.content;
    }

    let commonName = '';
    for (const rdn of children(subject)) {
      for (const atv of children(rdn)) {
        const [type, value] = children(atv);
        if (oidToString(type) === OID.commonName) commonName = new TextDecoder().decode(value.content);
      }
    }

    return {
      subject: subject.raw, spki: spki.raw, keyId, isCA, commonName, notBefore, notAfter,
      serial: Array.from(serial.content, b => b.toString(16).padStart(2, '0')).join(':'),
      keyDescription: describeSpki(spki.raw),
    };
  }

  function describeSpki(spki) {
    const [algId, keyBits] = children(parseDer(spki));
    const alg = algorithmFromAlgId(algId);
    if (alg.name !== 'RSASSA-PKCS1-v1_5') return describeKey(alg);
    const modulus = children(parseDer(keyBits.content.subarray(1)))[0].content;
    return `RSA ${stripLeadingZeros(modulus).length * 8}`;
  }

  async function loadCA(certPem, keyPem, passphrase) {
    const certBlock = parsePem(certPem).find(b => b.label === 'CERTIFICATE');
    if (!certBlock) throw new Error('No PEM certificate found in the certificate file.');
    const info = certificateInfo(certBlock.der);
    if (!info.isCA) throw new Error('This certificate is not a CA certificate (basicConstraints CA:FALSE).');

    const privateKey = await importPrivateKey(keyPem, passphrase);
    const certAlg = algorithmFromAlgId(children(parseDer(info.spki))[0]);
    if (certAlg.name !== privateKey.algorithm.name || certAlg.namedCurve !== privateKey.algorithm.namedCurve) {
      throw new Error('The private key does not belong to this certificate.');
    }
    const publicKey = await subtle.importKey('spki', info.spki, certAlg, true, ['verify']);
    const [pub, priv] = await Promise.all([publicKey, privateKey].map(k => subtle.exportKey('jwk', k)));
    if (['n', 'x', 'y'].some(k => pub[k] !== priv[k])) {
      throw new Error('The private key does not belong to this certificate.');
    }
    return { privateKey, der: certBlock.der, ...info };
  }

  // ---------------------------------------------------------------- misc

  // 24 characters from a 57-symbol alphabet without look-alikes: ~140 bits.
  function randomPassphrase() {
    const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const limit = 256 - (256 % alphabet.length);
    let out = '';
    while (out.length < 24) {
      for (const b of randomBytes(32)) {
        if (b < limit && out.length < 24) out += alphabet[b % alphabet.length];
      }
    }
    return out.match(/.{6}/g).join('-');
  }

  const certificatePem = der => toPem('CERTIFICATE', der);

  return {
    generateSshKey, createCA, loadCA, createServerCertificate, parseSubjectAltNames,
    exportPrivateKey, certificatePem, randomPassphrase,
    // exposed for tests
    bcryptPbkdf, parsePem, importPrivateKey,
  };
})();
