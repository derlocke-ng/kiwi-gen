// Kiwi crypto core: OpenSSH keys and certificates, X.509, PKCS#8/#10/#12 on top of WebCrypto.
// No DOM access in here, so it can be exercised outside the browser.
const Kiwi = (() => {
  'use strict';

  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  const utf8 = new TextEncoder();
  const decodeUtf8 = b => new TextDecoder().decode(b);

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
  const toBase64Url = b => toBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const fromBase64Url = s => fromBase64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const toHex = (b, sep = ':') => Array.from(b, x => x.toString(16).padStart(2, '0').toUpperCase()).join(sep);

  function equalBytes(a, b) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }

  function stripLeadingZeros(b) {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
  }

  function leftPad(b, size) {
    b = stripLeadingZeros(b);
    return b.length >= size ? b : concat(new Uint8Array(size - b.length), b);
  }

  const toBigInt = b => b.length ? BigInt('0x' + toHex(b, '')) : 0n;
  function fromBigInt(n) {
    const h = n.toString(16);
    return Uint8Array.from((h.length % 2 ? '0' + h : h).match(/../g), x => parseInt(x, 16));
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
    if (off + 2 > der.length) throw new Error('Truncated DER');
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

  // Parses a whole DER document, rejecting trailing garbage.
  function parseDocument(der) {
    const node = parseDer(der);
    if (node.end !== der.length || node.tag !== 0x30) throw new Error('Not a DER structure');
    return node;
  }

  function oidToString(node) {
    const b = node.content, arcs = [Math.floor(b[0] / 40), b[0] % 40];
    for (let i = 1, v = 0; i < b.length; i++) {
      v = v * 128 + (b[i] & 0x7f);
      if (!(b[i] & 0x80)) { arcs.push(v); v = 0; }
    }
    return arcs.join('.');
  }

  const intValue = node => node.content.reduce((n, b) => n * 256 + b, 0);

  function parseTime(node) {
    let s = decodeUtf8(node.content);
    if (node.tag === 0x17) s = (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s;
    return new Date(Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14)));
  }

  function decodeString(node) {
    if (node.tag !== 0x1e) return decodeUtf8(node.content); // BMPString is UTF-16BE
    let s = '';
    for (let i = 0; i + 1 < node.content.length; i += 2) s += String.fromCharCode((node.content[i] << 8) | node.content[i + 1]);
    return s;
  }

  // ---------------------------------------------------------------- algorithms

  const OID = {
    rsaEncryption: '1.2.840.113549.1.1.1',
    sha1WithRSA: '1.2.840.113549.1.1.5',
    rsassaPss: '1.2.840.113549.1.1.10',
    sha256WithRSA: '1.2.840.113549.1.1.11',
    sha384WithRSA: '1.2.840.113549.1.1.12',
    sha512WithRSA: '1.2.840.113549.1.1.13',
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
    clientAuth: '1.3.6.1.5.5.7.3.2',
    extensionRequest: '1.2.840.113549.1.9.14',
    localKeyId: '1.2.840.113549.1.9.21',
    x509Certificate: '1.2.840.113549.1.9.22.1',
    data: '1.2.840.113549.1.7.1',
    shroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
    certBag: '1.2.840.113549.1.12.10.1.3',
    sha256: '2.16.840.1.101.3.4.2.1',
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
    'P-256': { oid: '1.2.840.10045.3.1.7', ssh: 'nistp256', size: 32, hash: 'SHA-256', sigOid: OID.ecdsaSha256 },
    'P-384': { oid: '1.3.132.0.34', ssh: 'nistp384', size: 48, hash: 'SHA-384', sigOid: OID.ecdsaSha384 },
    'P-521': { oid: '1.3.132.0.35', ssh: 'nistp521', size: 66, hash: 'SHA-512', sigOid: OID.ecdsaSha512 },
  };
  const curveBySsh = name => Object.keys(CURVES).find(c => CURVES[c].ssh === name);

  const RSA = 'RSASSA-PKCS1-v1_5';
  const SIGNATURES = {
    [OID.sha1WithRSA]: { label: 'SHA1 with RSA', key: RSA, hash: 'SHA-1' },
    [OID.sha256WithRSA]: { label: 'SHA256 with RSA', key: RSA, hash: 'SHA-256' },
    [OID.sha384WithRSA]: { label: 'SHA384 with RSA', key: RSA, hash: 'SHA-384' },
    [OID.sha512WithRSA]: { label: 'SHA512 with RSA', key: RSA, hash: 'SHA-512' },
    [OID.rsassaPss]: { label: 'RSA-PSS' },
    [OID.ecdsaSha256]: { label: 'ECDSA with SHA256', key: 'ECDSA', hash: 'SHA-256' },
    [OID.ecdsaSha384]: { label: 'ECDSA with SHA384', key: 'ECDSA', hash: 'SHA-384' },
    [OID.ecdsaSha512]: { label: 'ECDSA with SHA512', key: 'ECDSA', hash: 'SHA-512' },
    [OID.ed25519]: { label: 'Ed25519', key: 'Ed25519' },
  };

  // Key spec strings used by the UI: "ed25519", "ecdsa-P-256", "rsa-4096", ...
  function webCryptoAlgorithm(spec) {
    if (spec === 'ed25519') return { name: 'Ed25519' };
    if (spec.startsWith('ecdsa-')) return { name: 'ECDSA', namedCurve: spec.slice(6) };
    if (spec.startsWith('rsa-')) {
      return { name: RSA, modulusLength: Number(spec.slice(4)), publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' };
    }
    throw new Error(`Unknown key type ${spec}`);
  }

  function requireWebCrypto() {
    if (!subtle) throw new Error('WebCrypto is unavailable. Open this page via https://, localhost or file://.');
  }

  async function generateKey(spec) {
    requireWebCrypto();
    try {
      return await subtle.generateKey(webCryptoAlgorithm(spec), true, ['sign', 'verify']);
    } catch (e) {
      if (spec === 'ed25519') throw new Error('This browser does not support Ed25519 yet. Update it or pick ECDSA.');
      throw e;
    }
  }

  // WebCrypto algorithm for an AlgorithmIdentifier from a PKCS#8 or SPKI structure.
  function algorithmFromAlgId(algId) {
    const [id, params] = children(algId);
    switch (oidToString(id)) {
      case OID.rsaEncryption: return { name: RSA, hash: 'SHA-256' };
      case OID.ed25519: return { name: 'Ed25519' };
      case OID.ecPublicKey: {
        const curveOid = params && params.tag === 0x06 && oidToString(params);
        const curve = Object.keys(CURVES).find(c => CURVES[c].oid === curveOid);
        if (curve) return { name: 'ECDSA', namedCurve: curve };
        throw new Error('Unsupported EC curve.');
      }
      default: throw new Error('Unsupported key algorithm.');
    }
  }

  function describeSpki(spki) {
    const [algId, keyBits] = children(parseDer(spki));
    const alg = algorithmFromAlgId(algId);
    if (alg.name === 'Ed25519') return 'Ed25519';
    if (alg.name === 'ECDSA') return `ECDSA ${alg.namedCurve}`;
    const modulus = children(parseDer(keyBits.content.subarray(1)))[0].content;
    return `RSA ${toBigInt(modulus).toString(2).length}`;
  }

  function importPrivateJwk(jwk, hash = 'SHA-256') {
    const { alg, key_ops, ext, ...clean } = jwk;
    const algorithm = clean.kty === 'OKP' ? { name: 'Ed25519' }
      : clean.kty === 'EC' ? { name: 'ECDSA', namedCurve: clean.crv } : { name: RSA, hash };
    return subtle.importKey('jwk', clean, algorithm, true, ['sign']);
  }

  // SubjectPublicKeyInfo for a private CryptoKey.
  async function publicSpki(privateKey) {
    const { d, p, q, dp, dq, qi, alg, key_ops, ext, ...pub } = await subtle.exportKey('jwk', privateKey);
    const key = await subtle.importKey('jwk', pub, privateKey.algorithm, true, ['verify']);
    return bytes(await subtle.exportKey('spki', key));
  }

  // DER ECDSA signature -> r||s as WebCrypto expects.
  function derToP1363(der, size) {
    const [r, s] = children(parseDer(der));
    return concat(leftPad(r.content, size), leftPad(s.content, size));
  }

  // Verifies an X.509-style signature; null when the algorithm can't be checked here.
  async function verifySignature(spki, sigOid, data, signature) {
    const s = SIGNATURES[sigOid];
    if (!s || !s.key) return null;
    try {
      const keyAlg = algorithmFromAlgId(children(parseDer(spki))[0]);
      if (keyAlg.name !== s.key) return false;
      let importAlg = keyAlg, verifyAlg = { name: s.key };
      if (s.key === RSA) importAlg = { name: RSA, hash: s.hash };
      if (s.key === 'ECDSA') {
        verifyAlg = { name: 'ECDSA', hash: s.hash };
        signature = derToP1363(signature, CURVES[keyAlg.namedCurve].size);
      }
      const key = await subtle.importKey('spki', spki, importAlg, false, ['verify']);
      return await subtle.verify(verifyAlg, key, signature, data);
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------- SSH wire format

  const u32 = n => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  function u64(n) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n));
    return b;
  }
  const sshString = data => {
    const b = typeof data === 'string' ? utf8.encode(data) : data;
    return concat(u32(b.length), b);
  };
  const mpint = b => {
    b = stripLeadingZeros(b);
    if (b.length === 1 && b[0] === 0) return u32(0);
    return sshString(b[0] & 0x80 ? concat(Uint8Array.of(0), b) : b);
  };

  function sshReader(buf) {
    let off = 0;
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const need = n => { if (off + n > buf.length) throw new Error('Truncated SSH data'); };
    const r = {
      u32() { need(4); off += 4; return view.getUint32(off - 4); },
      u64() { need(8); off += 8; return view.getBigUint64(off - 8); },
      string() { const n = r.u32(); need(n); off += n; return buf.subarray(off - n, off); },
      text() { return decodeUtf8(r.string()); },
      get offset() { return off; },
      get done() { return off >= buf.length; },
    };
    return r;
  }

  // Number of key fields after the type name in a public key blob.
  const SSH_KEY_FIELDS = {
    'ssh-ed25519': 1, 'ssh-rsa': 2,
    'ecdsa-sha2-nistp256': 2, 'ecdsa-sha2-nistp384': 2, 'ecdsa-sha2-nistp521': 2,
    'sk-ssh-ed25519@openssh.com': 2, 'sk-ecdsa-sha2-nistp256@openssh.com': 3,
  };
  const CERT_SUFFIX = '-cert-v01@openssh.com';
  const certTypeName = name => name.replace(/@openssh\.com$/, '') + CERT_SUFFIX;
  const certBaseName = name => {
    const base = name.slice(0, -CERT_SUFFIX.length);
    return base.startsWith('sk-') ? base + '@openssh.com' : base;
  };

  function spkiToSshBlob(spki) {
    const [algId, bits] = children(parseDer(spki));
    const alg = algorithmFromAlgId(algId);
    const key = bits.content.subarray(1);
    if (alg.name === 'Ed25519') return concat(sshString('ssh-ed25519'), sshString(key));
    if (alg.name === 'ECDSA') {
      const c = CURVES[alg.namedCurve].ssh;
      return concat(sshString(`ecdsa-sha2-${c}`), sshString(c), sshString(key));
    }
    const [n, e] = children(parseDer(key));
    return concat(sshString('ssh-rsa'), mpint(e.content), mpint(n.content));
  }

  // SubjectPublicKeyInfo for an SSH public key blob, or null for types X.509 can't express.
  function sshBlobToSpki(blob) {
    const r = sshReader(blob);
    const name = r.text();
    if (name === 'ssh-ed25519') return seq(seq(oid(OID.ed25519)), bitString(r.string()));
    if (name === 'ssh-rsa') {
      const e = r.string(), n = r.string();
      return seq(seq(oid(OID.rsaEncryption), derNull()), bitString(seq(integer(n), integer(e))));
    }
    if (name.startsWith('ecdsa-sha2-')) {
      const curve = curveBySsh(r.text());
      if (!curve) return null;
      return seq(seq(oid(OID.ecPublicKey), oid(CURVES[curve].oid)), bitString(r.string()));
    }
    return null;
  }

  function describeSshBlob(blob) {
    const name = sshReader(blob).text();
    if (name === 'sk-ssh-ed25519@openssh.com') return 'Ed25519 security key';
    if (name === 'sk-ecdsa-sha2-nistp256@openssh.com') return 'ECDSA P-256 security key';
    const spki = sshBlobToSpki(blob);
    return spki ? describeSpki(spki) : name;
  }

  async function sshFingerprint(blob) {
    return 'SHA256:' + toBase64(bytes(await subtle.digest('SHA-256', blob))).replace(/=+$/, '');
  }

  const SSH_LINE = /(?:^|\s)((?:sk-)?(?:ssh|ecdsa)-[\w@.-]+)\s+(AAAA[A-Za-z0-9+/]+={0,3})(?:[ \t]+([^\n]*))?/;

  function parseSshPublicKey(line) {
    const m = SSH_LINE.exec(line.trim());
    if (!m) throw new Error('Not an SSH public key. Expected something like "ssh-ed25519 AAAA... comment".');
    const blob = fromBase64(m[2]);
    const name = sshReader(blob).text();
    if (name !== m[1]) throw new Error('SSH public key type does not match its contents.');
    return { name, blob, comment: (m[3] || '').trim() };
  }

  const sshPublicKeyLine = (blob, comment) =>
    `${sshReader(blob).text()} ${toBase64(blob)}${comment ? ' ' + comment : ''}\n`;

  // ---------------------------------------------------------------- OpenSSH private keys

  // Public key blob and private-key fields of the openssh-key-v1 format (PROTOCOL.key).
  async function sshKeyParts(privateKey) {
    const jwk = await subtle.exportKey('jwk', privateKey);
    const alg = privateKey.algorithm;
    if (alg.name === 'Ed25519') {
      const pub = fromBase64Url(jwk.x), seed = fromBase64Url(jwk.d);
      const blob = concat(sshString('ssh-ed25519'), sshString(pub));
      return { blob, priv: concat(blob, sshString(concat(seed, pub))) };
    }
    if (alg.name === 'ECDSA') {
      const curve = CURVES[alg.namedCurve].ssh;
      const point = concat(Uint8Array.of(4), fromBase64Url(jwk.x), fromBase64Url(jwk.y));
      const blob = concat(sshString(`ecdsa-sha2-${curve}`), sshString(curve), sshString(point));
      return { blob, priv: concat(blob, mpint(fromBase64Url(jwk.d))) };
    }
    const [n, e, d, p, q, qi] = ['n', 'e', 'd', 'p', 'q', 'qi'].map(k => fromBase64Url(jwk[k]));
    return {
      blob: concat(sshString('ssh-rsa'), mpint(e), mpint(n)),
      priv: concat(sshString('ssh-rsa'), mpint(n), mpint(e), mpint(d), mpint(qi), mpint(p), mpint(q)),
    };
  }

  async function encodeOpenSshPrivateKey(privateKey, comment, passphrase) {
    const { blob, priv } = await sshKeyParts(privateKey);
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
    return { pem: toPem('OPENSSH PRIVATE KEY', file, 70), blob };
  }

  async function decodeOpenSshPrivateKey(der, passphrase) {
    if (decodeUtf8(der.subarray(0, 15)) !== 'openssh-key-v1\0') throw new Error('Not an OpenSSH private key.');
    const r = sshReader(der.subarray(15));
    const cipher = r.text(), kdf = r.text(), kdfOptions = r.string();
    if (r.u32() !== 1) throw new Error('OpenSSH key files holding several keys are not supported.');
    r.string(); // public key blob, repeated in the private section
    let section = r.string();
    const encrypted = cipher !== 'none';
    if (encrypted) {
      const keyLen = { 'aes128-ctr': 16, 'aes192-ctr': 24, 'aes256-ctr': 32 }[cipher];
      if (!keyLen || kdf !== 'bcrypt') throw new Error(`Unsupported OpenSSH key encryption: ${cipher}`);
      if (!passphrase) throw new Error('The private key is encrypted. Enter its passphrase.');
      const o = sshReader(kdfOptions);
      const salt = o.string(), rounds = o.u32();
      const km = await bcryptPbkdf(utf8.encode(passphrase), salt, rounds, keyLen + 16);
      const aesKey = await subtle.importKey('raw', km.subarray(0, keyLen), 'AES-CTR', false, ['decrypt']);
      section = bytes(await subtle.decrypt({ name: 'AES-CTR', counter: km.subarray(keyLen), length: 128 }, aesKey, section));
    }

    const p = sshReader(section);
    if (p.u32() !== p.u32()) throw new Error(encrypted ? 'Wrong passphrase for the private key.' : 'Corrupt OpenSSH private key.');
    const type = p.text();
    let jwk;
    if (type === 'ssh-ed25519') {
      const pub = p.string(), both = p.string();
      jwk = { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(pub), d: toBase64Url(both.subarray(0, 32)) };
    } else if (type.startsWith('ecdsa-sha2-')) {
      const curve = curveBySsh(p.text());
      if (!curve) throw new Error(`Unsupported OpenSSH key type: ${type}`);
      const size = CURVES[curve].size, point = p.string(), d = p.string();
      jwk = { kty: 'EC', crv: curve, x: toBase64Url(point.subarray(1, 1 + size)),
        y: toBase64Url(point.subarray(1 + size)), d: toBase64Url(leftPad(d, size)) };
    } else if (type === 'ssh-rsa') {
      const [n, e, d, qi, pp, q] = Array.from({ length: 6 }, () => stripLeadingZeros(p.string()));
      const D = toBigInt(d);
      const dp = fromBigInt(D % (toBigInt(pp) - 1n)), dq = fromBigInt(D % (toBigInt(q) - 1n));
      jwk = { kty: 'RSA', ...Object.fromEntries(Object.entries({ n, e, d, p: pp, q, dp, dq, qi })
        .map(([k, v]) => [k, toBase64Url(v)])) };
    } else {
      throw new Error(`Unsupported OpenSSH key type: ${type}`);
    }
    return { privateKey: await importPrivateJwk(jwk), comment: p.text(), encrypted };
  }

  async function generateSshKey(spec, comment, passphrase) {
    const { privateKey } = await generateKey(spec);
    const { pem, blob } = await encodeOpenSshPrivateKey(privateKey, comment, passphrase);
    return {
      key: privateKey,
      blob,
      description: describeSshBlob(blob),
      privateKey: pem,
      publicKey: sshPublicKeyLine(blob, comment),
      fingerprint: await sshFingerprint(blob),
    };
  }

  // ---------------------------------------------------------------- bcrypt_pbkdf

  // As used by OpenSSH (openbsd-compat/bcrypt_pbkdf.c).
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

  // ---------------------------------------------------------------- SSH certificates (PROTOCOL.certkeys)

  // ssh-keygen's default extensions for user certificates, in the required sorted order.
  const USER_CERT_EXTENSIONS = ['permit-X11-forwarding', 'permit-agent-forwarding', 'permit-port-forwarding',
    'permit-pty', 'permit-user-rc'];
  const FOREVER = 0xffffffffffffffffn;

  async function sshSign(privateKey, data) {
    const alg = privateKey.algorithm;
    if (alg.name === 'Ed25519') {
      return concat(sshString('ssh-ed25519'), sshString(bytes(await subtle.sign('Ed25519', privateKey, data))));
    }
    if (alg.name === 'ECDSA') {
      const c = CURVES[alg.namedCurve];
      const sig = bytes(await subtle.sign({ name: 'ECDSA', hash: c.hash }, privateKey, data));
      const half = sig.length / 2;
      return concat(sshString(`ecdsa-sha2-${c.ssh}`),
        sshString(concat(mpint(sig.subarray(0, half)), mpint(sig.subarray(half)))));
    }
    // RSA keys are bound to one hash in WebCrypto; rsa-sha2-512 needs a SHA-512 one.
    const key = await importPrivateJwk(await subtle.exportKey('jwk', privateKey), 'SHA-512');
    return concat(sshString('rsa-sha2-512'), sshString(bytes(await subtle.sign(RSA, key, data))));
  }

  async function sshVerify(keyBlob, data, sigBlob) {
    try {
      const r = sshReader(sigBlob);
      const sigType = r.text();
      let sig = r.string();
      const spki = sshBlobToSpki(keyBlob);
      const keyAlg = algorithmFromAlgId(children(parseDer(spki))[0]);
      let importAlg = keyAlg, verifyAlg = { name: keyAlg.name };
      if (keyAlg.name === 'ECDSA') {
        const c = CURVES[keyAlg.namedCurve], s = sshReader(sig);
        sig = concat(leftPad(s.string(), c.size), leftPad(s.string(), c.size));
        verifyAlg = { name: 'ECDSA', hash: c.hash };
      }
      if (keyAlg.name === RSA) {
        const hash = { 'rsa-sha2-512': 'SHA-512', 'rsa-sha2-256': 'SHA-256', 'ssh-rsa': 'SHA-1' }[sigType];
        importAlg = { name: RSA, hash };
      }
      const key = await subtle.importKey('spki', spki, importAlg, false, ['verify']);
      return await subtle.verify(verifyAlg, key, sig, data);
    } catch {
      return false;
    }
  }

  async function createSshCertificate(ca, { publicKey, certType, keyId, principals, days }) {
    const { name, blob, comment } = parseSshPublicKey(publicKey);
    if (name.endsWith(CERT_SUFFIX)) throw new Error('That is already a certificate. Paste the plain public key.');
    if (!SSH_KEY_FIELDS[name]) throw new Error(`Unsupported key type: ${name}`);

    const keyFields = blob.subarray(4 + utf8.encode(name).length);
    const now = Math.floor(Date.now() / 1000);
    const validAfter = BigInt(now - 300); // allow 5 minutes of clock skew
    const validBefore = days ? BigInt(now + days * 86400) : FOREVER;
    const serial = new DataView(randomBytes(8).buffer).getBigUint64(0);
    const extensions = certType === 'user'
      ? USER_CERT_EXTENSIONS.map(e => concat(sshString(e), sshString(new Uint8Array(0)))) : [];
    const empty = sshString(new Uint8Array(0));

    const body = concat(sshString(certTypeName(name)), sshString(randomBytes(32)), keyFields, u64(serial),
      u32(certType === 'user' ? 1 : 2), sshString(keyId), sshString(concat(...principals.map(sshString))),
      u64(validAfter), u64(validBefore), empty, sshString(concat(...extensions)), empty, sshString(ca.blob));
    const cert = concat(body, sshString(await sshSign(ca.privateKey, body)));
    return { certificate: sshPublicKeyLine(cert, comment), ...(await parseSshCertificate(cert)) };
  }

  async function parseSshCertificate(cert) {
    const r = sshReader(cert);
    const name = r.text();
    r.string(); // nonce
    const baseName = certBaseName(name);
    const fields = Array.from({ length: SSH_KEY_FIELDS[baseName] || 0 }, () => r.string());
    if (!fields.length) throw new Error(`Unsupported certificate type: ${name}`);
    const keyBlob = concat(sshString(baseName), ...fields.map(sshString));
    const serial = r.u64(), type = r.u32() === 1 ? 'user' : 'host', keyId = r.text();
    const principals = [];
    for (const pr = sshReader(r.string()); !pr.done;) principals.push(pr.text());
    const validAfter = r.u64(), validBefore = r.u64();
    const options = buf => {
      const out = [];
      for (const o = sshReader(buf); !o.done;) {
        const key = o.text(), value = o.string();
        out.push(value.length ? `${key} ${sshReader(value).text()}` : key);
      }
      return out;
    };
    const criticalOptions = options(r.string()), extensions = options(r.string());
    r.string(); // reserved
    const caBlob = r.string();
    const signed = cert.subarray(0, r.offset);
    const signatureValid = await sshVerify(caBlob, signed, r.string());
    const date = v => v === FOREVER ? null : new Date(Number(v) * 1000);
    return {
      type, keyId, serial: serial.toString(), principals, criticalOptions, extensions,
      validAfter: date(validAfter), validBefore: date(validBefore), keyBlob, caBlob, signatureValid,
    };
  }

  async function generateSshCA(spec, comment, passphrase) {
    const key = await generateSshKey(spec, comment, passphrase);
    return { ...key, ca: { privateKey: key.key, blob: key.blob } };
  }

  async function loadSshCA(keyText, passphrase) {
    const { privateKey } = await loadPrivateKey(keyText, passphrase);
    const blob = spkiToSshBlob(await publicSpki(privateKey));
    return { privateKey, blob, publicKey: sshPublicKeyLine(blob, ''), fingerprint: await sshFingerprint(blob),
      description: describeSshBlob(blob) };
  }

  // ---------------------------------------------------------------- PKCS#8

  const PBKDF2_ITERATIONS = 600000;
  const PRF_HASH = { [OID.hmacSha1]: 'SHA-1', [OID.hmacSha256]: 'SHA-256', [OID.hmacSha384]: 'SHA-384', [OID.hmacSha512]: 'SHA-512' };
  const AES_BITS = { [OID.aes128Cbc]: 128, [OID.aes192Cbc]: 192, [OID.aes256Cbc]: 256 };

  async function pbkdf2Key(passphrase, salt, iterations, hash, bits, usage) {
    const base = await subtle.importKey('raw', utf8.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash }, base, { name: 'AES-CBC', length: bits }, false, [usage]);
  }

  // EncryptedPrivateKeyInfo with PBES2: PBKDF2-HMAC-SHA256 and AES-256-CBC.
  async function encryptPkcs8(pkcs8, passphrase) {
    const salt = randomBytes(16), iv = randomBytes(16);
    const aes = await pbkdf2Key(passphrase, salt, PBKDF2_ITERATIONS, 'SHA-256', 256, 'encrypt');
    const data = bytes(await subtle.encrypt({ name: 'AES-CBC', iv }, aes, pkcs8));
    const algId = seq(oid(OID.pbes2), seq(
      seq(oid(OID.pbkdf2), seq(octets(salt), smallInt(PBKDF2_ITERATIONS), seq(oid(OID.hmacSha256), derNull()))),
      seq(oid(OID.aes256Cbc), octets(iv))));
    return seq(algId, octets(data));
  }

  // Unencrypted "PRIVATE KEY", or "ENCRYPTED PRIVATE KEY" when a passphrase is given.
  async function exportPrivateKey(privateKey, passphrase) {
    const pkcs8 = bytes(await subtle.exportKey('pkcs8', privateKey));
    return passphrase ? toPem('ENCRYPTED PRIVATE KEY', await encryptPkcs8(pkcs8, passphrase)) : toPem('PRIVATE KEY', pkcs8);
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
    const prf = kp.find((n, i) => i >= 2 && n.tag === 0x30);
    const hash = PRF_HASH[prf ? oidToString(children(prf)[0]) : OID.hmacSha1];
    const [cipherOid, iv] = children(encScheme);
    const bits = AES_BITS[oidToString(cipherOid)];
    if (!hash || !bits) throw new Error('Unsupported key encryption parameters.');
    const aes = await pbkdf2Key(passphrase, kp[0].content, intValue(kp[1]), hash, bits, 'decrypt');
    try {
      return bytes(await subtle.decrypt({ name: 'AES-CBC', iv: iv.content }, aes, data.content));
    } catch {
      throw new Error('Wrong passphrase for the private key.');
    }
  }

  const KEY_FORMATS = {
    'PRIVATE KEY': 'PKCS#8',
    'ENCRYPTED PRIVATE KEY': 'PKCS#8 (encrypted)',
    'RSA PRIVATE KEY': 'PKCS#1',
    'EC PRIVATE KEY': 'SEC1',
    'OPENSSH PRIVATE KEY': 'OpenSSH',
  };

  // Accepts PKCS#8 (plain or encrypted), PKCS#1 RSA, SEC1 EC and OpenSSH keys.
  async function privateKeyFromBlock(block, passphrase) {
    requireWebCrypto();
    if (/ENCRYPTED/.test(block.headers)) {
      throw new Error('Legacy encrypted PEM keys are not supported. Convert it first: ' +
        'openssl pkey -in old.key -out new.key -aes256');
    }
    const format = KEY_FORMATS[block.label];
    if (block.label === 'OPENSSH PRIVATE KEY') return { format, ...(await decodeOpenSshPrivateKey(block.der, passphrase)) };

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
    return { format, encrypted: block.label === 'ENCRYPTED PRIVATE KEY', comment: '', privateKey: await importPkcs8(pkcs8) };
  }

  function importPkcs8(pkcs8) {
    const algorithm = algorithmFromAlgId(children(parseDer(pkcs8))[1]);
    return subtle.importKey('pkcs8', pkcs8, algorithm, true, ['sign']);
  }

  async function loadPrivateKey(text, passphrase) {
    const block = parsePem(text).find(b => /PRIVATE KEY$/.test(b.label));
    if (!block) throw new Error('No private key found in the key file.');
    return privateKeyFromBlock(block, passphrase);
  }

  // PKCS#1 RSAPrivateKey, the "traditional" format some older software insists on.
  async function exportPkcs1(privateKey) {
    const pkcs8 = bytes(await subtle.exportKey('pkcs8', privateKey));
    return toPem('RSA PRIVATE KEY', children(parseDer(pkcs8))[2].content);
  }

  // ---------------------------------------------------------------- PKCS#12

  // RFC 7292 appendix B key derivation, for the MAC key (id 3) only: one SHA-256 block.
  async function pkcs12MacKey(password, salt, iterations) {
    const v = 64;
    const pw = new Uint8Array(password.length * 2 + 2);
    for (let i = 0; i < password.length; i++) {
      pw[2 * i] = password.charCodeAt(i) >> 8;
      pw[2 * i + 1] = password.charCodeAt(i) & 0xff;
    }
    const fill = b => {
      const out = new Uint8Array(v * Math.ceil(b.length / v));
      for (let i = 0; i < out.length; i++) out[i] = b[i % b.length];
      return out;
    };
    let a = concat(new Uint8Array(v).fill(3), fill(salt), fill(pw));
    for (let i = 0; i < iterations; i++) a = bytes(await subtle.digest('SHA-256', a));
    return a;
  }

  // .p12/.pfx with the key (PBES2, AES-256) and certificates, MAC'd with HMAC-SHA256 like OpenSSL 3.
  async function exportPkcs12({ privateKey, certificates, password }) {
    if (!password) throw new Error('A .p12 file needs a password.');
    const localKeyId = seq(oid(OID.localKeyId), set(octets(bytes(await subtle.digest('SHA-1', certificates[0])))));
    const pkcs8 = bytes(await subtle.exportKey('pkcs8', privateKey));
    const certBag = (der, i) => seq(oid(OID.certBag), explicit(0, seq(oid(OID.x509Certificate), explicit(0, octets(der)))),
      ...(i === 0 ? [set(localKeyId)] : []));
    const keyBag = seq(oid(OID.shroudedKeyBag), explicit(0, await encryptPkcs8(pkcs8, password)), set(localKeyId));
    const authSafe = seq(seq(oid(OID.data), explicit(0, octets(seq(...certificates.map(certBag), keyBag)))));

    const salt = randomBytes(16), iterations = 2048;
    const macKey = await subtle.importKey('raw', await pkcs12MacKey(password, salt, iterations),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = bytes(await subtle.sign('HMAC', macKey, authSafe));
    return seq(smallInt(3), seq(oid(OID.data), explicit(0, octets(authSafe))),
      seq(seq(seq(oid(OID.sha256), derNull()), octets(mac)), octets(salt), smallInt(iterations)));
  }

  // ---------------------------------------------------------------- X.509

  function signatureAlgorithm(key) {
    const alg = key.algorithm;
    if (alg.name === 'Ed25519') return { id: seq(oid(OID.ed25519)), params: { name: 'Ed25519' } };
    if (alg.name === 'ECDSA') {
      const c = CURVES[alg.namedCurve];
      return { id: seq(oid(c.sigOid)), params: { name: 'ECDSA', hash: c.hash }, ecdsa: true };
    }
    return { id: seq(oid(OID.sha256WithRSA), derNull()), params: { name: RSA } };
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
  const KEY_USAGE_NAMES = ['Digital Signature', 'Non Repudiation', 'Key Encipherment', 'Data Encipherment',
    'Key Agreement', 'Certificate Sign', 'CRL Sign', 'Encipher Only', 'Decipher Only'];
  const EKU_NAMES = {
    [OID.serverAuth]: 'TLS Server', [OID.clientAuth]: 'TLS Client', '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email', '1.3.6.1.5.5.7.3.8': 'Time Stamping', '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  };

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
  const authorityKeyId = async ca =>
    extension(OID.authorityKeyId, false, seq(tlv(0x80, ca.keyId || await keyIdentifier(ca.spki))));

  // A self-signed root, or an intermediate when `issuer` (a loaded CA) is given.
  async function createCA({ keySpec, commonName, organization, days, issuer }) {
    if (issuer && issuer.pathLen === 0) {
      throw new Error(`"${issuer.commonName}" may not issue intermediate CAs (its path length is 0).`);
    }
    const keyPair = await generateKey(keySpec);
    const spki = bytes(await subtle.exportKey('spki', keyPair.publicKey));
    const name = distinguishedName(commonName, organization);
    const now = new Date();
    const der = await signCertificate({
      subject: name, issuer: issuer ? issuer.subject : name, spki,
      signer: issuer ? issuer.privateKey : keyPair.privateKey,
      notBefore: now, notAfter: addDays(now, days),
      extensions: [
        // Roots may sign intermediates; intermediates only sign end-entity certificates.
        extension(OID.basicConstraints, true, issuer ? seq(boolTrue(), smallInt(0)) : seq(boolTrue())),
        extension(OID.keyUsage, true, keyUsage(KU.digitalSignature, KU.keyCertSign, KU.cRLSign)),
        extension(OID.subjectKeyId, false, octets(await keyIdentifier(spki))),
        ...(issuer ? [await authorityKeyId(issuer)] : []),
      ],
    });
    return { privateKey: keyPair.privateKey, der, chain: issuer ? [issuer.der, ...issuer.chain] : [], ...parseCertificate(der) };
  }

  // Split "example.com, *.example.com 10.0.0.1 ::1 me@example.com" into SAN entries.
  function parseSubjectAltNames(input) {
    return input.split(/[\s,]+/).filter(Boolean).map(raw => {
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
      if (name.includes('@')) {
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(name)) return { type: 'email', value: name };
        throw new Error(`Invalid email address: ${raw}`);
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

  function ipToString(b) {
    if (b.length === 4) return b.join('.');
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
    return groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::').replace(/:{3,}/, '::');
  }

  const SAN_TAGS = { dns: 0x82, email: 0x81, ip: 0x87 };
  const encodeSan = names => seq(...names.map(n => tlv(SAN_TAGS[n.type], n.type === 'ip' ? n.bytes : utf8.encode(n.value))));

  function parseGeneralNames(node) {
    return children(node).map(n => {
      switch (n.tag) {
        case 0x82: return { type: 'dns', value: decodeUtf8(n.content) };
        case 0x81: return { type: 'email', value: decodeUtf8(n.content) };
        case 0x86: return { type: 'uri', value: decodeUtf8(n.content) };
        case 0x87: return { type: 'ip', value: ipToString(n.content) };
        case 0xa4: return { type: 'dirName', value: nameToString(children(n)[0]) };
        default: return { type: 'other', value: '(unsupported name type)' };
      }
    });
  }

  // Server or client certificate signed by `ca`, for a new key or for the key in a CSR.
  async function issueCertificate(ca, { profile, keySpec, csr, names, commonName, days }) {
    let privateKey = null, spki, subject;
    if (csr) {
      ({ spki, subject } = csr);
    } else {
      const keyPair = await generateKey(keySpec);
      privateKey = keyPair.privateKey;
      spki = bytes(await subtle.exportKey('spki', keyPair.publicKey));
    }
    commonName = commonName || (names[0] && names[0].value);
    if (!subject && !commonName) throw new Error('Enter a common name or at least one hostname.');
    if (profile === 'server' && !names.length) throw new Error('Enter at least one hostname or IP address.');

    const rsa = oidToString(children(children(parseDer(spki))[0])[0]) === OID.rsaEncryption;
    const usage = rsa && profile === 'server' ? keyUsage(KU.digitalSignature, KU.keyEncipherment) : keyUsage(KU.digitalSignature);
    const now = new Date();
    const der = await signCertificate({
      subject: subject || distinguishedName(commonName), issuer: ca.subject, spki, signer: ca.privateKey,
      notBefore: now, notAfter: addDays(now, days),
      extensions: [
        extension(OID.basicConstraints, true, seq()),
        extension(OID.keyUsage, true, usage),
        extension(OID.extKeyUsage, false, seq(oid(profile === 'client' ? OID.clientAuth : OID.serverAuth))),
        ...(names.length ? [extension(OID.subjectAltName, false, encodeSan(names))] : []),
        extension(OID.subjectKeyId, false, octets(await keyIdentifier(spki))),
        await authorityKeyId(ca),
      ],
    });
    return { privateKey, der, ...parseCertificate(der) };
  }

  const DN_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.9': 'street',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
  };

  function nameAttributes(name) {
    const out = [];
    for (const rdn of children(name)) {
      for (const atv of children(rdn)) {
        const [type, value] = children(atv);
        const id = oidToString(type);
        out.push({ id, key: DN_NAMES[id] || id, value: decodeString(value) });
      }
    }
    return out;
  }

  const nameToString = name => nameAttributes(name).map(a => `${a.key}=${a.value}`).join(', ') || '(empty)';
  const commonNameOf = name => (nameAttributes(name).find(a => a.id === OID.commonName) || {}).value || '';

  function parseCertificate(der) {
    const [tbs, sigAlg, sigBits] = children(parseDocument(der));
    const f = children(tbs);
    const i = f[0].tag === 0xa0 ? 1 : 0;
    const [serial, , issuer, validity, subject, spki] = f.slice(i);
    const [notBefore, notAfter] = children(validity).map(parseTime);

    let isCA = false, pathLen = null, keyId = null, authorityKeyId = null, names = [], usages = [], extUsages = [];
    const exts = f.find(n => n.tag === 0xa3);
    for (const ext of exts ? children(children(exts)[0]) : []) {
      const parts = children(ext);
      const id = oidToString(parts[0]);
      const value = parseDer(parts[parts.length - 1].content);
      if (id === OID.basicConstraints) {
        const bc = children(value);
        isCA = bc.some(n => n.tag === 0x01 && n.content[0]);
        const pl = bc.find(n => n.tag === 0x02);
        if (isCA && pl) pathLen = intValue(pl);
      }
      if (id === OID.subjectKeyId) keyId = value.content;
      if (id === OID.authorityKeyId) authorityKeyId = (children(value).find(n => n.tag === 0x80) || {}).content || null;
      if (id === OID.subjectAltName) names = parseGeneralNames(value);
      if (id === OID.keyUsage) {
        const b = value.content;
        usages = KEY_USAGE_NAMES.filter((_, bit) => b[1 + (bit >> 3)] & (0x80 >> (bit & 7)));
      }
      if (id === OID.extKeyUsage) extUsages = children(value).map(n => EKU_NAMES[oidToString(n)] || oidToString(n));
    }

    const sigOid = oidToString(children(sigAlg)[0]);
    let keyDescription;
    try { keyDescription = describeSpki(spki.raw); } catch { keyDescription = 'Unsupported key type'; }
    return {
      subject: subject.raw, issuer: issuer.raw, spki: spki.raw, keyId, authorityKeyId, isCA, pathLen, names,
      usages, extUsages, notBefore, notAfter, keyDescription,
      commonName: commonNameOf(subject), subjectText: nameToString(subject), issuerText: nameToString(issuer),
      selfSigned: equalBytes(subject.raw, issuer.raw),
      serial: toHex(stripLeadingZeros(serial.content)),
      sigOid, signatureName: (SIGNATURES[sigOid] || {}).label || sigOid,
      tbs: tbs.raw, signature: sigBits.content.subarray(1),
    };
  }

  async function parseCsr(der) {
    const [info, sigAlg, sigBits] = children(parseDocument(der));
    const f = children(info);
    const [, subject, spki] = f;
    let names = [];
    const attrs = f.find(n => n.tag === 0xa0);
    for (const attr of attrs ? children(attrs) : []) {
      const [type, values] = children(attr);
      if (oidToString(type) !== OID.extensionRequest) continue;
      for (const ext of children(children(values)[0])) {
        const parts = children(ext);
        if (oidToString(parts[0]) === OID.subjectAltName) names = parseGeneralNames(parseDer(parts[parts.length - 1].content));
      }
    }
    const sigOid = oidToString(children(sigAlg)[0]);
    return {
      subject: subject.raw, spki: spki.raw, names,
      commonName: commonNameOf(subject), subjectText: nameToString(subject),
      keyDescription: describeSpki(spki.raw), signatureName: (SIGNATURES[sigOid] || {}).label || sigOid,
      signatureValid: await verifySignature(spki.raw, sigOid, info.raw, sigBits.content.subarray(1)),
    };
  }

  async function loadCsr(text) {
    const block = parsePem(text).find(b => /CERTIFICATE REQUEST$/.test(b.label));
    if (!block) throw new Error('No PEM certificate request (CSR) found.');
    const csr = await parseCsr(block.der);
    if (!csr.signatureValid) throw new Error('The CSR signature is invalid or uses an unsupported algorithm.');
    return csr;
  }

  // The first certificate is the CA; any further ones form its chain.
  async function loadCA(certText, keyText, passphrase) {
    const certs = parsePem(certText).filter(b => b.label === 'CERTIFICATE');
    if (!certs.length) throw new Error('No PEM certificate found in the certificate file.');
    const info = parseCertificate(certs[0].der);
    if (!info.isCA) throw new Error('This certificate is not a CA certificate (basicConstraints CA:FALSE).');

    const { privateKey } = await loadPrivateKey(keyText, passphrase);
    if (!equalBytes(spkiToSshBlob(await publicSpki(privateKey)), spkiToSshBlob(info.spki))) {
      throw new Error('The private key does not belong to this certificate.');
    }
    return { privateKey, der: certs[0].der, chain: certs.slice(1).map(c => c.der), ...info };
  }

  // Leaf plus intermediates, as servers should send it. Null when the CA is a root.
  function fullChainPem(leafDer, ca) {
    const intermediates = [ca.der, ...ca.chain].filter(der => !parseCertificate(der).selfSigned);
    return intermediates.length ? [leafDer, ...intermediates].map(certificatePem).join('') : null;
  }

  const certificatePem = der => toPem('CERTIFICATE', der);

  // ---------------------------------------------------------------- inspect & convert

  const fmtDate = d => d ? d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : 'forever';
  const sha256Hex = async b => toHex(bytes(await subtle.digest('SHA-256', b)));

  // Describes whatever is pasted or dropped. Returns items of { title, info, rows, files }.
  // Files are [title, filename, content] where content is a string or bytes.
  async function inspect(input, { passphrase = '', outputPassphrase = '' } = {}) {
    requireWebCrypto();
    const items = [];
    const add = async (fn, fallbackTitle) => {
      try { items.push(await fn()); } catch (e) { items.push({ title: fallbackTitle, info: 'Error', rows: [['Error', e.message]], files: [] }); }
    };

    let text = typeof input === 'string' ? input : null;
    if (!text) {
      const asText = decodeUtf8(input);
      if (/-----BEGIN |(^|\s)(ssh|ecdsa|sk)-\S+\s+AAAA/.test(asText)) text = asText;
      else await add(() => inspectDer(input, passphrase, outputPassphrase), 'Binary file');
    }
    if (text) {
      for (const block of parsePem(text)) await add(() => inspectPem(block, passphrase, outputPassphrase), block.label);
      for (const line of text.replace(/\r/g, '').split('\n')) {
        if (!/^\s*#/.test(line) && SSH_LINE.test(line)) await add(() => inspectSshLine(line), 'SSH key');
      }
      const compact = text.replace(/\s+/g, '');
      if (!items.length && compact.length > 64 && /^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
        await add(() => inspectDer(fromBase64(compact), passphrase, outputPassphrase), 'Base64 data');
      }
    }
    if (!items.length) {
      throw new Error('Nothing recognised. Paste a PEM certificate, key or CSR, an OpenSSH key or an SSH public key.');
    }

    // Cross-check what was given together: which key belongs to which certificate, who signed whom.
    for (const item of items.filter(it => it.cert)) {
      for (const other of items.filter(it => it.privateBlob && item.blob)) {
        item.rows.push(['Private key in input', equalBytes(other.privateBlob, item.blob) ? '✓ matches' : '✗ does not match']);
      }
      for (const issuer of items.filter(it => it.cert && it !== item && equalBytes(it.cert.subject, item.cert.issuer))) {
        const ok = await verifySignature(issuer.cert.spki, item.cert.sigOid, item.cert.tbs, item.cert.signature);
        item.rows.push(['Signed by', `${issuer.cert.subjectText} ${ok ? '(✓ signature valid)' : '(✗ signature invalid)'}`]);
      }
    }
    return items.map(({ title, info, rows, files }) => ({ title, info, rows, files }));
  }

  async function inspectDer(der, passphrase, outputPassphrase) {
    for (const attempt of [
      () => inspectCertificate(der),
      () => inspectCsr(der),
      () => inspectPrivateKey({ label: 'PRIVATE KEY', headers: '', der }, passphrase, outputPassphrase),
      () => inspectPublicKey(parseDocument(der).raw),
    ]) {
      try { return await attempt(); } catch { /* try the next format */ }
    }
    throw new Error('Unrecognised binary data. Supported: DER certificates, CSRs, PKCS#8 keys and public keys.');
  }

  function inspectPem(block, passphrase, outputPassphrase) {
    if (block.label === 'CERTIFICATE') return inspectCertificate(block.der);
    if (/CERTIFICATE REQUEST$/.test(block.label)) return inspectCsr(block.der);
    if (block.label === 'PUBLIC KEY') return inspectPublicKey(block.der);
    if (block.label === 'RSA PUBLIC KEY') return inspectPublicKey(seq(seq(oid(OID.rsaEncryption), derNull()), bitString(block.der)));
    if (/PRIVATE KEY$/.test(block.label)) return inspectPrivateKey(block, passphrase, outputPassphrase);
    throw new Error(`Unsupported PEM type: ${block.label}`);
  }

  async function inspectCertificate(der) {
    const c = parseCertificate(der);
    const now = new Date();
    const status = now > c.notAfter ? ' (expired)' : now < c.notBefore ? ' (not yet valid)' : '';
    const rows = [
      ['Subject', c.subjectText],
      ['Issuer', c.selfSigned ? 'Self-signed' : c.issuerText],
      ['Serial', c.serial],
      ['Valid', `${fmtDate(c.notBefore)} – ${fmtDate(c.notAfter)}${status}`],
      ['Key', c.keyDescription],
      ['Signature', c.signatureName],
      ['Type', c.isCA ? `CA${c.pathLen !== null ? ` (path length ${c.pathLen})` : ''}` : 'End entity'],
    ];
    if (c.names.length) rows.push(['Alternative names', c.names.map(n => n.value).join(', ')]);
    if (c.usages.length) rows.push(['Key usage', c.usages.join(', ')]);
    if (c.extUsages.length) rows.push(['Extended key usage', c.extUsages.join(', ')]);
    if (c.keyId) rows.push(['Subject key ID', toHex(c.keyId)]);
    if (c.authorityKeyId) rows.push(['Authority key ID', toHex(c.authorityKeyId)]);
    if (c.selfSigned) {
      const ok = await verifySignature(c.spki, c.sigOid, c.tbs, c.signature);
      rows.push(['Self-signature', ok ? '✓ valid' : ok === null ? 'not checked (unsupported algorithm)' : '✗ invalid']);
    }
    rows.push(['SHA-256 fingerprint', await sha256Hex(der)]);

    const base = (c.commonName || 'certificate').replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_');
    const files = [['Certificate (PEM)', base + '.pem', certificatePem(der)], ['Certificate (DER)', base + '.der', der]];
    let blob = null;
    try {
      blob = spkiToSshBlob(c.spki);
      files.push(['Public key (PEM)', base + '.pub.pem', toPem('PUBLIC KEY', c.spki)]);
    } catch { /* unsupported key type */ }
    return { title: c.isCA ? '📜 CA Certificate' : '📜 Certificate', info: c.commonName, rows, files, cert: c, blob };
  }

  async function inspectCsr(der) {
    const r = await parseCsr(der);
    const rows = [
      ['Subject', r.subjectText],
      ['Key', r.keyDescription],
      ['Signature', `${r.signatureName} ${r.signatureValid ? '(✓ valid)' : r.signatureValid === null ? '(not checked)' : '(✗ invalid)'}`],
    ];
    if (r.names.length) rows.push(['Requested names', r.names.map(n => n.value).join(', ')]);
    const base = (r.commonName || 'request').replace(/[^A-Za-z0-9._-]+/g, '_');
    return {
      title: '📝 Certificate Request', info: r.commonName, rows,
      files: [['CSR (PEM)', base + '.csr', toPem('CERTIFICATE REQUEST', der)], ['CSR (DER)', base + '.csr.der', der]],
    };
  }

  async function inspectPublicKey(spki) {
    const blob = spkiToSshBlob(spki);
    return {
      title: '🔑 Public Key', info: describeSpki(spki),
      rows: [['Key', describeSpki(spki)], ['SSH fingerprint', await sshFingerprint(blob)]],
      files: [
        ['SSH public key', 'key.pub', sshPublicKeyLine(blob, '')],
        ['Public key (PEM)', 'public.pem', toPem('PUBLIC KEY', spki)],
        ['Public key (DER)', 'public.der', spki],
      ],
      blob,
    };
  }

  async function inspectPrivateKey(block, passphrase, outputPassphrase) {
    const format = KEY_FORMATS[block.label] || block.label;
    const encryptedInput = block.label === 'ENCRYPTED PRIVATE KEY' ||
      (block.label === 'OPENSSH PRIVATE KEY' && !/^openssh-key-v1\0\0\0\0\x04none/.test(decodeUtf8(block.der.subarray(0, 23))));
    if (encryptedInput && !passphrase) {
      return { title: '🔐 Private Key', info: format,
        rows: [['Format', format], ['Encrypted', 'Yes. Enter the passphrase to inspect and convert it.']], files: [] };
    }

    const { privateKey, comment } = await privateKeyFromBlock(block, passphrase);
    const spki = await publicSpki(privateKey);
    const blob = spkiToSshBlob(spki);
    const rows = [
      ['Format', format],
      ['Key', describeSpki(spki)],
      ['Encrypted', encryptedInput ? 'Yes' : 'No'],
      ...(comment ? [['Comment', comment]] : []),
      ['SSH fingerprint', await sshFingerprint(blob)],
    ];
    const sshName = 'id_' + ({ 'ssh-ed25519': 'ed25519', 'ssh-rsa': 'rsa' }[sshReader(blob).text()] || 'ecdsa');
    const enc = outputPassphrase ? ' (encrypted)' : '';
    const files = [
      [`PKCS#8 private key${enc}`, 'private.pem', await exportPrivateKey(privateKey, outputPassphrase)],
      [`OpenSSH private key${enc}`, sshName, (await encodeOpenSshPrivateKey(privateKey, comment, outputPassphrase)).pem],
      ['SSH public key', sshName + '.pub', sshPublicKeyLine(blob, comment)],
      ['Public key (PEM)', 'public.pem', toPem('PUBLIC KEY', spki)],
    ];
    if (privateKey.algorithm.name === RSA && !outputPassphrase) {
      files.splice(1, 0, ['PKCS#1 private key', 'private-rsa.pem', await exportPkcs1(privateKey)]);
    }
    return { title: '🔐 Private Key', info: describeSpki(spki), rows, files, privateBlob: blob };
  }

  async function inspectSshLine(line) {
    const { name, blob, comment } = parseSshPublicKey(line);
    if (name.endsWith(CERT_SUFFIX)) {
      const c = await parseSshCertificate(blob);
      return {
        title: '📜 SSH Certificate', info: `${c.type} certificate`,
        rows: [
          ['Key', `${describeSshBlob(c.keyBlob)} ${await sshFingerprint(c.keyBlob)}`],
          ['Key ID', c.keyId || '(none)'],
          ['Serial', c.serial],
          ['Principals', c.principals.join(', ') || '(any)'],
          ['Valid', `${c.validAfter && c.validAfter.getTime() ? fmtDate(c.validAfter) : 'always'} – ${fmtDate(c.validBefore)}`],
          ['Critical options', c.criticalOptions.join(', ') || '(none)'],
          ['Extensions', c.extensions.join(', ') || '(none)'],
          ['Signed by', `${describeSshBlob(c.caBlob)} ${await sshFingerprint(c.caBlob)}`],
          ['Signature', c.signatureValid ? '✓ valid' : '✗ invalid'],
        ],
        files: [['CA public key', 'ca.pub', sshPublicKeyLine(c.caBlob, '')]],
      };
    }
    const spki = sshBlobToSpki(blob);
    return {
      title: '🔑 SSH Public Key', info: describeSshBlob(blob),
      rows: [['Key', describeSshBlob(blob)], ['Fingerprint', await sshFingerprint(blob)], ...(comment ? [['Comment', comment]] : [])],
      files: spki ? [['Public key (PEM)', 'public.pem', toPem('PUBLIC KEY', spki)]] : [],
      blob,
    };
  }

  // ---------------------------------------------------------------- vault

  // The vault is JSON encrypted with AES-256-GCM under a PBKDF2-SHA256 key derived from the master password.
  const VAULT_FORMAT = 'kiwi-vault';

  async function vaultKey(password, salt, iterations) {
    const base = await subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function createVaultSession(password) {
    requireWebCrypto();
    if (password.length < 8) throw new Error('Use a master password of at least 8 characters.');
    const salt = randomBytes(16);
    return { key: await vaultKey(password, salt, PBKDF2_ITERATIONS), salt, iterations: PBKDF2_ITERATIONS };
  }

  async function sealVault(session, data) {
    const iv = randomBytes(12);
    const ciphertext = bytes(await subtle.encrypt({ name: 'AES-GCM', iv }, session.key, utf8.encode(JSON.stringify(data))));
    return JSON.stringify({
      format: VAULT_FORMAT, version: 1, kdf: 'PBKDF2-SHA256', iterations: session.iterations, salt: toBase64(session.salt),
      cipher: 'AES-256-GCM', iv: toBase64(iv), data: toBase64(ciphertext),
    });
  }

  function isVaultFile(text) {
    try { return JSON.parse(text).format === VAULT_FORMAT; } catch { return false; }
  }

  async function openVault(text, password) {
    requireWebCrypto();
    let file;
    try { file = JSON.parse(text); } catch { throw new Error('Not a Kiwi vault file.'); }
    if (file.format !== VAULT_FORMAT || file.version !== 1 || file.kdf !== 'PBKDF2-SHA256' || file.cipher !== 'AES-256-GCM') {
      throw new Error('Not a Kiwi vault file, or one from a newer version.');
    }
    const salt = fromBase64(file.salt);
    const session = { key: await vaultKey(password, salt, file.iterations), salt, iterations: file.iterations };
    let plain;
    try {
      plain = await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(file.iv) }, session.key, fromBase64(file.data));
    } catch {
      throw new Error('Wrong master password, or the vault file is damaged.');
    }
    return { session, data: JSON.parse(decodeUtf8(bytes(plain))) };
  }

  // Vault items share { id, kind, name, notes, created } plus, per kind:
  //   key      - SSH public key line, optional unencrypted OpenSSH private key; role 'ssh-ca' marks SSH CAs
  //   x509     - certificate PEM, optional PKCS#8 private key and the chain of issuer certificates above it
  //   ssh-cert - SSH certificate line
  const newItem = (kind, name, fields) =>
    ({ id: toHex(randomBytes(16), '').toLowerCase(), kind, name, notes: '', created: new Date().toISOString(), ...fields });

  async function keyItem(privateKey, { name, comment = '', role } = {}) {
    const { pem, blob } = await encodeOpenSshPrivateKey(privateKey, comment, '');
    return newItem('key', name || comment || describeSshBlob(blob), {
      ...(role ? { role } : {}), privateKey: pem, publicKey: sshPublicKeyLine(blob, comment),
    });
  }

  async function x509Item({ der, privateKey, chain = [], name }) {
    return newItem('x509', name || parseCertificate(der).commonName || 'Certificate', {
      certificate: certificatePem(der),
      ...(chain.length ? { chain: chain.map(certificatePem).join('') } : {}),
      ...(privateKey ? { privateKey: await exportPrivateKey(privateKey) } : {}),
    });
  }

  const sshCertItem = (line, name) => newItem('ssh-cert', name || 'SSH certificate', { certificate: line.trim() + '\n' });

  // Turns pasted or opened text/bytes into vault items: certificates are paired with their keys
  // and issuer certificates, the rest become standalone items.
  async function importItems(input, passphrase) {
    requireWebCrypto();
    let text = typeof input === 'string' ? input : decodeUtf8(input);
    let blocks;
    if (typeof input !== 'string' && !/-----BEGIN |(^|\s)(ssh|ecdsa|sk)-\S+\s+AAAA/.test(text)) {
      let isCert = false;
      try { parseCertificate(input); isCert = true; } catch { /* not a DER certificate */ }
      blocks = [{ label: isCert ? 'CERTIFICATE' : 'PRIVATE KEY', headers: '', der: input }];
      text = '';
    } else {
      blocks = parsePem(text);
    }

    const certs = [], keys = [];
    for (const block of blocks) {
      if (block.label === 'CERTIFICATE') {
        certs.push({ der: block.der, info: parseCertificate(block.der) });
      } else if (/PRIVATE KEY$/.test(block.label)) {
        const { privateKey, comment } = await privateKeyFromBlock(block, passphrase);
        keys.push({ privateKey, comment, blob: spkiToSshBlob(await publicSpki(privateKey)) });
      }
    }

    const blobOf = cert => { try { return spkiToSshBlob(cert.info.spki); } catch { return null; } };
    const chainOf = cert => {
      const chain = [];
      for (let cur = cert; !cur.info.selfSigned;) {
        cur = certs.find(c => c !== cert && !chain.includes(c) && equalBytes(c.info.subject, cur.info.issuer));
        if (!cur) break;
        chain.push(cur);
      }
      return chain;
    };

    const items = [], usedCerts = new Set(), usedKeys = new Set();
    for (const cert of certs) {
      const blob = blobOf(cert);
      const key = blob && keys.find(k => equalBytes(k.blob, blob));
      if (!key) continue;
      const chain = chainOf(cert);
      chain.forEach(c => usedCerts.add(c));
      usedCerts.add(cert);
      usedKeys.add(key);
      items.push(await x509Item({ der: cert.der, privateKey: key.privateKey, chain: chain.map(c => c.der) }));
    }
    for (const cert of certs.filter(c => !usedCerts.has(c))) {
      items.push(await x509Item({ der: cert.der, chain: chainOf(cert).map(c => c.der) }));
    }
    for (const key of keys.filter(k => !usedKeys.has(k))) {
      items.push(await keyItem(key.privateKey, { comment: key.comment }));
    }
    for (const line of text.replace(/\r/g, '').split('\n')) {
      if (/^\s*#/.test(line) || !SSH_LINE.test(line)) continue;
      const { name, blob, comment } = parseSshPublicKey(line);
      if (name.endsWith(CERT_SUFFIX)) {
        items.push(sshCertItem(sshPublicKeyLine(blob, comment), (await parseSshCertificate(blob)).keyId || comment));
      } else if (!keys.some(k => equalBytes(k.blob, blob))) {
        items.push(newItem('key', comment || describeSshBlob(blob), { publicKey: sshPublicKeyLine(blob, comment) }));
      }
    }
    if (!items.length) throw new Error('Nothing to import. Paste PEM certificates or keys, OpenSSH keys or SSH public keys.');
    return items;
  }

  // What the vault list shows for an item.
  async function summarizeItem(item) {
    if (item.kind === 'x509') {
      const c = parseCertificate(parsePem(item.certificate)[0].der);
      const label = c.isCA ? (c.selfSigned ? 'Root CA' : 'Intermediate CA')
        : c.extUsages.includes('TLS Client') && !c.extUsages.includes('TLS Server') ? 'Client certificate' : 'Certificate';
      return {
        label, isCA: c.isCA, hasPrivateKey: !!item.privateKey, expires: c.notAfter,
        description: [c.keyDescription, c.names.map(n => n.value).join(', ')].filter(Boolean).join(' · '),
      };
    }
    const { blob } = parseSshPublicKey(item.publicKey || item.certificate);
    if (item.kind === 'ssh-cert') {
      const c = await parseSshCertificate(blob);
      return {
        label: `SSH ${c.type} certificate`, hasPrivateKey: false, expires: c.validBefore,
        description: `${describeSshBlob(c.keyBlob)} · ${c.principals.join(', ')}`,
      };
    }
    return {
      label: item.role === 'ssh-ca' ? 'SSH CA' : item.privateKey ? 'Key pair' : 'Public key',
      isCA: item.role === 'ssh-ca', hasPrivateKey: !!item.privateKey, expires: null,
      description: `${describeSshBlob(blob)} · ${await sshFingerprint(blob)}`,
    };
  }

  // Details and downloadable files for an item; private keys in the files are encrypted with `passphrase` if given.
  async function itemDetails(item, passphrase = '') {
    if (item.kind !== 'x509') {
      const [view] = await inspect(item.privateKey || item.certificate || item.publicKey, { outputPassphrase: passphrase });
      return { rows: view.rows, files: view.files };
    }
    const [view] = await inspect(item.certificate);
    const files = [...view.files];
    const leaf = parsePem(item.certificate)[0].der;
    const chain = item.chain ? parsePem(item.chain).map(b => b.der) : [];
    const base = files[0][1].replace(/\.pem$/, '');
    if (chain.length) {
      files.push(['Issuer chain', base + '.chain.pem', item.chain]);
      const full = fullChainPem(leaf, { der: chain[0], chain: chain.slice(1) });
      if (full) files.push(['Full chain (certificate + intermediates)', base + '.fullchain.pem', full]);
    }
    if (item.privateKey) {
      const { privateKey } = await loadPrivateKey(item.privateKey, '');
      files.unshift([`Private key${passphrase ? ' (encrypted)' : ''}`, base + '.key', await exportPrivateKey(privateKey, passphrase)]);
      if (passphrase) {
        files.push(['PKCS#12 bundle (password: the download passphrase)', base + '.p12',
          await exportPkcs12({ privateKey, certificates: [leaf, ...chain], password: passphrase })]);
      }
    }
    return { rows: view.rows, files };
  }

  // A vault item as a signing CA for issueCertificate / createSshCertificate.
  async function caFromItem(item) {
    if (item.kind === 'x509') return loadCA(item.certificate + (item.chain || ''), item.privateKey, '');
    const ca = await loadSshCA(item.privateKey, '');
    return { ...ca, publicKey: item.publicKey };
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

  return {
    generateSshKey, generateSshCA, loadSshCA, createSshCertificate,
    createCA, loadCA, issueCertificate, loadCsr, parseSubjectAltNames, fullChainPem,
    exportPrivateKey, exportPkcs12, certificatePem, inspect, randomPassphrase,
    createVaultSession, sealVault, openVault, isVaultFile,
    keyItem, x509Item, sshCertItem, importItems, summarizeItem, itemDetails, caFromItem,
    // exposed for tests
    bcryptPbkdf, loadPrivateKey,
  };
})();
