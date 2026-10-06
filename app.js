// Kiwi Key Generator - UI wiring. All crypto lives in kiwi-crypto.js.

const $ = id => document.getElementById(id);
let ca = null;    // TLS CA: { privateKey, der, chain, subject, commonName, notAfter, ... }
let sshCa = null; // SSH CA: { privateKey, blob }

document.addEventListener('DOMContentLoaded', () => {
  if (!(window.crypto && crypto.subtle)) {
    $('unsupported').hidden = false;
    document.querySelectorAll('.btn-primary').forEach(b => { b.disabled = true; });
  }

  document.querySelectorAll('.mode-btn').forEach(btn => btn.addEventListener('click', () => switchMode(btn.dataset.mode)));
  document.querySelectorAll('.upload-section-header').forEach(header => {
    header.addEventListener('click', () => header.parentElement.classList.toggle('open'));
  });
  document.querySelectorAll('[data-passphrase-for]').forEach(btn => {
    btn.addEventListener('click', () => fillPassphrase($(btn.dataset.passphraseFor)));
  });

  const actions = {
    generateSSH: generateSSHKey,
    createSshCA, uploadSshCA, createSshCert,
    createCA, uploadCA, createCert: createCertificate,
    inspectBtn: runInspect,
  };
  for (const [id, action] of Object.entries(actions)) $(id).addEventListener('click', e => busy(e.target, action));

  $('sshcert-type').addEventListener('change', updateSshCertForm);
  $('cert-profile').addEventListener('change', updateCertForm);
  $('cert-type').addEventListener('change', updateCertForm);
  $('cert-csr').addEventListener('change', () => busy($('createCert'), prefillFromCsr));
  $('inspect-file').addEventListener('change', () => {
    if (!$('inspect-file').files[0]) return;
    $('inspect-input').value = '';
    busy($('inspectBtn'), runInspect);
  });
});

function switchMode(mode) {
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
  document.querySelectorAll('.form-mode').forEach(m => m.classList.toggle('active', m.id === mode));
}

// Runs an async action with its button disabled, reporting errors as notifications.
async function busy(button, action) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Working…';
  try {
    await action();
  } catch (error) {
    console.error(error);
    showNotification(error.message, 'error');
  } finally {
    button.textContent = label;
    button.disabled = false;
    $('createCert').disabled = !ca;
    $('createSshCert').disabled = !sshCa;
  }
}

function fillPassphrase(input) {
  const passphrase = Kiwi.randomPassphrase();
  input.value = passphrase;
  input.type = 'text';
  writeClipboard(passphrase).then(
    () => showNotification('Passphrase generated and copied to clipboard', 'success'),
    () => showNotification('Passphrase generated', 'success'));
}

function readDays(id, allowZero = false) {
  const days = Number($(id).value);
  if (!Number.isInteger(days) || days < (allowZero ? 0 : 1)) throw new Error('Validity must be a whole number of days.');
  return days;
}

const dateRange = (from, to) => `${from.toLocaleDateString()} – ${to ? to.toLocaleDateString() : 'forever'}`;

function fileSlug(name) {
  return name.replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_') || 'cert';
}

// ---------------------------------------------------------------- SSH keys

async function generateSSHKey() {
  const spec = $('ssh-type').value;
  const key = await Kiwi.generateSshKey(spec, $('ssh-comment').value.trim(), $('ssh-passphrase').value);
  const filename = 'id_' + spec.split('-')[0];
  $('ssh-output').replaceChildren(renderOutput('🔐 SSH Key Generated', key.description, [
    ['Fingerprint', key.fingerprint],
    ['Passphrase', $('ssh-passphrase').value ? 'Yes (bcrypt KDF, aes256-ctr)' : 'None'],
  ], [
    ['Private Key', filename, key.privateKey],
    ['Public Key', filename + '.pub', key.publicKey],
  ]));
  showNotification('SSH key generated', 'success');
}

// ---------------------------------------------------------------- SSH certificates

async function createSshCA() {
  const passphrase = $('sshca-passphrase').value;
  const created = await Kiwi.generateSshCA($('sshca-type').value, $('sshca-comment').value.trim(), passphrase);
  setSshCA(created.ca, created);
  showSshCA('🔏 SSH CA Created', created, passphrase ? 'Yes (bcrypt KDF, aes256-ctr)' : 'None', created.privateKey);
  showNotification('SSH CA created', 'success');
}

async function uploadSshCA() {
  const file = $('upload-sshca-key').files[0];
  if (!file) throw new Error('Select the CA private key file.');
  const loaded = await Kiwi.loadSshCA(await file.text(), $('upload-sshca-passphrase').value);
  setSshCA(loaded, loaded);
  showSshCA('📂 SSH CA Loaded', loaded, 'Loaded from file', null);
  document.querySelector('#sshcert-mode .upload-section-container').classList.remove('open');
  showNotification('SSH CA loaded', 'success');
}

function setSshCA(value, info) {
  sshCa = { privateKey: value.privateKey, blob: value.blob, publicKey: info.publicKey };
  $('sshCaStatus').textContent = `SSH CA ready: ${info.description} ${info.fingerprint}`;
  $('sshCaStatus').classList.add('ca-ready');
  $('createSshCert').disabled = false;
  $('sshcert-output').replaceChildren();
}

function showSshCA(title, info, keyStatus, privateKeyPem) {
  const pub = info.publicKey.trim();
  const files = [['CA Public Key', 'ssh_ca.pub', info.publicKey]];
  if (privateKeyPem) files.unshift(['CA Private Key', 'ssh_ca', privateKeyPem]);
  $('sshca-output').replaceChildren(renderOutput(title, info.description, [
    ['Fingerprint', info.fingerprint],
    ['Passphrase', keyStatus],
    ['Trust user certificates', 'On servers, add to sshd_config: TrustedUserCAKeys /etc/ssh/ssh_ca.pub'],
    ['Trust host certificates', `On clients, add to ~/.ssh/known_hosts: @cert-authority *.example.com ${pub}`],
  ], files));
  $('sshcert-placeholder').hidden = true;
}

function updateSshCertForm() {
  const host = $('sshcert-type').value === 'host';
  $('sshcert-principals-label').textContent = host ? 'Hostnames' : 'Usernames';
  $('sshcert-principals').placeholder = host ? 'e.g., server.example.com server' : 'e.g., alice root';
  $('sshcert-principals-hint').textContent = host
    ? 'Names clients use to connect to this host.' : 'Accounts this certificate may log in as.';
}

// Default OpenSSH file names for a public key type.
function sshFileBase(type, host) {
  const alg = type.replace(/^sk-/, '').replace(/@openssh\.com$/, '')
    .replace(/^ssh-/, '').replace(/^ecdsa-sha2-nistp\d+$/, 'ecdsa') + (type.startsWith('sk-') ? '_sk' : '');
  return host ? `ssh_host_${alg}_key` : `id_${alg}`;
}

async function createSshCert() {
  if (!sshCa) throw new Error('Create or load an SSH CA first.');
  const publicKey = $('sshcert-pubkey').value.trim();
  if (!publicKey) throw new Error('Paste the public key to sign.');
  const certType = $('sshcert-type').value;
  const principals = $('sshcert-principals').value.split(/[\s,]+/).filter(Boolean);
  if (!principals.length) {
    throw new Error(certType === 'user' ? 'Enter the usernames this certificate may log in as.' : 'Enter the host names.');
  }
  const keyId = $('sshcert-keyid').value.trim() || publicKey.split(/\s+/).slice(2).join(' ') || principals[0];
  const days = readDays('sshcert-days', true);

  const cert = await Kiwi.createSshCertificate(sshCa, { publicKey, certType, keyId, principals, days });
  const host = certType === 'host';
  const base = sshFileBase(publicKey.split(/\s+/)[0], host);
  const rows = [
    ['Type', host ? 'Host certificate' : 'User certificate'],
    ['Key ID', cert.keyId],
    [host ? 'Hostnames' : 'Usernames', cert.principals.join(', ')],
    ['Valid', dateRange(cert.validAfter, cert.validBefore)],
    ['Serial', cert.serial],
    ['Use it', host
      ? `Copy to /etc/ssh/${base}-cert.pub and add to sshd_config: HostCertificate /etc/ssh/${base}-cert.pub`
      : `Save as ~/.ssh/${base}-cert.pub next to the private key; ssh picks it up automatically.`],
  ];
  if (!host) rows.splice(4, 0, ['Permissions', cert.extensions.join(', ')]);
  const files = [['Certificate', `${base}-cert.pub`, cert.certificate]];
  if (host) {
    files.push(['known_hosts line for clients', 'known_hosts', `@cert-authority ${cert.principals.join(',')} ${sshCa.publicKey.trim()}\n`]);
  }
  $('sshcert-output').replaceChildren(renderOutput('📜 SSH Certificate Signed', cert.type, rows, files));
  showNotification('Certificate signed', 'success');
}

// ---------------------------------------------------------------- TLS

async function createCA() {
  const commonName = $('ca-name').value.trim();
  if (!commonName) throw new Error('Enter a name for the CA.');
  const intermediate = $('ca-kind').value === 'intermediate';
  if (intermediate && !ca) throw new Error('Create or load the CA that will sign the intermediate first.');
  const passphrase = $('ca-passphrase').value;
  const created = await Kiwi.createCA({
    keySpec: $('ca-type').value, commonName, days: readDays('ca-days'), issuer: intermediate ? ca : null,
  });
  const keyPem = await Kiwi.exportPrivateKey(created.privateKey, passphrase);
  setCA(created);
  showCA(intermediate ? '🔒 Intermediate CA Created' : '🔒 Root CA Created',
    passphrase ? 'Encrypted (AES-256, PBKDF2)' : 'Unencrypted', keyPem);
  showNotification(intermediate ? 'Intermediate CA created; it now signs new certificates' : 'Root CA created', 'success');
}

async function uploadCA() {
  const certFile = $('upload-ca-cert').files[0];
  const keyFile = $('upload-ca-key').files[0];
  if (!certFile || !keyFile) throw new Error('Select both the CA certificate and its private key.');
  const [certPem, keyPem] = await Promise.all([certFile.text(), keyFile.text()]);
  setCA(await Kiwi.loadCA(certPem, keyPem, $('upload-ca-passphrase').value));
  showCA('📂 CA Loaded', 'Loaded from file', null);
  document.querySelector('#ssl-mode .upload-section-container').classList.remove('open');
  showNotification('CA loaded', 'success');
}

function setCA(value) {
  ca = value;
  const status = $('caStatus');
  status.textContent = `CA ready: ${ca.commonName}${ca.selfSigned ? '' : ' (intermediate)'}, valid until ${ca.notAfter.toLocaleDateString()}`;
  status.classList.add('ca-ready');
  $('createCert').disabled = false;
  $('ca-kind').options[1].disabled = false;
  $('cert-output').replaceChildren();
}

// CA blocks stack up (newest first) so a root's key is never lost when an intermediate is made.
function showCA(title, keyStatus, keyPem) {
  const slug = fileSlug(ca.commonName);
  const files = [['CA Certificate', slug + '.pem', Kiwi.certificatePem(ca.der)]];
  if (keyPem) files.unshift(['CA Private Key', slug + '.key', keyPem]);
  const rows = [
    ['Subject', ca.subjectText],
    ['Issuer', ca.selfSigned ? 'Self-signed (root)' : ca.issuerText],
    ['Private key', keyStatus],
    ['Valid', dateRange(ca.notBefore, ca.notAfter)],
    ['Serial', ca.serial],
  ];
  if (ca.selfSigned) rows.push(['Trust it', 'Import the CA certificate into your OS or browser trust store.']);
  $('ca-output').prepend(renderOutput(title, ca.keyDescription, rows, files));
  $('ssl-placeholder').hidden = true;
}

function updateCertForm() {
  const client = $('cert-profile').value === 'client';
  const fromCsr = $('cert-type').value === 'csr';
  $('cert-csr-group').hidden = !fromCsr;
  $('cert-cn-group').hidden = !client || fromCsr;
  $('cert-p12-group').hidden = fromCsr;
  $('cert-names-label').textContent = client ? 'Email addresses (optional)' : 'Hostnames and IP addresses';
  $('cert-names').placeholder = client ? 'e.g., alice@example.com' : 'e.g., example.com *.example.com 192.168.1.10';
  $('cert-names-hint').textContent = client
    ? 'Added as alternative names. Separate with spaces or commas.'
    : 'Separate with spaces or commas. The first entry becomes the common name.';
}

async function prefillFromCsr() {
  if (!$('cert-csr').value.trim()) return;
  const csr = await Kiwi.loadCsr($('cert-csr').value);
  const names = csr.names.filter(n => ['dns', 'ip', 'email'].includes(n.type)).map(n => n.value);
  $('cert-names').value = (names.length ? names : [csr.commonName]).join(' ');
  showNotification(`Request from ${csr.subjectText} (${csr.keyDescription}), signature valid`, 'success');
}

async function createCertificate() {
  if (!ca) throw new Error('Create or load a CA first.');
  const profile = $('cert-profile').value;
  const keyType = $('cert-type').value;
  const csr = keyType === 'csr' ? await Kiwi.loadCsr($('cert-csr').value) : null;
  const names = Kiwi.parseSubjectAltNames($('cert-names').value);
  const commonName = profile === 'client' && !csr ? $('cert-cn').value.trim() : '';
  if (profile === 'client' && !csr && !commonName) throw new Error('Enter a name for the client certificate.');
  const days = readDays('cert-days');
  const p12Password = csr ? '' : $('cert-p12').value;

  const cert = await Kiwi.issueCertificate(ca, { profile, keySpec: keyType, csr, names, commonName, days });
  const slug = fileSlug(cert.commonName || (names[0] && names[0].value) || 'cert');
  const files = [['Certificate', slug + '.pem', Kiwi.certificatePem(cert.der)]];
  if (cert.privateKey) files.unshift(['Private Key', slug + '.key', await Kiwi.exportPrivateKey(cert.privateKey)]);
  const fullChain = Kiwi.fullChainPem(cert.der, ca);
  if (fullChain) files.push(['Full Chain (certificate + intermediates, for servers)', slug + '.fullchain.pem', fullChain]);
  if (p12Password) {
    files.push(['PKCS#12 Bundle (key + certificates)', slug + '.p12', await Kiwi.exportPkcs12({
      privateKey: cert.privateKey, certificates: [cert.der, ca.der, ...ca.chain], password: p12Password,
    })]);
  }

  const rows = [
    ['Subject', cert.subjectText],
    ['Usage', cert.extUsages.join(', ')],
    ...(cert.names.length ? [['Names', cert.names.map(n => n.value).join(', ')]] : []),
    ['Issuer', ca.subjectText],
    ['Valid', dateRange(cert.notBefore, cert.notAfter)],
    ['Serial', cert.serial],
  ];
  $('cert-output').replaceChildren(renderOutput(
    profile === 'client' ? '🔒 Client Certificate Created' : '🔒 Server Certificate Created', cert.keyDescription, rows, files));

  if (cert.notAfter > ca.notAfter) {
    showNotification('Note: the certificate outlives its CA and will stop working when the CA expires.', 'info');
  } else {
    showNotification('Certificate created', 'success');
  }
}

// ---------------------------------------------------------------- inspect & convert

async function runInspect() {
  const text = $('inspect-input').value;
  const file = $('inspect-file').files[0];
  let input = text;
  if (!text.trim()) {
    if (!file) throw new Error('Paste something or choose a file.');
    input = new Uint8Array(await file.arrayBuffer());
  } else {
    $('inspect-file').value = '';
  }
  const items = await Kiwi.inspect(input, {
    passphrase: $('inspect-passphrase').value, outputPassphrase: $('inspect-out-passphrase').value,
  });
  $('inspect-output').replaceChildren(...items.map(it => renderOutput(it.title, it.info, it.rows, it.files)));
}

// ---------------------------------------------------------------- output

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// details: [label, value][]; files: [title, filename, content][] with string or Uint8Array content.
function renderOutput(title, info, details, files) {
  const group = el('div', 'output-group');

  const header = el('div', 'output-header');
  header.append(el('h3', null, title));
  if (info) header.append(el('span', 'output-info', info));

  const detailBox = el('div', 'certificate-details');
  for (const [label, value] of details) {
    const row = el('p');
    row.append(el('strong', null, label + ': '), document.createTextNode(value));
    detailBox.append(row);
  }
  group.append(header, detailBox);

  for (const [fileTitle, filename, content] of files) {
    const binary = content instanceof Uint8Array;
    const file = el('div', 'output-file');
    const fileHeader = el('div', 'file-header');
    const actions = el('div', 'file-actions');
    if (!binary) {
      const copy = el('button', 'btn-copy', '📋 Copy');
      copy.type = 'button';
      copy.addEventListener('click', () => writeClipboard(content).then(
        () => showNotification('Copied to clipboard', 'success'),
        () => showNotification('Copy failed', 'error')));
      actions.append(copy);
    }
    const download = el('button', 'btn-download', '💾 Download');
    download.type = 'button';
    download.addEventListener('click', () => downloadFile(filename, content));
    actions.append(download);
    fileHeader.append(el('strong', null, `${fileTitle} (${filename})`), actions);
    file.append(fileHeader);

    if (binary) {
      file.append(el('p', 'binary-note', `Binary file, ${content.length} bytes.`));
    } else {
      const textarea = el('textarea');
      textarea.readOnly = true;
      textarea.spellcheck = false;
      textarea.value = content;
      file.append(textarea);
    }
    group.append(file);
  }
  return group;
}

function writeClipboard(text) {
  if (navigator.clipboard) return navigator.clipboard.writeText(text);
  const temp = el('textarea');
  temp.value = text;
  document.body.append(temp);
  temp.select();
  const ok = document.execCommand('copy');
  temp.remove();
  return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
}

function downloadFile(filename, content) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/octet-stream' }));
  const a = el('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function showNotification(message, type = 'info') {
  document.querySelector('.notification')?.remove();
  const notification = el('div', `notification notification-${type}`, message);
  document.body.append(notification);
  setTimeout(() => notification.remove(), type === 'error' ? 6000 : 3000);
}
