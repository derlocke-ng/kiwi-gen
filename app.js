// Kiwi Key Generator - UI wiring. All crypto lives in kiwi-crypto.js.

const $ = id => document.getElementById(id);
let ca = null; // { privateKey, der, subject, spki, keyId, commonName, notAfter, ... }

document.addEventListener('DOMContentLoaded', () => {
  if (!(window.crypto && crypto.subtle)) {
    $('unsupported').hidden = false;
    document.querySelectorAll('.btn-primary').forEach(b => { b.disabled = true; });
  }

  $('sshModeBtn').addEventListener('click', () => switchMode('ssh'));
  $('sslModeBtn').addEventListener('click', () => switchMode('ssl'));
  $('generateSSH').addEventListener('click', e => busy(e.target, generateSSHKey));
  $('createCA').addEventListener('click', e => busy(e.target, createCA));
  $('uploadCA').addEventListener('click', e => busy(e.target, uploadCA));
  $('createCert').addEventListener('click', e => busy(e.target, createCertificate));
  document.querySelector('.upload-section-header').addEventListener('click', () => {
    document.querySelector('.upload-section-container').classList.toggle('open');
  });
  document.querySelectorAll('[data-passphrase-for]').forEach(btn => {
    btn.addEventListener('click', () => fillPassphrase($(btn.dataset.passphraseFor)));
  });
});

function switchMode(mode) {
  const ssh = mode === 'ssh';
  $('sshModeBtn').classList.toggle('active', ssh);
  $('sslModeBtn').classList.toggle('active', !ssh);
  $('ssh-mode').classList.toggle('active', ssh);
  $('ssl-mode').classList.toggle('active', !ssh);
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
    button.disabled = button.id === 'createCert' && !ca;
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

function readDays(id) {
  const days = Number($(id).value);
  if (!Number.isInteger(days) || days < 1) throw new Error('Validity must be a whole number of days.');
  return days;
}

// ---------------------------------------------------------------- SSH

async function generateSSHKey() {
  const spec = $('ssh-type').value;
  const key = await Kiwi.generateSshKey(spec, $('ssh-comment').value.trim(), $('ssh-passphrase').value);
  const filename = 'id_' + spec.split('-')[0];
  renderOutput($('ssh-output'), '🔐 SSH Key Generated', key.description, [
    ['Fingerprint', key.fingerprint],
    ['Passphrase', $('ssh-passphrase').value ? 'Yes (bcrypt KDF, aes256-ctr)' : 'None'],
  ], [
    ['Private Key', filename, key.privateKey],
    ['Public Key', filename + '.pub', key.publicKey],
  ]);
  showNotification('SSH key generated', 'success');
}

// ---------------------------------------------------------------- TLS

async function createCA() {
  const commonName = $('ca-name').value.trim();
  if (!commonName) throw new Error('Enter a name for the CA.');
  const passphrase = $('ca-passphrase').value;
  const created = await Kiwi.createCA({ keySpec: $('ca-type').value, commonName, days: readDays('ca-days') });
  const keyPem = await Kiwi.exportPrivateKey(created.privateKey, passphrase);
  setCA(created);
  showCA('🔒 Certificate Authority Created', passphrase ? 'Encrypted (AES-256, PBKDF2)' : 'Unencrypted', keyPem);
  showNotification('Certificate Authority created', 'success');
}

async function uploadCA() {
  const certFile = $('upload-ca-cert').files[0];
  const keyFile = $('upload-ca-key').files[0];
  if (!certFile || !keyFile) throw new Error('Select both the CA certificate and its private key.');
  const [certPem, keyPem] = await Promise.all([certFile.text(), keyFile.text()]);
  setCA(await Kiwi.loadCA(certPem, keyPem, $('upload-ca-passphrase').value));
  showCA('📂 Certificate Authority Loaded', 'Loaded from file', null);
  document.querySelector('.upload-section-container').classList.remove('open');
  showNotification('CA loaded', 'success');
}

function setCA(value) {
  ca = value;
  const status = $('caStatus');
  status.textContent = `CA ready: ${ca.commonName} (valid until ${ca.notAfter.toLocaleDateString()})`;
  status.classList.add('ca-ready');
  $('createCert').disabled = false;
  $('cert-output').replaceChildren();
}

function showCA(title, keyStatus, keyPem) {
  const slug = fileSlug(ca.commonName);
  const files = [['CA Certificate', slug + '.pem', Kiwi.certificatePem(ca.der)]];
  if (keyPem) files.unshift(['CA Private Key', slug + '.key', keyPem]);
  renderOutput($('ca-output'), title, ca.keyDescription, [
    ['Subject', 'CN=' + ca.commonName],
    ['Private key', keyStatus],
    ['Valid', `${ca.notBefore.toLocaleDateString()} – ${ca.notAfter.toLocaleDateString()}`],
    ['Serial', ca.serial],
  ], files);
  $('ssl-placeholder').hidden = true;
}

async function createCertificate() {
  if (!ca) throw new Error('Create or load a CA first.');
  const names = Kiwi.parseSubjectAltNames($('cert-names').value);
  const days = readDays('cert-days');
  const cert = await Kiwi.createServerCertificate(ca, { keySpec: $('cert-type').value, names, days });
  if (cert.notAfter > ca.notAfter) {
    showNotification('Note: the certificate outlives its CA and will stop working when the CA expires.', 'info');
  } else {
    showNotification('Certificate created', 'success');
  }
  const slug = fileSlug(names[0].value);
  renderOutput($('cert-output'), '🔒 Server Certificate Created', cert.keyDescription, [
    ['Subject', 'CN=' + cert.commonName],
    ['Names', names.map(n => n.value).join(', ')],
    ['Issuer', 'CN=' + ca.commonName],
    ['Valid', `${cert.notBefore.toLocaleDateString()} – ${cert.notAfter.toLocaleDateString()}`],
    ['Serial', cert.serial],
  ], [
    ['Private Key', slug + '.key', await Kiwi.exportPrivateKey(cert.privateKey)],
    ['Certificate', slug + '.pem', Kiwi.certificatePem(cert.der)],
  ]);
}

function fileSlug(name) {
  return name.replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_') || 'cert';
}

// ---------------------------------------------------------------- output

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// details: [label, value][]; files: [title, filename, content][]
function renderOutput(container, title, info, details, files) {
  const group = el('div', 'output-group');

  const header = el('div', 'output-header');
  header.append(el('h3', null, title), el('span', 'output-info', info));

  const detailBox = el('div', 'certificate-details');
  for (const [label, value] of details) {
    const row = el('p');
    row.append(el('strong', null, label + ': '), document.createTextNode(value));
    detailBox.append(row);
  }

  group.append(header, detailBox);

  for (const [fileTitle, filename, content] of files) {
    const file = el('div', 'output-file');
    const fileHeader = el('div', 'file-header');
    const actions = el('div', 'file-actions');
    const copy = el('button', 'btn-copy', '📋 Copy');
    const download = el('button', 'btn-download', '💾 Download');
    copy.type = download.type = 'button';
    copy.addEventListener('click', () => writeClipboard(content).then(
      () => showNotification('Copied to clipboard', 'success'),
      () => showNotification('Copy failed', 'error')));
    download.addEventListener('click', () => downloadFile(filename, content));
    actions.append(copy, download);
    fileHeader.append(el('strong', null, `${fileTitle} (${filename})`), actions);

    const textarea = el('textarea');
    textarea.readOnly = true;
    textarea.spellcheck = false;
    textarea.value = content;
    file.append(fileHeader, textarea);
    group.append(file);
  }

  container.replaceChildren(group);
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
