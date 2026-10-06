// Kiwi Key Generator - encrypted vault: storage, state and the Vault tab.
// The vault lives in localStorage as an encrypted blob (see Kiwi.sealVault); it is only ever
// decrypted in memory while unlocked.

const Vault = (() => {
  const STORAGE_KEY = 'kiwi-gen-vault';
  let session = null; // { key, salt, iterations } while unlocked
  let items = [];
  const summaries = new Map(); // item id -> summary, computed lazily

  // localStorage can be unavailable (private windows, blocked storage); the vault then only lives in memory.
  const storage = {
    get() { try { return localStorage.getItem(STORAGE_KEY); } catch { return null; } },
    set(value) { try { localStorage.setItem(STORAGE_KEY, value); return true; } catch { return false; } },
    remove() { try { localStorage.removeItem(STORAGE_KEY); } catch { /* nothing stored */ } },
  };

  const exists = () => !!storage.get();
  const isUnlocked = () => !!session;

  async function persist() {
    const sealed = await Kiwi.sealVault(session, { version: 1, items });
    if (!storage.set(sealed)) showNotification('Could not save to browser storage. Export the vault to keep your changes.', 'error');
    render();
    return sealed;
  }

  function readPasswords(id1, id2) {
    const password = $(id1).value;
    if (password !== $(id2).value) throw new Error('The passwords do not match.');
    return password;
  }

  async function create() {
    session = await Kiwi.createVaultSession(readPasswords('vault-new-password', 'vault-new-password2'));
    items = [];
    $('vault-new-password').value = $('vault-new-password2').value = '';
    await persist();
    showNotification('Vault created. New keys and certificates will be saved to it.', 'success');
  }

  async function unlock() {
    const stored = storage.get();
    if (!stored) throw new Error('No vault is stored in this browser.');
    const opened = await Kiwi.openVault(stored, $('vault-password').value);
    session = opened.session;
    items = opened.data.items || [];
    $('vault-password').value = '';
    render();
    showNotification(`Vault unlocked (${items.length} items)`, 'success');
  }

  // Opening a file while locked replaces the stored vault; use "Add" to merge into an unlocked one.
  async function openFile() {
    const file = $('vault-open-file').files[0];
    if (!file) throw new Error('Choose a vault file.');
    if (exists() && !confirm('Replace the vault stored in this browser with this file?')) return;
    const opened = await Kiwi.openVault(await file.text(), $('vault-open-password').value);
    session = opened.session;
    items = opened.data.items || [];
    $('vault-open-password').value = '';
    $('vault-open-file').value = '';
    await persist();
    showNotification(`Vault opened (${items.length} items)`, 'success');
  }

  function lock() {
    session = null;
    items = [];
    summaries.clear();
    render();
    showNotification('Vault locked', 'info');
  }

  function forget() {
    if (!confirm('Delete the vault stored in this browser? This cannot be undone. Export it first if you want to keep it.')) return;
    storage.remove();
    lock();
  }

  async function exportFile() {
    const sealed = await persist();
    downloadFile(`kiwi-vault-${new Date().toISOString().slice(0, 10)}.kiwi.json`, sealed);
  }

  async function changePassword() {
    const fresh = await Kiwi.createVaultSession(readPasswords('vault-change-password', 'vault-change-password2'));
    session = fresh;
    $('vault-change-password').value = $('vault-change-password2').value = '';
    await persist();
    showNotification('Master password changed. Exported copies keep their old password.', 'success');
  }

  async function add(newItems) {
    items.push(...newItems);
    await persist();
  }

  async function importExisting() {
    const text = $('vault-import-text').value;
    const file = $('vault-import-file').files[0];
    const passphrase = $('vault-import-passphrase').value;
    let input = text;
    if (!text.trim()) {
      if (!file) throw new Error('Paste something or choose a file.');
      input = new Uint8Array(await file.arrayBuffer());
      const asText = new TextDecoder().decode(input);
      if (Kiwi.isVaultFile(asText)) {
        const other = await Kiwi.openVault(asText, passphrase);
        const known = new Set(items.map(i => i.id));
        const fresh = (other.data.items || []).filter(i => !known.has(i.id));
        await add(fresh);
        clearImportForm();
        showNotification(`Merged ${fresh.length} new items from the vault file`, 'success');
        return;
      }
    }
    const found = await Kiwi.importItems(input, passphrase);
    await add(found);
    clearImportForm();
    showNotification(`Added ${found.length} item${found.length === 1 ? '' : 's'} to the vault`, 'success');
  }

  function clearImportForm() {
    $('vault-import-text').value = $('vault-import-passphrase').value = $('vault-import-file').value = '';
  }

  // Called by the generator tabs. Returns true when the item went into the vault.
  async function store(makeItem) {
    if (!session) return false;
    await add([await makeItem()]);
    return true;
  }

  const savedNote = saved => saved ? ' and saved to the vault' : exists() ? ' (vault locked, not saved)' : '';

  async function summary(item) {
    if (!summaries.has(item.id)) {
      summaries.set(item.id, await Kiwi.summarizeItem(item).catch(e => ({ label: 'Unreadable item', description: e.message })));
    }
    return summaries.get(item.id);
  }

  // ---------------------------------------------------------------- rendering

  const KIND_ORDER = { 'Root CA': 0, 'Intermediate CA': 1, 'SSH CA': 2 };

  async function render() {
    const unlocked = isUnlocked();
    $('vault-locked').hidden = unlocked;
    $('vault-unlocked').hidden = !unlocked;
    $('vault-create').hidden = exists();
    $('vault-unlock').hidden = !exists();
    $('vaultForget').hidden = !exists();
    $('vault-open-title').textContent = exists() ? 'Or open a different vault file (replaces this one)' : 'Or open a vault file';

    const rows = unlocked ? await Promise.all(items.map(async item => ({ item, s: await summary(item) }))) : [];
    rows.sort((a, b) => (KIND_ORDER[a.s.label] ?? 9) - (KIND_ORDER[b.s.label] ?? 9) || a.item.name.localeCompare(b.item.name));
    renderPickers(rows);
    if (!unlocked) return;

    const expiring = rows.filter(r => r.s.expires && r.s.expires - Date.now() < 30 * 86400000).length;
    $('vault-status').textContent = `${items.length} item${items.length === 1 ? '' : 's'}` +
      (expiring ? ` · ${expiring} expired or expiring within 30 days` : '') +
      (storage.get() ? ' · saved in this browser' : ' · not saved in this browser, export to keep it');

    const query = $('vault-search').value.trim().toLowerCase();
    const list = $('vault-list');
    const open = new Set([...list.querySelectorAll('.vault-item.open')].map(n => n.dataset.id));
    const shown = rows.filter(({ item, s }) =>
      !query || [item.name, item.notes, s.label, s.description].join(' ').toLowerCase().includes(query));
    list.replaceChildren(...shown.map(({ item, s }) => renderItem(item, s, open.has(item.id))));
    if (!shown.length) {
      list.append(el('p', 'output-placeholder', items.length ? 'Nothing matches.' : 'The vault is empty. Create keys or certificates in the other tabs, or add existing ones above.'));
    }
  }

  function expiryBadge(expires) {
    if (!expires) return null;
    const days = Math.floor((expires - Date.now()) / 86400000);
    if (days < 0) return el('span', 'badge badge-bad', 'Expired');
    if (days < 30) return el('span', 'badge badge-warn', `Expires in ${days} day${days === 1 ? '' : 's'}`);
    return el('span', 'badge', `Until ${expires.toLocaleDateString()}`);
  }

  function renderItem(item, s, isOpen) {
    const node = el('div', 'vault-item' + (isOpen ? ' open' : ''));
    node.dataset.id = item.id;

    const head = el('div', 'vault-item-head');
    const main = el('div', 'vault-item-main');
    const title = el('div', 'vault-item-title');
    title.append(el('strong', null, item.name), el('span', 'badge', s.label));
    if (s.hasPrivateKey) title.append(el('span', 'badge', '🔑 private key'));
    const badge = expiryBadge(s.expires);
    if (badge) title.append(badge);
    main.append(title, el('div', 'vault-item-desc', s.description || ''));

    const actions = el('div', 'file-actions');
    const toggle = button(isOpen ? 'Close' : 'Open', 'btn-copy');
    const remove = button('Delete', 'btn-download btn-danger');
    actions.append(toggle, remove);
    head.append(main, actions);

    const details = el('div', 'vault-item-details');
    details.hidden = !isOpen;
    node.append(head, details);

    toggle.addEventListener('click', () => {
      const opening = details.hidden;
      details.hidden = !opening;
      node.classList.toggle('open', opening);
      toggle.textContent = opening ? 'Close' : 'Open';
      if (opening && !details.childElementCount) busy(toggle, () => renderDetails(item, s, details)).then(() => { toggle.textContent = 'Close'; });
    });
    remove.addEventListener('click', () => busy(remove, async () => {
      if (!confirm(`Delete "${item.name}" from the vault?${s.hasPrivateKey ? ' Its private key will be gone unless you exported it.' : ''}`)) return;
      items = items.filter(i => i.id !== item.id);
      summaries.delete(item.id);
      await persist();
      showNotification(`Deleted "${item.name}"`, 'info');
    }));
    if (isOpen) busy(toggle, () => renderDetails(item, s, details)).then(() => { toggle.textContent = 'Close'; });
    return node;
  }

  async function renderDetails(item, s, container) {
    const form = el('div', 'form-container');

    const nameGroup = el('div', 'form-group');
    const nameInput = el('input');
    nameInput.value = item.name;
    nameGroup.append(el('label', null, 'Name'), nameInput);

    const notesGroup = el('div', 'form-group');
    const notes = el('textarea');
    notes.rows = 2;
    notes.value = item.notes || '';
    notes.placeholder = 'Where it is deployed, who owns it, …';
    notesGroup.append(el('label', null, 'Notes'), notes);

    const buttons = el('div', 'file-actions');
    const save = button('Save changes', 'btn-secondary');
    save.addEventListener('click', () => busy(save, async () => {
      const name = nameInput.value.trim();
      if (!name) throw new Error('The name cannot be empty.');
      Object.assign(items.find(i => i.id === item.id), { name, notes: notes.value });
      await persist();
      showNotification('Saved', 'success');
    }));
    buttons.append(save);
    if (s.isCA && s.hasPrivateKey) {
      const use = button(item.kind === 'x509' ? 'Use as TLS CA' : 'Use as SSH CA', 'btn-secondary');
      use.addEventListener('click', () => busy(use, () => useAsCA(item)));
      buttons.append(use);
    }

    const passGroup = el('div', 'form-group');
    const pass = el('input');
    pass.type = 'password';
    pass.autocomplete = 'new-password';
    pass.placeholder = 'Leave empty for unencrypted downloads';
    passGroup.append(el('label', null, item.kind === 'x509' && s.hasPrivateKey
      ? 'Passphrase for downloaded keys (also adds a .p12 bundle)' : 'Passphrase for downloaded keys'), pass);

    const output = el('div');
    const showFiles = async () => {
      const d = await Kiwi.itemDetails(item, pass.value);
      output.replaceChildren(renderOutput(s.label, s.description.split(' · ')[0], d.rows, d.files));
    };
    pass.addEventListener('change', () => busy(save, showFiles));

    form.append(nameGroup, notesGroup, buttons);
    if (item.kind !== 'ssh-cert' && s.hasPrivateKey) form.append(passGroup);
    container.replaceChildren(form, output);
    await showFiles();
  }

  async function useAsCA(item) {
    const value = await Kiwi.caFromItem(item);
    if (item.kind === 'x509') {
      setCA(value);
      showCA('🗄️ CA from the Vault', 'Stored in the vault', null);
      switchMode('ssl-mode');
    } else {
      setSshCA(value, value);
      showSshCA('🗄️ SSH CA from the Vault', value, 'Stored in the vault', null);
      switchMode('sshcert-mode');
    }
    showNotification(`Using "${item.name}" as CA`, 'success');
  }

  // Dropdowns in the generator tabs that pick CAs and public keys from the vault.
  function renderPickers(rows) {
    const fill = (select, label, entries) => {
      select.replaceChildren(el('option', null, label), ...entries.map(({ item, s }) => {
        const option = el('option', null, `${item.name} (${s.label})`);
        option.value = item.id;
        return option;
      }));
      (select.classList.contains('vault-picker') ? select : select.parentElement).hidden = !entries.length;
    };
    const tlsCAs = rows.filter(r => r.item.kind === 'x509' && r.s.isCA && r.s.hasPrivateKey);
    const keys = rows.filter(r => r.item.kind === 'key');
    fill($('ca-vault'), 'Choose a CA…', tlsCAs);
    fill($('sshca-vault'), 'Choose a key…', keys.filter(r => r.s.hasPrivateKey));
    fill($('sshcert-vault-key'), 'Pick a public key from the vault…', keys);
  }

  function pickedItem(select) {
    const item = items.find(i => i.id === select.value);
    select.selectedIndex = 0;
    return item;
  }

  function button(text, className) {
    const b = el('button', className, text);
    b.type = 'button';
    return b;
  }

  document.addEventListener('DOMContentLoaded', () => {
    const actions = {
      vaultCreate: create, vaultUnlock: unlock, vaultOpenFile: openFile, vaultForget: forget,
      vaultExport: exportFile, vaultLock: lock, vaultImport: importExisting, vaultChangePassword: changePassword,
    };
    for (const [id, action] of Object.entries(actions)) $(id).addEventListener('click', e => busy(e.target, action));
    $('vault-password').addEventListener('keydown', e => { if (e.key === 'Enter') $('vaultUnlock').click(); });
    $('vault-search').addEventListener('input', () => render());
    $('ca-vault').addEventListener('change', e => { const item = pickedItem(e.target); if (item) busy($('createCA'), () => useAsCA(item)); });
    $('sshca-vault').addEventListener('change', e => { const item = pickedItem(e.target); if (item) busy($('createSshCA'), () => useAsCA(item)); });
    $('sshcert-vault-key').addEventListener('change', e => {
      const item = pickedItem(e.target);
      if (item) $('sshcert-pubkey').value = item.publicKey.trim();
    });
    if (exists()) switchMode('vault-mode');
    render();
  });

  return { store, savedNote, isUnlocked };
})();
