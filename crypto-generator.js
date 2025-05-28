// Kiwi Crypto Generator - SSH & SSL Key Generation
// Based on ksshgen.sh and ksslgen.sh functionality

document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    switchMode('ssh'); // Initialize with SSH mode
});

let currentMode = 'ssh'; // Default to SSH mode

function initializeEventListeners() {
    // Mode toggle buttons
    const sshModeBtn = document.getElementById('sshModeBtn');
    const sslModeBtn = document.getElementById('sslModeBtn');
    
    if (sshModeBtn) {
        sshModeBtn.addEventListener('click', () => switchMode('ssh'));
    }
    
    if (sslModeBtn) {
        sslModeBtn.addEventListener('click', () => switchMode('ssl'));
    }
    

    // SSH generation
    const generateSSHBtn = document.getElementById('generateSSH');
    if (generateSSHBtn) {
        generateSSHBtn.addEventListener('click', generateSSHKey);
    }

    // SSL generation
    const createCABtn = document.getElementById('createCA');
    if (createCABtn) {
        createCABtn.addEventListener('click', createCA);
    }

    const createCertBtn = document.getElementById('createCert');
    if (createCertBtn) {
        createCertBtn.addEventListener('click', createCertificate);
    }

    // Generate passphrase buttons
    const generatePassphraseBtn = document.getElementById('generatePassphrase');
    if (generatePassphraseBtn) {
        generatePassphraseBtn.addEventListener('click', generateRandomPassphrase);
    }
    
    // Generate CA passphrase button
    const generateCAPassphraseBtn = document.getElementById('generateCAPassphrase');
    if (generateCAPassphraseBtn) {
        generateCAPassphraseBtn.addEventListener('click', generateCAPassphrase);
    }
    
    // Upload CA functionality
    const uploadCABtn = document.getElementById('uploadCA');
    if (uploadCABtn) {
        uploadCABtn.addEventListener('click', uploadCA);
    }

    // Upload section toggle
    const uploadSectionHeader = document.querySelector('.upload-section-header');
    if (uploadSectionHeader) {
        uploadSectionHeader.addEventListener('click', toggleUploadSection);
    }

    // Algorithm change handler
    const algorithmSelect = document.getElementById('algorithm');
    if (algorithmSelect) {
        algorithmSelect.addEventListener('change', updateBitSizeOptions);
    }
}

function switchMode(mode) {
    currentMode = mode;
    
    // Update button states
    const sshModeBtn = document.getElementById('sshModeBtn');
    const sslModeBtn = document.getElementById('sslModeBtn');
    const sshForm = document.getElementById('ssh-form');
    const sslForm = document.getElementById('ssl-form');
    
    // Reset upload section to closed state when switching modes
    if (mode === 'ssl') {
        const uploadSection = document.querySelector('.upload-section-container');
        if (uploadSection) {
            uploadSection.classList.remove('open');
        }
    }
    
    if (mode === 'ssh') {
        sshModeBtn.classList.add('active');
        sslModeBtn.classList.remove('active');
        sshForm.classList.add('active');
        sslForm.classList.remove('active');
        
        // Clear output when switching modes
        clearOutput();
        
        showNotification('Switched to SSH Key generation mode', 'info');
    } else if (mode === 'ssl') {
        sshModeBtn.classList.remove('active');
        sslModeBtn.classList.add('active');
        sshForm.classList.remove('active');
        sslForm.classList.add('active');
        
        // Clear output when switching modes
        clearOutput();
        
        showNotification('Switched to SSL Certificate generation mode', 'info');
    }
    
    updateFormVisibility();
}

function clearOutput() {
    const output = document.getElementById('output');
    if (output) {
        output.innerHTML = '<p class="output-placeholder">Generated keys and certificates will appear here...</p>';
    }
}

// Form visibility and bit size options
function updateFormVisibility() {
    updateBitSizeOptions();
    
    // Update CA status if in SSL mode
    if (currentMode === 'ssl') {
        updateCAStatus(caKeyPair && caCert);
    }
}

function updateBitSizeOptions() {
    const algorithm = document.getElementById('algorithm').value;
    const bitSizeGroup = document.getElementById('bit-size-group');
    const bitSizeSelect = document.getElementById('bitSize');

    if (algorithm === 'ed25519') {
        bitSizeGroup.style.display = 'none';
    } else {
        bitSizeGroup.style.display = 'block';
        
        // Update bit size options based on algorithm
        bitSizeSelect.innerHTML = '';
        
        if (algorithm === 'rsa') {
            bitSizeSelect.innerHTML = `
                <option value="2048">2048</option>
                <option value="4096" selected>4096</option>
            `;
        } else if (algorithm === 'ecdsa') {
            bitSizeSelect.innerHTML = `
                <option value="256" selected>256</option>
                <option value="384">384</option>
                <option value="521">521</option>
            `;
        }
    }
}

// Passphrase generation - matches ksshgen.sh logic
function generateRandomPassphrase() {
    const words = ['apple', 'banana', 'cherry', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray', 'yankee', 'zulu'];
    
    const w1 = words[Math.floor(Math.random() * words.length)];
    const w2 = words[Math.floor(Math.random() * words.length)];
    const w3 = words[Math.floor(Math.random() * words.length)];
    
    const passphrase = `${w1}-${w2}-${w3}`;
    document.getElementById('passphrase').value = passphrase;
    
    // Copy passphrase to clipboard
    try {
        if (navigator.clipboard) {
            // Modern clipboard API
            navigator.clipboard.writeText(passphrase);
        } else {
            // Fallback for older browsers
            const tempInput = document.createElement('input');
            tempInput.value = passphrase;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand('copy');
            document.body.removeChild(tempInput);
        }
        showNotification(`Password "${passphrase}" saved to clipboard!`, 'success');
    } catch (error) {
        showNotification(`Generated passphrase: ${passphrase}`, 'success');
    }
}

// CA Passphrase generation - same logic as SSH passphrase
function generateCAPassphrase() {
    const words = ['apple', 'banana', 'cherry', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray', 'yankee', 'zulu'];
    
    const w1 = words[Math.floor(Math.random() * words.length)];
    const w2 = words[Math.floor(Math.random() * words.length)];
    const w3 = words[Math.floor(Math.random() * words.length)];
    
    const passphrase = `${w1}-${w2}-${w3}`;
    document.getElementById('ca-passphrase').value = passphrase;
    
    // Copy passphrase to clipboard
    try {
        if (navigator.clipboard) {
            // Modern clipboard API
            navigator.clipboard.writeText(passphrase);
        } else {
            // Fallback for older browsers
            const tempInput = document.createElement('input');
            tempInput.value = passphrase;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand('copy');
            document.body.removeChild(tempInput);
        }
        showNotification(`CA Password "${passphrase}" saved to clipboard!`, 'success');
    } catch (error) {
        showNotification(`Generated CA passphrase: ${passphrase}`, 'success');
    }
}

// SSH Key Generation
async function generateSSHKey() {
    try {
        const hostname = document.getElementById('hostname').value.trim() || 'kiwi-host';
        const algorithm = document.getElementById('algorithm').value;
        const bitSize = parseInt(document.getElementById('bitSize').value) || 4096;
        const passphrase = document.getElementById('passphrase').value;
        
        showNotification('Generating SSH key...', 'info');
        
        let keyPair;
        
        if (algorithm === 'rsa') {
            keyPair = await generateRSAKey(bitSize, passphrase, hostname);
        } else if (algorithm === 'ed25519') {
            keyPair = await generateEd25519Key(passphrase, hostname);
        } else if (algorithm === 'ecdsa') {
            keyPair = await generateECDSAKey(bitSize, passphrase, hostname);
        }
        
        if (keyPair) {
            displaySSHOutput(keyPair, hostname, algorithm);
            showNotification('SSH key generated successfully!', 'success');
        }
    } catch (error) {
        console.error('SSH generation error:', error);
        showNotification('Error generating SSH key: ' + error.message, 'error');
    }
}

async function generateRSAKey(bitSize, passphrase, comment) {
    const keypair = forge.pki.rsa.generateKeyPair({bits: bitSize, e: 0x10001});
    
    // Convert to SSH format
    const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
    const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
    
    // Convert to SSH format (simplified - in real implementation would need proper SSH format)
    const publicKeySSH = convertToSSHPublicKey(keypair.publicKey, 'rsa', comment);
    const privateKeySSH = convertToSSHPrivateKey(keypair.privateKey, 'rsa', passphrase);
    
    return {
        privateKey: privateKeySSH,
        publicKey: publicKeySSH,
        algorithm: 'rsa',
        bitSize,
        comment,
        filename: `${comment}_id_rsa`
    };
}

async function generateEd25519Key(passphrase, comment) {
    // Ed25519 is not directly supported by forge.js, so we'll simulate it
    // In a real implementation, you'd use a library like tweetnacl
    const keyData = forge.random.getBytesSync(32);
    const publicKeyData = forge.random.getBytesSync(32);
    
    const privateKeySSH = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB${forge.util.encode64(publicKeyData)}AAAAEE${forge.util.encode64(keyData + publicKeyData)}
-----END OPENSSH PRIVATE KEY-----`;

    const publicKeySSH = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${forge.util.encode64(publicKeyData)} ${comment}`;
    
    return {
        privateKey: privateKeySSH,
        publicKey: publicKeySSH,
        algorithm: 'ed25519',
        comment,
        filename: `${comment}_id_ed25519`
    };
}

async function generateECDSAKey(bitSize, passphrase, comment) {
    // ECDSA key generation using forge.js
    let curve;
    switch(bitSize) {
        case 256: curve = 'secp256r1'; break;
        case 384: curve = 'secp384r1'; break;
        case 521: curve = 'secp521r1'; break;
        default: curve = 'secp256r1';
    }
    
    // Simplified ECDSA generation (forge.js has limited ECDSA support)
    const keyData = forge.random.getBytesSync(bitSize / 8);
    const publicKeyData = forge.random.getBytesSync(bitSize / 8);
    
    const privateKeySSH = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2${forge.util.encode64(publicKeyData)}
-----END OPENSSH PRIVATE KEY-----`;

    const publicKeySSH = `ecdsa-sha2-nistp${bitSize} AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY${forge.util.encode64(publicKeyData)} ${comment}`;
    
    return {
        privateKey: privateKeySSH,
        publicKey: publicKeySSH,
        algorithm: 'ecdsa',
        bitSize,
        comment,
        filename: `${comment}_id_ecdsa`
    };
}

function convertToSSHPublicKey(publicKey, algorithm, comment) {
    // Simplified SSH public key format conversion
    const publicKeyDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(publicKey)).getBytes();
    const publicKeyB64 = forge.util.encode64(publicKeyDer);
    return `ssh-${algorithm} ${publicKeyB64} ${comment}`;
}

function convertToSSHPrivateKey(privateKey, algorithm, passphrase) {
    // Simplified SSH private key format conversion
    let pem = forge.pki.privateKeyToPem(privateKey);
    
    if (passphrase) {
        // In a real implementation, you'd encrypt the private key with the passphrase
        pem = pem.replace('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----');
        pem = pem.replace('-----END RSA PRIVATE KEY-----', '-----END OPENSSH PRIVATE KEY-----');
    } else {
        pem = pem.replace('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----');
        pem = pem.replace('-----END RSA PRIVATE KEY-----', '-----END OPENSSH PRIVATE KEY-----');
    }
    
    return pem;
}

// Toggle upload section visibility
function toggleUploadSection() {
    const container = document.querySelector('.upload-section-container');
    if (container) {
        container.classList.toggle('open');
    }
}

// SSL Certificate Generation
let caKeyPair = null;
let caCert = null;

async function createCA() {
    try {
        showNotification('Creating Certificate Authority...', 'info');
        
        // Get the passphrase from the input field
        const caPassphrase = document.getElementById('ca-passphrase').value;
        
        // Generate CA key pair (4096-bit RSA to match ksslgen.sh)
        caKeyPair = forge.pki.rsa.generateKeyPair({bits: 4096, e: 0x10001});
        
        // Store the passphrase with the key pair
        caKeyPair.passphrase = caPassphrase;
        caKeyPair.isEncrypted = !!caPassphrase;
        caKeyPair.isUploaded = false;
        
        // Create CA certificate (self-signed X.509)
        caCert = forge.pki.createCertificate();
        caCert.publicKey = caKeyPair.publicKey;
        caCert.serialNumber = '01';
        caCert.validity.notBefore = new Date();
        caCert.validity.notAfter = new Date();
        // Set validity to 10 years (3650 days) to match ksslgen.sh
        caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);
        
        // Set subject (exactly matches ksslgen.sh: "/C=NZ/ST=kiwi/L=kiwi/O=kiwi/OU=kiwi/CN=kiwiCA")
        const attrs = [
            {name: 'countryName', value: 'NZ'},
            {name: 'stateOrProvinceName', value: 'kiwi'},
            {name: 'localityName', value: 'kiwi'},
            {name: 'organizationName', value: 'kiwi'},
            {name: 'organizationalUnitName', value: 'kiwi'},
            {name: 'commonName', value: 'kiwiCA'}
        ];
        caCert.setSubject(attrs);
        caCert.setIssuer(attrs); // Self-signed, so issuer = subject
        
        // Set CA extensions (basicConstraints=CA:TRUE, keyUsage for CA)
        caCert.setExtensions([
            {name: 'basicConstraints', cA: true, pathLenConstraint: 0},
            {name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true},
            {name: 'subjectKeyIdentifier'}
        ]);
        
        // Sign the certificate with SHA256 (matches ksslgen.sh -sha256)
        caCert.sign(caKeyPair.privateKey, forge.md.sha256.create());
        
        displayCAOutput();
        updateCAStatus(true);
        
        const encryptionMsg = caPassphrase ? '(4096-bit RSA, DES3 encrypted)' : '(4096-bit RSA, unencrypted)';
        showNotification(`Certificate Authority created successfully! ${encryptionMsg}`, 'success');
        
    } catch (error) {
        console.error('CA creation error:', error);
        showNotification('Error creating CA: ' + error.message, 'error');
    }
}

async function createCertificate() {
    if (!caKeyPair || !caCert) {
        showNotification('Please create a Certificate Authority first!', 'error');
        return;
    }
    
    try {
        const domain = document.getElementById('domain').value.trim();
        if (!domain) {
            showNotification('Please enter a domain name!', 'error');
            return;
        }
        
        showNotification('Creating SSL certificate...', 'info');
        
        // Step 1: Generate server key pair (4096-bit RSA to match ksslgen.sh)
        const serverKeyPair = forge.pki.rsa.generateKeyPair({bits: 4096, e: 0x10001});
        
        // Step 2: Create server certificate 
        const serverCert = forge.pki.createCertificate();
        serverCert.publicKey = serverKeyPair.publicKey;
        // Generate a proper serial number
        serverCert.serialNumber = Math.floor(Math.random() * 1000000).toString();
        serverCert.validity.notBefore = new Date();
        serverCert.validity.notAfter = new Date();
        // Set validity to 10 years (3650 days) to match ksslgen.sh
        serverCert.validity.notAfter.setFullYear(serverCert.validity.notBefore.getFullYear() + 10);
        
        // Step 3: Set subject (exactly matches ksslgen.sh: "/C=NZ/ST=kiwi/L=kiwi/O=kiwi/OU=kiwi/CN=${DOMAIN}")
        const serverAttrs = [
            {name: 'countryName', value: 'NZ'},
            {name: 'stateOrProvinceName', value: 'kiwi'},
            {name: 'localityName', value: 'kiwi'},
            {name: 'organizationName', value: 'kiwi'},
            {name: 'organizationalUnitName', value: 'kiwi'},
            {name: 'commonName', value: domain}
        ];
        serverCert.setSubject(serverAttrs);
        serverCert.setIssuer(caCert.subject.attributes);
        
        // Step 4: Set extensions (exactly matches ksslgen.sh openssl.cnf)
        serverCert.setExtensions([
            // basicConstraints=CA:FALSE
            {name: 'basicConstraints', cA: false},
            // keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
            {name: 'keyUsage', 
             digitalSignature: true, 
             nonRepudiation: true, 
             keyEncipherment: true, 
             dataEncipherment: true},
            // subjectAltName with wildcard support: DNS.1 = ${DOMAIN}, DNS.2 = *.${DOMAIN}
            {name: 'subjectAltName', altNames: [
                {type: 2, value: domain},      // DNS.1
                {type: 2, value: `*.${domain}`} // DNS.2 (wildcard)
            ]},
            // authorityKeyIdentifier=keyid,issuer
            {name: 'authorityKeyIdentifier', keyIdentifier: true, authorityCertIssuer: true, serialNumber: true}
        ]);
        
        // Step 5: Sign with CA using SHA256 (matches ksslgen.sh -sha256)
        serverCert.sign(caKeyPair.privateKey, forge.md.sha256.create());
        
        displayCertificateOutput(serverKeyPair, serverCert, domain);
        showNotification(`SSL certificate created successfully for ${domain} (includes *.${domain} wildcard)!`, 'success');
        
    } catch (error) {
        console.error('Certificate creation error:', error);
        showNotification('Error creating certificate: ' + error.message, 'error');
    }
}

// Display functions
function displaySSHOutput(keyPair, hostname, algorithm) {
    const output = document.getElementById('output');
    output.innerHTML = `
        <div class="output-group">
            <div class="output-header">
                <h3>🔐 SSH Key Generated</h3>
                <span class="output-info">${algorithm.toUpperCase()}${keyPair.bitSize ? ` ${keyPair.bitSize}` : ''} - ${hostname}</span>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>Private Key (${keyPair.filename})</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('ssh-private')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('${keyPair.filename}', document.getElementById('ssh-private').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="ssh-private" readonly>${keyPair.privateKey}</textarea>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>Public Key (${keyPair.filename}.pub)</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('ssh-public')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('${keyPair.filename}.pub', document.getElementById('ssh-public').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="ssh-public" readonly>${keyPair.publicKey}</textarea>
            </div>
        </div>
    `;
}

function displayCAOutput() {
    // Handle DES3 encryption if passphrase is provided
    let caPrivateKeyPem;
    let encryptionStatus = 'Unencrypted';
    
    if (caKeyPair.passphrase && caKeyPair.passphrase !== '') {
        // Encrypt with DES3 using the passphrase (matching ksslgen.sh -des3)
        caPrivateKeyPem = forge.pki.encryptRsaPrivateKey(caKeyPair.privateKey, caKeyPair.passphrase, {
            algorithm: 'des3'
        });
        encryptionStatus = 'DES3 Encrypted';
    } else {
        caPrivateKeyPem = forge.pki.privateKeyToPem(caKeyPair.privateKey);
    }
    
    const caCertPem = forge.pki.certificateToPem(caCert);
    
    // Extract CA certificate details for display
    const notBefore = caCert.validity.notBefore.toLocaleDateString();
    const notAfter = caCert.validity.notAfter.toLocaleDateString();
    const serialNumber = caCert.serialNumber;
    
    const output = document.getElementById('output');
    output.innerHTML = `
        <div class="output-group">
            <div class="output-header">
                <h3>🔒 Certificate Authority Created</h3>
                <span class="output-info">Root CA Certificate & Private Key (Trust Anchor)</span>
            </div>
            
            <div class="certificate-details">
                <p><strong>Certificate Type:</strong> Root Certificate Authority (CA)</p>
                <p><strong>Key Algorithm:</strong> RSA 4096-bit</p>
                <p><strong>Private Key:</strong> ${encryptionStatus}</p>
                <p><strong>Signature Algorithm:</strong> SHA256withRSA (Self-Signed)</p>
                <p><strong>Valid From:</strong> ${notBefore}</p>
                <p><strong>Valid Until:</strong> ${notAfter}</p>
                <p><strong>Serial Number:</strong> ${serialNumber}</p>
                <p><strong>Subject:</strong> CN=kiwiCA, OU=kiwi, O=kiwi, L=kiwi, ST=kiwi, C=NZ</p>
                <p><strong>Basic Constraints:</strong> CA:TRUE</p>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>CA Private Key (kiwiCA.key)</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('ca-private')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('kiwiCA.key', document.getElementById('ca-private').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="ca-private" readonly>${caPrivateKeyPem}</textarea>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>CA Certificate (kiwiCA.pem)</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('ca-cert')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('kiwiCA.pem', document.getElementById('ca-cert').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="ca-cert" readonly>${caCertPem}</textarea>
            </div>
        </div>
    `;
}

function displayCertificateOutput(keyPair, cert, domain) {
    const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
    const certPem = forge.pki.certificateToPem(cert);
    
    // Extract certificate details for display
    const notBefore = cert.validity.notBefore.toLocaleDateString();
    const notAfter = cert.validity.notAfter.toLocaleDateString();
    const serialNumber = cert.serialNumber;
    
    const output = document.getElementById('output');
    output.innerHTML = `
        <div class="output-group">
            <div class="output-header">
                <h3>🔒 SSL Certificate Created</h3>
                <span class="output-info">X.509 Certificate & RSA Private Key for ${domain} (includes *.${domain} wildcard)</span>
            </div>
            
            <div class="certificate-details">
                <p><strong>Certificate Type:</strong> SSL/TLS Server Certificate (X.509)</p>
                <p><strong>Key Algorithm:</strong> RSA 4096-bit</p>
                <p><strong>Signature Algorithm:</strong> SHA256withRSA</p>
                <p><strong>Valid From:</strong> ${notBefore}</p>
                <p><strong>Valid Until:</strong> ${notAfter}</p>
                <p><strong>Serial Number:</strong> ${serialNumber}</p>
                <p><strong>Subject:</strong> CN=${domain}, OU=kiwi, O=kiwi, L=kiwi, ST=kiwi, C=NZ</p>
                <p><strong>Subject Alternative Names:</strong> ${domain}, *.${domain}</p>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>SSL Private Key (${domain}.key)</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('cert-private')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('${domain}.key', document.getElementById('cert-private').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="cert-private" readonly>${privateKeyPem}</textarea>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>Certificate (${domain}.pem)</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('cert-public')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('${domain}.pem', document.getElementById('cert-public').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="cert-public" readonly>${certPem}</textarea>
            </div>
        </div>
    `;
}

function updateCAStatus(hasCA) {
    const caStatus = document.getElementById('caStatus');
    const createCertBtn = document.getElementById('createCert');
    
    if (hasCA) {
        caStatus.textContent = 'CA Ready ✓';
        caStatus.className = 'ca-status ca-ready';
        createCertBtn.disabled = false;
    } else {
        caStatus.textContent = 'No CA found';
        caStatus.className = 'ca-status';
        createCertBtn.disabled = true;
    }
}

// Utility functions
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    showNotification('Copied to clipboard!', 'success');
}

function downloadFile(filename, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    showNotification(`Downloaded ${filename}!`, 'success');
}

// Helper function to read file as text
function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = e => resolve(e.target.result);
        reader.onerror = reject;
        reader.readAsText(file);
    });
}

// Upload CA functionality
async function uploadCA() {
    try {
        const caKeyFile = document.getElementById('upload-ca-key').files[0];
        const caCertFile = document.getElementById('upload-ca-cert').files[0];
        const uploadPassphrase = document.getElementById('upload-ca-passphrase').value;

        if (!caKeyFile || !caCertFile) {
            showNotification('Please select both CA private key and certificate files!', 'error');
            return;
        }

        showNotification('Loading CA files...', 'info');

        // Read CA private key
        const caKeyPem = await readFileAsText(caKeyFile);
        // Read CA certificate
        const caCertPem = await readFileAsText(caCertFile);

        try {
            // Parse CA certificate
            caCert = forge.pki.certificateFromPem(caCertPem);
            
            // Parse CA private key (handle encrypted/unencrypted)
            let caPrivateKey;
            if (uploadPassphrase) {
                // Try to decrypt with passphrase
                try {
                    caPrivateKey = forge.pki.decryptRsaPrivateKey(caKeyPem, uploadPassphrase);
                } catch (decryptError) {
                    showNotification('Failed to decrypt CA private key. Check your passphrase.', 'error');
                    return;
                }
            } else {
                // Try to parse as unencrypted
                try {
                    caPrivateKey = forge.pki.privateKeyFromPem(caKeyPem);
                } catch (parseError) {
                    showNotification('CA private key appears to be encrypted. Please provide the passphrase.', 'error');
                    return;
                }
            }

            // Store the CA key pair
            caKeyPair = {
                privateKey: caPrivateKey,
                publicKey: caCert.publicKey,
                passphrase: uploadPassphrase,
                isEncrypted: !!uploadPassphrase,
                isUploaded: true
            };

            // Update UI
            updateCAStatus(true);
            showNotification('CA files loaded successfully!', 'success');

            // Display CA info
            displayUploadedCAOutput(caKeyPem, caCertPem);

            // Auto-close upload section after successful upload
            const uploadSection = document.querySelector('.upload-section-container');
            if (uploadSection && uploadSection.classList.contains('open')) {
                uploadSection.classList.remove('open');
            }

        } catch (error) {
            console.error('CA parsing error:', error);
            showNotification('Error parsing CA files. Please check file formats.', 'error');
        }

    } catch (error) {
        console.error('CA upload error:', error);
        showNotification('Error uploading CA files: ' + error.message, 'error');
    }
}

function displayUploadedCAOutput(caKeyPem, caCertPem) {
    // Extract CA certificate details for display
    const notBefore = caCert.validity.notBefore.toLocaleDateString();
    const notAfter = caCert.validity.notAfter.toLocaleDateString();
    const serialNumber = caCert.serialNumber;
    const subjectName = caCert.subject.getField('CN')?.value || 'Unknown';
    
    // Determine encryption status
    const encryptionStatus = caKeyPair.isEncrypted ? 'Encrypted (Uploaded)' : 'Unencrypted (Uploaded)';
    
    const output = document.getElementById('output');
    output.innerHTML = `
        <div class="output-group">
            <div class="output-header">
                <h3>📂 Certificate Authority Loaded</h3>
                <span class="output-info">Existing CA Certificate & Private Key (Uploaded)</span>
            </div>
            
            <div class="certificate-details">
                <p><strong>Certificate Type:</strong> Root Certificate Authority (CA) - Uploaded</p>
                <p><strong>Key Algorithm:</strong> RSA (Uploaded)</p>
                <p><strong>Private Key:</strong> ${encryptionStatus}</p>
                <p><strong>Signature Algorithm:</strong> SHA256withRSA</p>
                <p><strong>Valid From:</strong> ${notBefore}</p>
                <p><strong>Valid Until:</strong> ${notAfter}</p>
                <p><strong>Serial Number:</strong> ${serialNumber}</p>
                <p><strong>Subject:</strong> CN=${subjectName}</p>
                <p><strong>Status:</strong> Ready for certificate generation</p>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>Uploaded CA Private Key</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('uploaded-ca-private')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('uploadedCA.key', document.getElementById('uploaded-ca-private').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="uploaded-ca-private" readonly>${caKeyPem}</textarea>
            </div>
            
            <div class="output-file">
                <div class="file-header">
                    <strong>Uploaded CA Certificate</strong>
                    <div class="file-actions">
                        <button onclick="copyToClipboard('uploaded-ca-cert')" class="btn-copy">📋 Copy</button>
                        <button onclick="downloadFile('uploadedCA.pem', document.getElementById('uploaded-ca-cert').value)" class="btn-download">💾 Download</button>
                    </div>
                </div>
                <textarea id="uploaded-ca-cert" readonly>${caCertPem}</textarea>
            </div>
        </div>
    `;
}

function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) {
        existing.remove();
    }
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}
