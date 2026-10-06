# 🥝 Kiwi Key Generator

> *Kiwi Key Generator is a browser-based tool for generating SSH keys and SSL certificates locally, without sending any data to external servers. It provides a clean, user-friendly interface for cryptographic operations that are typically performed via command line tools.*

<div align="center">

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Powered By: JavaScript](https://img.shields.io/badge/Powered%20By-JavaScript-blue.svg)

![Kiwi Key Generator Screenshot](kiwi-gen.png)

</div>

## 🚀 Live Demo

Try the live demo directly in your browser: [Kiwi Key Generator](https://derlocke-ng.github.io/kiwi-gen/)

## ✨ Features

### SSH Keys
- Ed25519, ECDSA (P-256/384/521) and RSA (3072/4096)
- Real OpenSSH format (`id_ed25519` / `id_ed25519.pub`), accepted by `ssh`, `ssh-keygen` and `ssh-add`
- Optional passphrase, encrypted like `ssh-keygen` does (bcrypt KDF, aes256-ctr)
- SHA256 fingerprint shown for verification

### SSL/TLS Certificates
- Create a local Certificate Authority (ECDSA or RSA), with an optionally encrypted key (PKCS#8, AES-256)
- Or load an existing CA (PEM certificate plus PKCS#8, PKCS#1 or SEC1 key, plain or encrypted)
- Issue server certificates for any mix of hostnames, wildcards and IP addresses
- Certificates verify with `openssl verify -x509_strict -purpose sslserver` and meet Apple's requirements for TLS server certificates

## 🔧 Usage

Open `index.html` in a modern browser (works straight from disk), or serve the folder:

```bash
git clone https://github.com/derlocke-ng/kiwi-gen.git
cd kiwi-gen
python3 -m http.server 8000
```

Then open `http://localhost:8000`. WebCrypto only works in secure contexts, so serving over plain HTTP from another machine won't work; use HTTPS, localhost or `file://`.

To use your CA, import its certificate (`.pem`) into your OS or browser trust store, then configure your server with the certificate and key you generated.

## 💻 How It Works

All cryptography uses the browser's built-in [Web Crypto API](https://developer.mozilla.org/docs/Web/API/Web_Crypto_API). The OpenSSH, X.509 and PKCS#8 encoding lives in `kiwi-crypto.js` (one file, no dependencies). There is no build step and nothing is loaded from a CDN. A Content-Security-Policy blocks all network requests, so keys can't leave the page.

Ed25519 needs a current browser (Chrome 137+, Firefox 129+, Safari 17+).
