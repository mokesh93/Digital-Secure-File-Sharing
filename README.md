# 🔐 Digital Secure File Sharing (RSA-4096 + AES-256 Hybrid Cryptography)

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Standard](https://img.shields.io/badge/Cryptography-RSA--4096%20%7C%20AES--256--GCM-green.svg)]()

A complete, beginner-friendly, production-grade secure file sharing system built in Python. Designed as a hands-on cybersecurity internship project, this application demonstrates industry-standard **Hybrid Cryptography** (RSA-4096 key exchange & signatures combined with AES-256-GCM symmetric file encryption).

---

## 📌 Features

- **🔐 4096-bit RSA Key Generation**: Automatically generates high-security 4096-bit RSA key pairs (`private_key.pem` and `public_key.pem`) for User A and User B using PKCS#8 formatting.
- **🔒 AES-256-GCM + RSA-OAEP Hybrid Encryption**: High-speed symmetric encryption for files of any size, with symmetric AES keys wrapped using 4096-bit RSA public keys.
- **✍️ Digital Signatures (SHA-256 + RSA-PSS)**: Sender signs file content hashes to guarantee authenticity and non-repudiation.
- **🛡️ Tamper Detection & Verification**: Recipient verifies digital signatures and AES-GCM authentication tags before decrypting payload.
- **🖥️ Dual User Interfaces**: Includes both a full-featured, modern **Tkinter Desktop GUI** and an interactive **Command-Line Interface (CLI)** menu.
- **📜 Comprehensive Audit Logging**: Logs key generation, encryption, decryption, and verification events to `app.log`.

---

## 🏗️ System Architecture & Hybrid Cryptography Workflow

Raw RSA encryption is computationally heavy and limited by key length. Industry standards use **Hybrid Encryption**:

```
                  ┌─────────────────────────────────────────────────┐
                  │                 SENDER (User A)                 │
                  └─────────────────────────────────────────────────┘
                                           │
  1. Generate Random 256-bit AES Key ──────┼─────────┐
                                           │         │
  2. Encrypt File with AES-256-GCM  ───────┴─► [ Encrypted File Payload ]
                                                     │
  3. Encrypt AES Key with Recipient's                │
     RSA-4096 Public Key (RSA-OAEP)   ───────────► [ Encrypted Key Header ]
                                                     │
  4. Sign File Hash with Sender's                    │
     RSA-4096 Private Key (RSA-PSS)   ───────────► [ Digital Signature (.sig) ]
                                                     │
                                                     ▼
                  ┌─────────────────────────────────────────────────┐
                  │                RECIPIENT (User B)               │
                  └─────────────────────────────────────────────────┘
                                           │
  1. Decrypt AES Key using User B's        │
     RSA-4096 Private Key                  │
                                           │
  2. Decrypt File Payload using            │
     Unwrapped AES Key & Verify Tag        │
                                           │
  3. Verify Digital Signature using        │
     User A's RSA-4096 Public Key          │
```

---

## 📁 Repository Directory Structure

```text
Digital-Secure-File-Sharing/
│
├── README.md               # Detailed project documentation & guide
├── LICENSE                 # MIT Open Source License
├── requirements.txt        # Python package dependencies
├── .gitignore              # Git ignore configuration
├── main.py                 # Primary entry point (CLI & GUI dispatcher)
│
├── crypto/                 # Cryptographic engine modules
│   ├── __init__.py
│   ├── keygen.py           # 4096-bit RSA key generation & PEM persistence
│   ├── encrypt.py          # Hybrid file encryption (AES-256-GCM + RSA-OAEP)
│   ├── decrypt.py          # Hybrid file decryption & authentication
│   ├── sign.py             # SHA-256 + RSA-PSS digital signature creation
│   ├── verify.py           # Digital signature verification engine
│   └── exchange.py         # Directory manager for user key exchange
│
├── gui/                    # Graphical User Interface
│   ├── __init__.py
│   └── app_gui.py          # Tkinter tabbed desktop application
│
├── utils/                  # Helper utilities
│   ├── __init__.py
│   ├── helper.py           # File formatting & sample creator utilities
│   └── logger.py           # Security logging module
│
├── users/                  # User key stores (Generated at runtime)
│   ├── user_a/             # User A key pair (private_key.pem & public_key.pem)
│   └── user_b/             # User B key pair (private_key.pem & public_key.pem)
│
└── files/                  # Sample test files & outputs
    ├── sample.txt          # Sample text file for encryption test
    └── .gitkeep
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9 or higher
- `pip` package manager

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/<your-username>/Digital-Secure-File-Sharing.git
cd Digital-Secure-File-Sharing

# Install required cryptography package
pip install -r requirements.txt
```

### 2. Launch the Application

#### 🖥️ Launch Desktop GUI (Recommended)
```bash
python main.py --gui
# Or simply
python main.py
```

#### 💻 Launch Interactive CLI Menu
```bash
python main.py --cli
```

---

## 💻 CLI & GUI Features Walkthrough

### 1. Generate RSA Key Pairs
- Generates 4096-bit RSA keys for **User A** and **User B**.
- Saved securely as PEM files inside `users/user_a/` and `users/user_b/`.

### 2. Encrypt & Sign File
- Select file (e.g., `files/sample.txt`).
- Encrypts payload with recipient's public key (`users/user_b/public_key.pem`).
- Signs payload with sender's private key (`users/user_a/private_key.pem`).
- Generates `files/encrypted.bin` and `files/signature.sig`.

### 3. Decrypt & Verify File
- Select encrypted binary (`files/encrypted.bin`) and signature file (`files/signature.sig`).
- Uses recipient's private key (`users/user_b/private_key.pem`) to decrypt.
- Uses sender's public key (`users/user_a/public_key.pem`) to verify signature authenticity.

---

## 🐙 Step-by-Step GitHub Upload Guide

Follow these steps to upload this project to your GitHub profile for your internship showcase:

### 1. Install Git & Verify
```bash
git --version
```

### 2. Create Repository on GitHub
1. Go to [GitHub.com](https://github.com/) and click **New Repository**.
2. Set **Repository Name**: `Digital-Secure-File-Sharing`.
3. Keep it **Public** and do NOT initialize with README (we already have a local README).

### 3. Initialize & Push Project
Open terminal inside the project directory:
```bash
# 1. Initialize local git repository
git init

# 2. Stage all files
git add .

# 3. Commit files
git commit -m "Initial commit: RSA-4096 + AES-256 Hybrid Secure File Sharing App"

# 4. Set default main branch
git branch -M main

# 5. Add remote GitHub link (Replace <your-username> with your actual GitHub username)
git remote add origin https://github.com/<your-username>/Digital-Secure-File-Sharing.git

# 6. Push to GitHub
git push -u origin main
```

---

## 🛡️ Security Best Practices Implemented

- **OAEP Padding**: RSA key wrapping utilizes Optimal Asymmetric Encryption Padding with SHA-256 digest to prevent Chosen Ciphertext Attacks (CCA).
- **PSS Signature Padding**: Digital signatures use Probabilistic Signature Scheme (PSS) for high security standards.
- **GCM Mode Tagging**: AES-256-GCM provides Galois/Counter Mode authenticated encryption to prevent ciphertext tampering.
- **No Hardcoded Keys**: All keys are dynamically generated with high entropy and saved in PEM standard format.

---

## 📄 License
Distributed under the MIT License. See [LICENSE](LICENSE) for more details.
