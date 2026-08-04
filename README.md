<div align="center">

# 🔐 MultiKeyCrypt

**Multi-pass AES-128-CBC file encryption with a thread pool**

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square&logo=cplusplus)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![AES-128-CBC](https://img.shields.io/badge/Cipher-AES--128--CBC-brightgreen?style=flat-square)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
[![CNG](https://img.shields.io/badge/Engine-Windows%20CNG-0078D6?style=flat-square)](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)

<br/>

> Encrypts all files in a folder using N independently generated AES-128-CBC keys applied in sequence.  
> A single concatenated key string is all that is needed to decrypt everything back.

</div>

---

## 📋 Table of Contents

- [How It Works](#-how-it-works)
- [Encryption Scheme](#-encryption-scheme)
- [Multi-Key Approach](#-multi-key-approach)
- [File Format](#-file-format)
- [Build](#-build)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Security Notes](#-security-notes)

---

## 🔬 How It Works

```
User enters folder path and number of keys (N)
                  │
                  ▼
    N random 128-bit AES keys are generated
    and printed as a concatenated hex string
                  │
        ┌─────────▼──────────────────────────┐
        │   Pass 1: AES-128-CBC with K1       │
        │   Each file: random IV + ciphertext │
        └─────────┬──────────────────────────┘
                  │
        ┌─────────▼──────────────────────────┐
        │   Pass 2: AES-128-CBC with K2       │
        │   Encrypts the already-encrypted    │
        │   output of pass 1 (IV included)    │
        └─────────┬──────────────────────────┘
                  │
                 ...
        ┌─────────▼──────────────────────────┐
        │   Pass N: AES-128-CBC with KN       │
        └─────────┬──────────────────────────┘
                  │
    Each pass: ThreadPool(5 workers) processes
    all files in the directory tree in parallel
                  │
                  ▼
    Long key (K1+K2+...+KN hex) printed for decryption
```

**Decryption** applies keys in **reverse order** — KN first, then K(N-1), ..., K1 — correctly unwrapping each encryption layer.

---

## 🔑 Encryption Scheme

Each pass uses **AES-128-CBC** via Windows CNG (`bcrypt.dll`):

- **Key**: 128-bit (16 bytes), randomly generated per pass
- **IV**: 128-bit (16 bytes), randomly generated per file per pass — prepended to the output
- **Padding**: PKCS7 — handled automatically by `BCryptEncrypt`/`BCryptDecrypt`
- **Engine**: Windows CNG (`BCryptOpenAlgorithmProvider`, `BCRYPT_AES_ALGORITHM`, `BCRYPT_CHAIN_MODE_CBC`)

---

## 🗝️ Multi-Key Approach

Encryption layers build on each other — conceptually identical to **Triple DES (3DES)**:

```
Pass 1:  C₁ = AES_ENC(P,  K₁, IV₁)   ← encrypt original data
Pass 2:  C₂ = AES_ENC(C₁, K₂, IV₂)   ← encrypt the ciphertext
  ...
Pass N:  Cₙ = AES_ENC(Cₙ₋₁, Kₙ, IVₙ)
```

Decryption reverses in the correct order:

```
Step 1:  Cₙ₋₁ = AES_DEC(Cₙ,   Kₙ,   IVₙ)
Step 2:  Cₙ₋₂ = AES_DEC(Cₙ₋₁, Kₙ₋₁, IVₙ₋₁)
  ...
Step N:  P    = AES_DEC(C₁,   K₁,   IV₁)
```

The decryption key is all keys concatenated as hex:
```
LongKey = hex(K₁) + hex(K₂) + ... + hex(Kₙ)
```

With 3 keys the long key is **96 hex characters** (3 × 32).  
Each additional key adds a full independent AES layer — unlike XOR where multiple keys collapse to one.

---

## 📦 File Format

After each encryption pass, every file has this structure:

```
┌──────────────────┬─────────────────────────────────────────┐
│  IV  (16 bytes)  │  AES-128-CBC ciphertext (PKCS7 padded)  │
└──────────────────┴─────────────────────────────────────────┘
```

After N passes the file contains N nested layers. Each decryption pass reads the IV from the first 16 bytes, decrypts the rest, and the result is the input for the next decryption pass.

> File size grows by at most **32 bytes** per pass (16-byte IV + up to 16 bytes of PKCS7 padding).

---

## 🏗 Build

**Requirements:** Visual Studio 2019+ with the **Desktop development with C++** workload.  
No external libraries needed — Windows CNG (`bcrypt.lib`) is part of the Windows SDK.

**Visual Studio:** open `MultiKeyCrypt.sln` → `Build → Build Solution` (`Ctrl+B`).

**Developer Command Prompt:**
```cmd
msbuild MultiKeyCrypt.sln /p:Configuration=Release
```

---

## 🚀 Usage

```
Enter path to folder: C:\Users\you\Documents\secret
1: Encrypt
2: Decrypt
>> 1
Number of keys (encryption passes): 3

=== DECRYPTION KEY (save this!) ===
a3f1c29e7b04d58e1c6f3a09b2e47d128f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
===================================

Pass 1/3  key: a3f1c29e7b04d58e1c6f3a09b2e47d12
Encrypted: C:\...\secret.docx
Encrypted: C:\...\budget.xlsx
Pass 1 done.

Pass 2/3  key: 8f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c
...
Pass 3/3  key: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
...

Encryption complete.
```

**To decrypt**, run again, choose `2`, and paste the long key:

```
Enter path to folder: C:\Users\you\Documents\secret
1: Encrypt
2: Decrypt
>> 2
Enter decryption key:
a3f1c29e7b04d58e1c6f3a09b2e47d128f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d

Pass 1/3   ← applies K3 first (reverse order)
Pass 2/3   ← applies K2
Pass 3/3   ← applies K1

Decryption complete.
```

> ⚠️ **Save the decryption key immediately.** It is not stored anywhere — if lost, files cannot be recovered.

---

## 📁 Project Structure

```
MultiKeyCrypt/
├── MultiKeyCrypt.sln
└── MultiKeyCrypt/
    ├── MultiKeyCrypt.cpp   # Main logic:
    │                       #   generateRandom16()    — key / IV generation
    │                       #   encryptAES()          — AES-128-CBC encrypt (CNG)
    │                       #   decryptAES()          — AES-128-CBC decrypt (CNG)
    │                       #   encryptFile()         — thread pool task (encrypt)
    │                       #   decryptFile()         — thread pool task (decrypt)
    │                       #   processDir()          — recursive dir traversal
    │                       #   main()                — CLI, key management, passes
    ├── ThreadPool.h        # Fixed-size thread pool (condition variable + task queue)
    └── ThreadPool.cpp      # (stub)
```

---

## 🔒 Security Notes

| Property | Details |
|---|---|
| Cipher | AES-128-CBC (real AES, Windows CNG) |
| Key size | 128 bits per pass |
| IV | Random 128 bits per file per pass — never reused |
| Padding | PKCS7 (added/removed automatically) |
| Multi-key strength | Each pass is a full independent AES layer — unlike XOR, keys do **not** cancel each other out |
| Key storage | Not stored anywhere — user is responsible for saving the decryption key |
| No authentication | CBC mode alone does not detect tampering — consider adding HMAC for integrity |
| Not GCM | AES-GCM would provide authenticated encryption; CBC without MAC allows ciphertext modification |

---

<div align="center">

Made with C++17 · Windows CNG · AES-128-CBC · Thread Pool

</div>
