// MultiKeyCrypt — Multi-pass AES-128-CBC file encryption
// Original logic (N keys, N directory passes, thread pool) preserved in full.
// Only the cipher was replaced: XOR → AES-128-CBC (Windows CNG).
//
// Encrypted file format after each pass:
//   [IV  16 bytes][encrypted data with PKCS7 padding]
//
// Decryption applies keys in REVERSE order (KN → ... → K1),
// which is correct for a multi-layer block cipher.

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <random>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <bcrypt.h>
#include <thread>
#include <mutex>
#include "ThreadPool.h"

#pragma comment(lib, "bcrypt.lib")

using namespace std;
using Bytes = std::vector<unsigned char>;

constexpr size_t AES_KEY_SIZE   = 16;   // 128-bit key
constexpr size_t AES_BLOCK_SIZE = 16;   // AES block size / IV size

std::mutex g_consoleMutex;

// ─────────────────────────────────────────────────────────────────────────────
//  Key / IV generation
// ─────────────────────────────────────────────────────────────────────────────

Bytes generateRandom16() {
    Bytes buf(AES_KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned short> dist(0, 255);
    std::generate(buf.begin(), buf.end(),
        [&]{ return static_cast<unsigned char>(dist(gen)); });
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hex utilities
// ─────────────────────────────────────────────────────────────────────────────

void printHex(const Bytes& data) {
    for (auto b : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec;
}

Bytes hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::runtime_error("Invalid hex string length");
    Bytes result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
        result.push_back(static_cast<unsigned char>(
            std::stoi(hex.substr(i, 2), nullptr, 16)));
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  File I/O
// ─────────────────────────────────────────────────────────────────────────────

Bytes readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to open: " + path);
    f.seekg(0, std::ios::end);
    size_t sz = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);
    Bytes data(sz);
    if (sz > 0 && !f.read(reinterpret_cast<char*>(data.data()), sz))
        throw std::runtime_error("Read error: " + path);
    return data;
}

void writeFile(const std::string& path, const Bytes& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to create: " + path);
    if (!data.empty() &&
        !f.write(reinterpret_cast<const char*>(data.data()), data.size()))
        throw std::runtime_error("Write error: " + path);
}

// ─────────────────────────────────────────────────────────────────────────────
//  AES-128-CBC encryption (Windows CNG)
//
//  Output: [IV (16 bytes)] + [ciphertext with PKCS7 padding]
//  A fresh random IV is generated for every file and every pass.
// ─────────────────────────────────────────────────────────────────────────────

Bytes encryptAES(const Bytes& plaintext, const Bytes& key) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    // 1. Open the AES algorithm provider
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    // 2. Set CBC chaining mode
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    // 3. Create the key object
    DWORD objSize = 0, cbRes = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objSize), sizeof(DWORD), &cbRes, 0);
    Bytes keyObj(objSize);

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, keyObj.data(), objSize,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGenerateSymmetricKey failed");
    }

    // 4. Random IV — unique per file and per pass
    Bytes iv    = generateRandom16();
    Bytes ivTmp = iv;   // BCryptEncrypt modifies the IV buffer — work on a copy

    // 5. Query the output size (accounts for PKCS7 padding)
    ULONG cipherLen = 0;
    BCryptEncrypt(hKey,
        const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
        nullptr,
        ivTmp.data(), AES_BLOCK_SIZE,
        nullptr, 0, &cipherLen, BCRYPT_BLOCK_PADDING);

    ivTmp = iv;  // restore IV — it was updated by the size-query call above

    // 6. Encrypt
    Bytes cipher(cipherLen);
    ULONG written = 0;
    NTSTATUS st = BCryptEncrypt(hKey,
        const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
        nullptr,
        ivTmp.data(), AES_BLOCK_SIZE,
        cipher.data(), cipherLen, &written, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("BCryptEncrypt failed");

    // 7. Prepend IV to ciphertext: [IV (16 bytes)][ciphertext]
    Bytes result;
    result.reserve(AES_BLOCK_SIZE + written);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), cipher.begin(), cipher.begin() + written);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  AES-128-CBC decryption (Windows CNG)
//
//  Input must be: [IV (16 bytes)] + [ciphertext]
// ─────────────────────────────────────────────────────────────────────────────

Bytes decryptAES(const Bytes& data, const Bytes& key) {
    if (data.size() < AES_BLOCK_SIZE * 2)
        throw std::runtime_error(
            "Data too small to decrypt (missing IV or ciphertext)");

    // Split input into IV and ciphertext
    Bytes iv    (data.begin(), data.begin() + AES_BLOCK_SIZE);
    Bytes cipher(data.begin() + AES_BLOCK_SIZE, data.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD objSize = 0, cbRes = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objSize), sizeof(DWORD), &cbRes, 0);
    Bytes keyObj(objSize);

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, keyObj.data(), objSize,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGenerateSymmetricKey failed");
    }

    // Query the plaintext size (PKCS7 padding will be stripped)
    ULONG plainLen = 0;
    BCryptDecrypt(hKey,
        cipher.data(), static_cast<ULONG>(cipher.size()),
        nullptr,
        iv.data(), AES_BLOCK_SIZE,
        nullptr, 0, &plainLen, BCRYPT_BLOCK_PADDING);

    Bytes plain(plainLen);
    ULONG decrypted = 0;
    NTSTATUS st = BCryptDecrypt(hKey,
        cipher.data(), static_cast<ULONG>(cipher.size()),
        nullptr,
        iv.data(), AES_BLOCK_SIZE,
        plain.data(), plainLen, &decrypted, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("BCryptDecrypt failed (wrong key?)");

    plain.resize(decrypted);
    return plain;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Thread pool tasks — one file per task
// ─────────────────────────────────────────────────────────────────────────────

void encryptFile(const std::string& path, const Bytes& key) {
    try {
        writeFile(path, encryptAES(readFile(path), key));
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cout << "Encrypted: " << path << "\n";
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cerr << "Error [" << path << "]: " << e.what() << "\n";
    }
}

void decryptFile(const std::string& path, const Bytes& key) {
    try {
        writeFile(path, decryptAES(readFile(path), key));
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cout << "Decrypted: " << path << "\n";
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cerr << "Error [" << path << "]: " << e.what() << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Recursive directory traversal
//  All files are enqueued into the provided thread pool.
//  Subdirectories are traversed synchronously on the calling thread.
// ─────────────────────────────────────────────────────────────────────────────

void processDir(const std::string& dir, ThreadPool& pool,
                const Bytes& key, bool encrypt)
{
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cerr << "Cannot open dir: " << dir << "\n";
        return;
    }
    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        std::string full = dir + "\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            processDir(full, pool, key, encrypt);   // recurse into subdirectory
        } else {
            if (encrypt) pool.enqueue(encryptFile, full, key);
            else         pool.enqueue(decryptFile, full, key);
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

int main() {
    try {
        // Read folder path; strip surrounding quotes (Windows drag-and-drop)
        std::cout << "Enter path to folder: ";
        std::string folderRaw;
        std::getline(std::cin, folderRaw);
        std::string folder;
        for (char c : folderRaw) if (c != '"') folder += c;

        std::cout << "1: Encrypt\n2: Decrypt\n>> ";
        int choice = 0;
        std::cin >> choice;

        // ── ENCRYPT ───────────────────────────────────────────────────────────
        if (choice == 1) {
            int numKeys = 1;
            std::cout << "Number of keys (encryption passes): ";
            std::cin >> numKeys;
            if (numKeys < 1) { std::cerr << "Must be >= 1\n"; return 1; }

            // Generate one random key per pass
            std::vector<Bytes> keys;
            keys.reserve(numKeys);
            for (int i = 0; i < numKeys; ++i)
                keys.push_back(generateRandom16());

            // Print the combined decryption key (all keys concatenated as hex)
            std::cout << "\n=== DECRYPTION KEY (save this!) ===\n";
            for (auto& k : keys) printHex(k);
            std::cout << "\n===================================\n\n";

            // Apply keys in forward order: K0 → K1 → ... → K(N-1)
            for (int i = 0; i < numKeys; ++i) {
                std::cout << "Pass " << (i + 1) << "/" << numKeys
                          << "  key: "; printHex(keys[i]); std::cout << "\n";
                {
                    ThreadPool pool(5);
                    processDir(folder, pool, keys[i], true);
                    // pool destructor blocks until all worker tasks complete
                }
                std::cout << "Pass " << (i + 1) << " done.\n\n";
            }
            std::cout << "Encryption complete.\n";

        // ── DECRYPT ───────────────────────────────────────────────────────────
        } else if (choice == 2) {
            std::string longKey;
            std::cout << "Enter decryption key: ";
            std::cin >> longKey;

            // Split the long hex key into 32-char (16-byte) chunks
            std::vector<Bytes> keys;
            for (size_t i = 0; i + AES_KEY_SIZE * 2 <= longKey.size();
                 i += AES_KEY_SIZE * 2)
                keys.push_back(hexToBytes(longKey.substr(i, AES_KEY_SIZE * 2)));

            if (keys.empty()) { std::cerr << "Invalid key.\n"; return 1; }

            // IMPORTANT: apply keys in REVERSE order K(N-1) → ... → K0
            // Decryption is the mirror of encryption for a block cipher.
            for (int i = static_cast<int>(keys.size()) - 1; i >= 0; --i) {
                std::cout << "Pass " << (keys.size() - i) << "/" << keys.size() << "\n";
                {
                    ThreadPool pool(5);
                    processDir(folder, pool, keys[i], false);
                }
                std::cout << "Pass " << (keys.size() - i) << " done.\n\n";
            }
            std::cout << "Decryption complete.\n";

        } else {
            std::cerr << "Invalid choice.\n";
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }

    Sleep(2000);
    return 0;
}
