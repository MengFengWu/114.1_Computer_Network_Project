#ifndef CRYPTO_CPP
#define CRYPTO_CPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <iomanip>

#include "crypto.h"

// 1. Generate local Diffie-Hellman Key Pair
std::string Crypto::get_my_public_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    // Convert to BIO to get string format
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pubKeyStr(data, len);
    BIO_free(bio);
    return pubKeyStr;
}

// 2. Derive Shared Secret (Session Key) from Peer's Public Key
bool Crypto::set_peer_public_key(const std::string& peer_key_str) {
    BIO* bio = BIO_new_mem_buf(peer_key_str.c_str(), -1);
    peer_pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!peer_pkey) return false;

    // Derive Shared Secret
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pkey);

    size_t secret_len;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    unsigned char* secret = (unsigned char*)OPENSSL_malloc(secret_len);
    EVP_PKEY_derive(ctx, secret, &secret_len);

    // Hash the secret (SHA256) to make it a valid AES-256 Key
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    unsigned int len;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, secret, secret_len);
    EVP_DigestFinal_ex(mdctx, session_key, &len);
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(secret);

    key_established = true;
    return true;
}

// 3. Encrypt Message (AES-256-CBC)
std::string Crypto::encrypt(const std::string& plaintext) {
    if (!key_established) return "";
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0}; // Zero IV for simplicity (use random in prod)
    
    // Output buffer (input len + block size)
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Base64 Encode the ciphertext so we can send it as a string
    // (Simplified manual hex string for this homework to avoid base64 lib dependency)
    std::string hex_out;
    char buf[3];
    for(int i=0; i<ciphertext_len; i++) {
        snprintf(buf, 3, "%02x", ciphertext[i]);
        hex_out += buf;
    }
    return hex_out;
}

// 4. Decrypt Message
std::string Crypto::decrypt(const std::string& hex_ciphertext) {
    if (!key_established) return "";
    
    // Convert Hex string back to bytes
    std::vector<unsigned char> ciphertext;
    for (size_t i = 0; i < hex_ciphertext.length(); i += 2) {
        std::string byteString = hex_ciphertext.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        ciphertext.push_back(byte);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, session_key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    // Remove padding and return string
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ----

std::string GroupCrypto::get_group_key() {
    return std::string(reinterpret_cast<const char*>(group_key), 32);
}

void GroupCrypto::set_random_group_key() {
    RAND_bytes(group_key, 32);
}

void GroupCrypto::set_group_key(const std::string& key_str) {
    if (key_str.size() != 32) {
        return; 
    }
    std::memcpy(group_key, key_str.data(), 32);
}

std::string GroupCrypto::encrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0}; // Zero IV for simplicity (use random in prod)
    
    // Output buffer (input len + block size)
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, group_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Base64 Encode the ciphertext so we can send it as a string
    // (Simplified manual hex string for this homework to avoid base64 lib dependency)
    std::string hex_out;
    char buf[3];
    for(int i=0; i<ciphertext_len; i++) {
        snprintf(buf, 3, "%02x", ciphertext[i]);
        hex_out += buf;
    }
    return hex_out;
}

std::string GroupCrypto::decrypt(const std::string& hex_ciphertext) {
    // Convert Hex string back to bytes
    std::vector<unsigned char> ciphertext;
    for (size_t i = 0; i < hex_ciphertext.length(); i += 2) {
        std::string byteString = hex_ciphertext.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        ciphertext.push_back(byte);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, group_key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    // Remove padding and return string
    return std::string((char*)plaintext.data(), plaintext_len);
}

#endif