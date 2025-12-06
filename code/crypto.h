#ifndef CRYPTO_H
#define CRYPTO_H

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

class Crypto {
    private:
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY* peer_pkey = nullptr;
        unsigned char session_key[32]; // AES-256 key
        bool key_established = false;

    public:
        Crypto() {
            pkey = nullptr;
            peer_pkey = nullptr;
            key_established = false;
        }

        ~Crypto() {
            if (pkey) EVP_PKEY_free(pkey);
            if (peer_pkey) EVP_PKEY_free(peer_pkey);
        }

        // 1. Generate local Diffie-Hellman Key Pair
        std::string get_my_public_key();

        // 2. Derive Shared Secret (Session Key) from Peer's Public Key
        bool set_peer_public_key(const std::string& peer_key_str);

        // 3. Encrypt Message (AES-256-CBC)
        std::string encrypt(const std::string& plaintext);

        // 4. Decrypt Message
        std::string decrypt(const std::string& hex_ciphertext);
};

#endif