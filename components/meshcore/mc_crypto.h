#pragma once
// Re-implementation of meshcore-dev/MeshCore src/Utils.cpp's crypto scheme,
// using mbedTLS (bundled with both the ESP-IDF and Arduino-ESP32 cores, so
// no extra library dependency). Confirmed against real MeshCore source:
//   - AES128, ECB mode, zero-padded final block
//   - "encryptThenMAC": ciphertext = AES-ECB(secret, src); mac = HMAC-SHA256(secret, ciphertext)[0:2]
//     wire order is [mac(2 bytes)][ciphertext]
//   - packet dedup hash = SHA256(payload_type byte [+ path_len if TRACE] + payload), truncated to 8 bytes
#include <cstdint>
#include <cstddef>

namespace esphome {
namespace meshcore {
namespace mc_crypto {

void sha256(uint8_t *hash, size_t hash_len, const uint8_t *msg, int msg_len);
void sha256(uint8_t *hash, size_t hash_len, const uint8_t *frag1, int frag1_len, const uint8_t *frag2, int frag2_len);

// AES-128-ECB, zero-padded to block size. Returns bytes written (multiple of 16).
int aes_ecb_encrypt(const uint8_t *key16, uint8_t *dest, const uint8_t *src, int src_len);
int aes_ecb_decrypt(const uint8_t *key16, uint8_t *dest, const uint8_t *src, int src_len);

// dest = [2-byte truncated HMAC-SHA256 MAC][ciphertext]. Returns total dest length.
int encrypt_then_mac(const uint8_t *shared_secret32, uint8_t *dest, const uint8_t *src, int src_len);

// Verifies MAC in leading 2 bytes of src, then decrypts remainder into dest.
// Returns 0 if MAC invalid, else the (padded, multiple-of-16) decrypted length.
int mac_then_decrypt(const uint8_t *shared_secret32, uint8_t *dest, const uint8_t *src, int src_len);

}  // namespace mc_crypto
}  // namespace meshcore
}  // namespace esphome
