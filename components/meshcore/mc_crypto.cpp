#include "mc_crypto.h"
#include <cstring>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>

namespace esphome {
namespace meshcore {
namespace mc_crypto {

void sha256(uint8_t *hash, size_t hash_len, const uint8_t *msg, int msg_len) {
  uint8_t full[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0 /* SHA-256, not 224 */);
  mbedtls_sha256_update(&ctx, msg, msg_len);
  mbedtls_sha256_finish(&ctx, full);
  mbedtls_sha256_free(&ctx);
  memcpy(hash, full, hash_len > 32 ? 32 : hash_len);
}

void sha256(uint8_t *hash, size_t hash_len, const uint8_t *frag1, int frag1_len, const uint8_t *frag2,
            int frag2_len) {
  uint8_t full[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, frag1, frag1_len);
  mbedtls_sha256_update(&ctx, frag2, frag2_len);
  mbedtls_sha256_finish(&ctx, full);
  mbedtls_sha256_free(&ctx);
  memcpy(hash, full, hash_len > 32 ? 32 : hash_len);
}

int aes_ecb_encrypt(const uint8_t *key16, uint8_t *dest, const uint8_t *src, int src_len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key16, 128);
  uint8_t *dp = dest;
  while (src_len >= 16) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, src, dp);
    dp += 16;
    src += 16;
    src_len -= 16;
  }
  if (src_len > 0) {
    uint8_t tmp[16] = {0};
    memcpy(tmp, src, src_len);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, tmp, dp);
    dp += 16;
  }
  mbedtls_aes_free(&aes);
  return dp - dest;
}

int aes_ecb_decrypt(const uint8_t *key16, uint8_t *dest, const uint8_t *src, int src_len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, key16, 128);
  uint8_t *dp = dest;
  const uint8_t *sp = src;
  while (sp - src < src_len) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, sp, dp);
    dp += 16;
    sp += 16;
  }
  mbedtls_aes_free(&aes);
  return sp - src;
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out32[32]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1 /* use hmac */);
  mbedtls_md_hmac_starts(&ctx, key, key_len);
  mbedtls_md_hmac_update(&ctx, msg, msg_len);
  mbedtls_md_hmac_finish(&ctx, out32);
  mbedtls_md_free(&ctx);
}

int encrypt_then_mac(const uint8_t *shared_secret32, uint8_t *dest, const uint8_t *src, int src_len) {
  static constexpr int MAC_SIZE = 2;  // matches CIPHER_MAC_SIZE in mc_packet.h (V1 wire format)
  int enc_len = aes_ecb_encrypt(shared_secret32, dest + MAC_SIZE, src, src_len);
  uint8_t mac[32];
  // MeshCore HMACs with the full PUB_KEY_SIZE (32-byte) shared secret as key
  hmac_sha256(shared_secret32, 32, dest + MAC_SIZE, enc_len, mac);
  memcpy(dest, mac, MAC_SIZE);
  return MAC_SIZE + enc_len;
}

int mac_then_decrypt(const uint8_t *shared_secret32, uint8_t *dest, const uint8_t *src, int src_len) {
  static constexpr int MAC_SIZE = 2;
  if (src_len <= MAC_SIZE)
    return 0;
  int enc_len = src_len - MAC_SIZE;
  uint8_t mac[32];
  hmac_sha256(shared_secret32, 32, src + MAC_SIZE, enc_len, mac);
  if (memcmp(mac, src, MAC_SIZE) != 0)
    return 0;  // bad MAC
  return aes_ecb_decrypt(shared_secret32, dest, src + MAC_SIZE, enc_len);
}

}  // namespace mc_crypto
}  // namespace meshcore
}  // namespace esphome
