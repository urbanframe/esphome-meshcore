#include "mc_identity.h"

extern "C" {
#define ED25519_NO_SEED 1  // we always supply our own seed (ESP32 HW RNG), matching MeshCore's own build flag
#include "ed25519/ed_25519.h"
}

namespace esphome {
namespace meshcore {
namespace mc {

bool Identity::verify(const uint8_t *sig, const uint8_t *message, int msg_len) const {
  return ed25519_verify(sig, message, (size_t) msg_len, pub_key) != 0;
}

void LocalIdentity::generate_from_seed(const uint8_t seed[32]) {
  ed25519_create_keypair(pub_key, prv_key, seed);
}

void LocalIdentity::sign(uint8_t sig[SIGNATURE_SIZE], const uint8_t *message, int msg_len) const {
  ed25519_sign(sig, message, (size_t) msg_len, pub_key, prv_key);
}

void LocalIdentity::calc_shared_secret(uint8_t secret[PUB_KEY_SIZE], const Identity &other) const {
  ed25519_key_exchange(secret, other.pub_key, prv_key);
}

}  // namespace mc
}  // namespace meshcore
}  // namespace esphome
