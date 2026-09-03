#pragma once
// Mirrors meshcore-dev/MeshCore src/Identity.h semantics: an Identity is a
// party's Ed25519 public key; a LocalIdentity additionally holds the
// private key and can sign / do the ECDH used to derive per-contact shared
// secrets. The path/route "hash" MeshCore uses everywhere is just the first
// PATH_HASH_SIZE (1) byte(s) of the public key.
#include "mc_packet.h"
#include <cstdint>
#include <cstring>

namespace esphome {
namespace meshcore {
namespace mc {

class Identity {
 public:
  uint8_t pub_key[PUB_KEY_SIZE]{};

  Identity() = default;
  explicit Identity(const uint8_t *pk) { memcpy(pub_key, pk, PUB_KEY_SIZE); }

  uint8_t hash_byte() const { return pub_key[0]; }  // PATH_HASH_SIZE == 1 in V1
  bool is_hash_match(uint8_t h) const { return h == pub_key[0]; }

  bool verify(const uint8_t *sig, const uint8_t *message, int msg_len) const;
};

class LocalIdentity : public Identity {
 public:
  uint8_t prv_key[PRV_KEY_SIZE]{};

  // Generates a fresh keypair from `seed` (32 bytes of real entropy — caller
  // supplies it, e.g. from the ESP32 hardware RNG via esphome::random_bytes).
  void generate_from_seed(const uint8_t seed[32]);

  // Loads a previously-generated (and persisted) keypair, e.g. from YAML secrets.
  void load(const uint8_t pub[PUB_KEY_SIZE], const uint8_t prv[PRV_KEY_SIZE]) {
    memcpy(pub_key, pub, PUB_KEY_SIZE);
    memcpy(prv_key, prv, PRV_KEY_SIZE);
  }

  void sign(uint8_t sig[SIGNATURE_SIZE], const uint8_t *message, int msg_len) const;

  // X25519 ECDH over the Ed25519 keys (matches ed25519_key_exchange as used
  // by MeshCore's LocalIdentity::calcSharedSecret).
  void calc_shared_secret(uint8_t secret[PUB_KEY_SIZE], const Identity &other) const;
};

}  // namespace mc
}  // namespace meshcore
}  // namespace esphome
