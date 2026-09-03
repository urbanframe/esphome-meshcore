#pragma once
#include "esphome/core/component.h"
#include "esphome/core/automation.h"
#include "esphome/core/hal.h"

#if __has_include("esphome/components/sx126x/sx126x.h")
#include "esphome/components/sx126x/sx126x.h"
#define MC_USE_SX126X 1
#endif
#if __has_include("esphome/components/sx127x/sx127x.h")
#include "esphome/components/sx127x/sx127x.h"
#define MC_USE_SX127X 1
#endif

#include "mc_packet.h"
#include "mc_identity.h"

#include <vector>
#include <string>
#include <array>

namespace esphome {
namespace meshcore {

// --- honest scope note (also in README) -------------------------------
// This component implements, against real upstream MeshCore source:
//   * exact V1 wire packet framing (mc_packet.h)
//   * the real crypto scheme: AES-128-ECB + HMAC-SHA256 truncated MAC,
//     SHA256 packet-hash for flood dedup (mc_crypto.*)
//   * Ed25519 identity: keypair, signing, verification, X25519 ECDH
//     (mc_identity.*, vendored ed25519 lib — same one MeshCore itself uses)
//   * ADVERT build/parse+verify, flood relay with hash-based dedup,
//     channel (group) text messages, direct text messages to our own
//     identity
// It deliberately does NOT yet implement: MeshCore's full path-based
// direct-routing state machine (path discovery/PATH payloads), transport
// codes, multi-part packets, repeater/room-server ACLs, or contact
// management persistence. Those are exactly the parts that are still
// actively evolving upstream (see MeshCore's own "V2 protocol spec"
// roadmap item) and are a substantial follow-on project, not a first cut.
// ------------------------------------------------------------------------

struct McChannel {
  std::string name;
  uint8_t psk[16]{};
  uint8_t hash{0};  // SHA256(psk)[0], matches how MeshCore derives channel hash
  void compute_hash();
};

struct SeenPacket {
  std::array<uint8_t, mc::MAX_HASH_SIZE> hash;
  uint32_t seen_at_ms;
};

class MeshCoreComponent : public Component
#ifdef MC_USE_SX126X
    ,
                           public sx126x::SX126xListener
#endif
#ifdef MC_USE_SX127X
    ,
                           public sx127x::SX127xListener
#endif
{
 public:
  void setup() override;
  void loop() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

#ifdef MC_USE_SX126X
  void set_lora(sx126x::SX126x *r) {
    this->sx126x_ = r;
    r->register_listener(this);
  }
  void on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) override;
#endif
#ifdef MC_USE_SX127X
  void set_lora(sx127x::SX127x *r) {
    this->sx127x_ = r;
    r->register_listener(this);
  }
#endif

  // --- identity / config, set from __init__.py codegen ---
  void set_identity(const uint8_t pub[mc::PUB_KEY_SIZE], const uint8_t prv[mc::PRV_KEY_SIZE]);
  void set_node_name(const std::string &name) { this->node_name_ = name; }
  void set_is_repeater(bool r) { this->is_repeater_ = r; }
  void set_advertise_interval(uint32_t ms) { this->advertise_interval_ms_ = ms; }
  void add_channel(const std::string &name, const uint8_t psk[16]);

  // Single known peer, identified by their full public key. This sidesteps
  // the whole contact-table problem below: with only one possible sender,
  // there's no ambiguity to resolve from a 1-byte hash, and we always know
  // which pubkey to run ECDH against.
  void set_peer(const uint8_t pub[mc::PUB_KEY_SIZE]) { this->peer_ = mc::Identity(pub); this->has_peer_ = true; }

  // --- actions, called from ESPHome automation ---
  void send_advert(bool flood = true);
  bool send_channel_text(const std::string &channel_name, const std::string &text);
  bool send_direct_text(const uint8_t dest_pub_key[mc::PUB_KEY_SIZE], const std::string &text);
  // Convenience: send straight to the configured peer_.
  bool send_message(const std::string &text);

  // --- triggers fired into YAML automations ---
  Trigger<std::string, std::string> *get_on_channel_message_trigger() { return &this->on_channel_message_trigger_; }
  // Single arg: with exactly one configured peer, there's nothing to disambiguate.
  Trigger<std::string> *get_on_message_trigger() { return &this->on_message_trigger_; }
  Trigger<std::string, std::string> *get_on_advert_trigger() { return &this->on_advert_trigger_; }

 protected:
  bool transmit_(const mc::Packet &pkt);
  void handle_packet_(mc::Packet &pkt, float rssi, float snr);
  void handle_advert_(mc::Packet &pkt);
  void handle_group_text_(mc::Packet &pkt);
  void handle_direct_text_(mc::Packet &pkt);
  bool already_seen_(const uint8_t hash[mc::MAX_HASH_SIZE]);
  void remember_seen_(const uint8_t hash[mc::MAX_HASH_SIZE]);
  void maybe_relay_(mc::Packet &pkt);
  McChannel *find_channel_(uint8_t hash);
  McChannel *find_channel_(const std::string &name);

#ifdef MC_USE_SX126X
  sx126x::SX126x *sx126x_{nullptr};
#endif
#ifdef MC_USE_SX127X
  sx127x::SX127x *sx127x_{nullptr};
#endif

  mc::LocalIdentity identity_;
  mc::Identity peer_;
  bool has_peer_{false};
  std::string node_name_;
  bool is_repeater_{false};
  uint32_t advertise_interval_ms_{0};
  uint32_t last_advert_ms_{0};

  std::vector<McChannel> channels_;

  static constexpr size_t DEDUP_CACHE_SIZE = 64;
  static constexpr uint32_t DEDUP_EXPIRE_MS = 10 * 60 * 1000UL;  // matches MeshCore's own FLOOD_EXPIRE_TIME
  std::vector<SeenPacket> seen_cache_;

  Trigger<std::string, std::string> on_channel_message_trigger_;  // (channel_name, text)
  Trigger<std::string> on_message_trigger_;                       // (text) — always from peer_
  Trigger<std::string, std::string> on_advert_trigger_;           // (pubkey_hex, name)
};

template<typename... Ts> class SendMessageAction : public Action<Ts...>, public Parented<MeshCoreComponent> {
 public:
  TEMPLATABLE_VALUE(std::string, text)
  void play(Ts... x) override { this->parent_->send_message(this->text_.value(x...)); }
};

template<typename... Ts> class SendChannelTextAction : public Action<Ts...>, public Parented<MeshCoreComponent> {
 public:
  TEMPLATABLE_VALUE(std::string, channel)
  TEMPLATABLE_VALUE(std::string, text)
  void play(Ts... x) override { this->parent_->send_channel_text(this->channel_.value(x...), this->text_.value(x...)); }
};

template<typename... Ts> class SendAdvertAction : public Action<Ts...>, public Parented<MeshCoreComponent> {
 public:
  void play(Ts... x) override { this->parent_->send_advert(); }
};

}  // namespace meshcore
}  // namespace esphome
