#include "meshcore.h"
#include "mc_crypto.h"
#include "esphome/core/log.h"
#include "esphome/core/helpers.h"
#include <algorithm>
#include <cstring>

namespace esphome {
namespace meshcore {

static const char *const TAG = "meshcore";

void McChannel::compute_hash() {
  uint8_t full[8];
  mc_crypto::sha256(full, 8, this->psk, 16);
  this->hash = full[0];
}

void MeshCoreComponent::set_identity(const uint8_t pub[mc::PUB_KEY_SIZE], const uint8_t prv[mc::PRV_KEY_SIZE]) {
  this->identity_.load(pub, prv);
}

void MeshCoreComponent::add_channel(const std::string &name, const uint8_t psk[16]) {
  McChannel ch;
  ch.name = name;
  memcpy(ch.psk, psk, 16);
  ch.compute_hash();
  this->channels_.push_back(ch);
}

McChannel *MeshCoreComponent::find_channel_(uint8_t hash) {
  for (auto &c : this->channels_)
    if (c.hash == hash)
      return &c;
  return nullptr;
}
McChannel *MeshCoreComponent::find_channel_(const std::string &name) {
  for (auto &c : this->channels_)
    if (c.name == name)
      return &c;
  return nullptr;
}

void MeshCoreComponent::setup() {
  ESP_LOGCONFIG(TAG, "Setting up MeshCore...");
  if (this->identity_.pub_key[0] == 0 && this->identity_.prv_key[0] == 0) {
    ESP_LOGW(TAG, "No identity configured — generating an ephemeral one for this boot only. "
                  "Set an explicit private_key/public_key in YAML to persist your node identity "
                  "across reboots (MeshCore contacts identify nodes by public key).");
    uint8_t seed[32];
    for (auto &b : seed)
      b = (uint8_t) esphome::random_uint32();
    this->identity_.generate_from_seed(seed);
  }
  if (this->advertise_interval_ms_ > 0) {
    this->last_advert_ms_ = millis() - this->advertise_interval_ms_;  // advertise soon after boot
  }
}

void MeshCoreComponent::loop() {
  if (this->advertise_interval_ms_ > 0 && millis() - this->last_advert_ms_ >= this->advertise_interval_ms_) {
    this->last_advert_ms_ = millis();
    this->send_advert();
  }
}

bool MeshCoreComponent::transmit_(const mc::Packet &pkt) {
  uint8_t buf[2 + mc::MAX_PATH_SIZE + mc::MAX_PACKET_PAYLOAD + 4];
  uint8_t len = pkt.write_to(buf);
  std::vector<uint8_t> out(buf, buf + len);
#ifdef MC_USE_SX126X
  if (this->sx126x_ != nullptr)
    return this->sx126x_->transmit_packet(out) == sx126x::SX126xError::NONE;
#endif
#ifdef MC_USE_SX127X
  if (this->sx127x_ != nullptr)
    return this->sx127x_->transmit_packet(out) == sx127x::SX127xError::NONE;
#endif
  ESP_LOGE(TAG, "No LoRa radio configured (set 'lora:' to an sx126x or sx127x component)");
  return false;
}

// --- ADVERT ---------------------------------------------------------------
// Wire format (from MeshCore's Mesh.cpp self-advert construction):
//   pub_key(32) | timestamp(4, LE) | signature(64) | flags(1) | [lat(4)] [lon(4)] [name...]
// We keep it simple: flags = ADV_TYPE_REPEATER or ADV_TYPE_CHAT, plus NAME bit; no lat/lon/battery.
void MeshCoreComponent::send_advert(bool flood) {
  mc::Packet pkt;
  pkt.header = (flood ? mc::ROUTE_TYPE_FLOOD : mc::ROUTE_TYPE_DIRECT) | (mc::PAYLOAD_TYPE_ADVERT << mc::PH_TYPE_SHIFT) |
               (mc::PAYLOAD_VER_1 << mc::PH_VER_SHIFT);
  pkt.path_len = 0;

  uint8_t body[32 + 4 + 64 + 1 + 32];
  uint8_t i = 0;
  memcpy(&body[i], this->identity_.pub_key, mc::PUB_KEY_SIZE);
  i += mc::PUB_KEY_SIZE;
  uint32_t ts = (uint32_t) (millis() / 1000);  // NOTE: not wall-clock time; see README limitations
  memcpy(&body[i], &ts, 4);
  i += 4;
  uint8_t sig_offset = i;
  i += mc::SIGNATURE_SIZE;  // signature filled in below, over pub_key+timestamp+flags+name
  uint8_t flags_offset = i;
  uint8_t flags = (this->is_repeater_ ? mc::ADV_TYPE_REPEATER : mc::ADV_TYPE_CHAT);
  if (!this->node_name_.empty())
    flags |= mc::ADV_NAME_MASK;
  body[i++] = flags;
  if (!this->node_name_.empty()) {
    size_t n = std::min(this->node_name_.size(), (size_t) mc::MAX_ADVERT_DATA_SIZE);
    memcpy(&body[i], this->node_name_.data(), n);
    i += n;
  }

  // Sign pub_key + timestamp + flags + name (everything except the signature itself)
  uint8_t to_sign[sizeof(body)];
  size_t sign_len = 0;
  memcpy(to_sign, body, mc::PUB_KEY_SIZE + 4);
  sign_len = mc::PUB_KEY_SIZE + 4;
  memcpy(&to_sign[sign_len], &body[flags_offset], i - flags_offset);
  sign_len += (i - flags_offset);
  this->identity_.sign(&body[sig_offset], to_sign, sign_len);

  pkt.payload_len = i;
  memcpy(pkt.payload, body, i);

  if (this->transmit_(pkt)) {
    ESP_LOGD(TAG, "Sent ADVERT (%s)", this->is_repeater_ ? "repeater" : "chat");
  }
}

void MeshCoreComponent::handle_advert_(mc::Packet &pkt) {
  if (pkt.payload_len < mc::PUB_KEY_SIZE + 4 + mc::SIGNATURE_SIZE + 1) {
    ESP_LOGW(TAG, "Malformed ADVERT (too short)");
    return;
  }
  const uint8_t *p = pkt.payload;
  mc::Identity from(p);
  uint32_t ts;
  memcpy(&ts, p + mc::PUB_KEY_SIZE, 4);
  const uint8_t *sig = p + mc::PUB_KEY_SIZE + 4;
  const uint8_t *rest = sig + mc::SIGNATURE_SIZE;
  uint8_t rest_len = pkt.payload_len - (mc::PUB_KEY_SIZE + 4 + mc::SIGNATURE_SIZE);

  uint8_t to_verify[mc::MAX_PACKET_PAYLOAD];
  memcpy(to_verify, p, mc::PUB_KEY_SIZE + 4);
  memcpy(&to_verify[mc::PUB_KEY_SIZE + 4], rest, rest_len);
  if (!from.verify(sig, to_verify, mc::PUB_KEY_SIZE + 4 + rest_len)) {
    ESP_LOGW(TAG, "ADVERT signature verification FAILED — dropping (could be a V2-protocol node, "
                  "or a bug in this port's advert layout — see README)");
    return;
  }

  uint8_t flags = rest[0];
  std::string name;
  if (flags & mc::ADV_NAME_MASK) {
    name.assign((const char *) &rest[1], rest_len - 1);
  }
  std::string pubhex = format_hex(from.pub_key, mc::PUB_KEY_SIZE);
  ESP_LOGD(TAG, "ADVERT from %s (%s)", pubhex.c_str(), name.c_str());
  this->on_advert_trigger_.trigger(pubhex, name);
}

// --- group (channel) text messages -----------------------------------------
// Payload: channel_hash(1) | mac+ciphertext(encryptThenMAC of: timestamp(4) | "Name: text")
void MeshCoreComponent::handle_group_text_(mc::Packet &pkt) {
  if (pkt.payload_len < 1 + 2)
    return;
  uint8_t chash = pkt.payload[0];
  McChannel *ch = this->find_channel_(chash);
  if (ch == nullptr)
    return;  // not a channel we're on — nothing more we can do with it (still eligible for relay)

  uint8_t plain[mc::MAX_PACKET_PAYLOAD];
  uint8_t key32[32] = {0};
  memcpy(key32, ch->psk, 16);  // AES-128 uses only the first 16 bytes of the key material
  int plen = mc_crypto::mac_then_decrypt(key32, plain, &pkt.payload[1], pkt.payload_len - 1);
  if (plen <= 4) {
    ESP_LOGW(TAG, "Channel '%s' message failed MAC check (wrong PSK?)", ch->name.c_str());
    return;
  }
  std::string text((const char *) &plain[4], plen - 4);
  // strip trailing zero-padding from the block cipher
  while (!text.empty() && text.back() == '\0')
    text.pop_back();
  ESP_LOGD(TAG, "Channel '%s': %s", ch->name.c_str(), text.c_str());
  this->on_channel_message_trigger_.trigger(ch->name, text);
}

// --- direct text messages to us --------------------------------------------
// Payload: dest_hash(1) | src_hash(1) | mac+ciphertext(encryptThenMAC of: timestamp(4) | text)
//
// With exactly one configured peer (set_peer()), there's no contact-table
// problem to solve: any direct message addressed to us either came from
// that peer or it didn't, so we just check the src_hash against peer_ and
// run ECDH against its already-known full public key.
void MeshCoreComponent::handle_direct_text_(mc::Packet &pkt) {
  if (pkt.payload_len < 2 + 2)
    return;
  uint8_t dest_hash = pkt.payload[0];
  uint8_t src_hash = pkt.payload[1];
  if (!this->identity_.is_hash_match(dest_hash))
    return;  // not for us (still eligible for relay)

  if (!this->has_peer_) {
    ESP_LOGW(TAG, "Direct message received but no peer configured (set 'peer_public_key' in YAML) — dropping");
    return;
  }
  if (!this->peer_.is_hash_match(src_hash)) {
    ESP_LOGW(TAG, "Direct message from src_hash=0x%02X doesn't match the configured peer — dropping "
                  "(if this is unexpected, hash collisions on a 1-byte hash are possible on a busy mesh)",
             src_hash);
    return;
  }

  uint8_t secret[32];
  this->identity_.calc_shared_secret(secret, this->peer_);
  uint8_t plain[mc::MAX_PACKET_PAYLOAD];
  int plen = mc_crypto::mac_then_decrypt(secret, plain, &pkt.payload[2], pkt.payload_len - 2);
  if (plen <= 4) {
    ESP_LOGW(TAG, "Direct message failed MAC check");
    return;
  }
  std::string text((const char *) &plain[4], plen - 4);
  while (!text.empty() && text.back() == '\0')
    text.pop_back();
  ESP_LOGD(TAG, "Message from peer: %s", text.c_str());
  this->on_message_trigger_.trigger(text);
}

bool MeshCoreComponent::send_message(const std::string &text) {
  if (!this->has_peer_) {
    ESP_LOGE(TAG, "Cannot send_message: no 'peer_public_key' configured");
    return false;
  }
  return this->send_direct_text(this->peer_.pub_key, text);
}

bool MeshCoreComponent::send_channel_text(const std::string &channel_name, const std::string &text) {
  McChannel *ch = this->find_channel_(channel_name);
  if (ch == nullptr) {
    ESP_LOGE(TAG, "Unknown channel '%s'", channel_name.c_str());
    return false;
  }
  uint8_t plain[4 + mc::MAX_PACKET_PAYLOAD];
  uint32_t ts = (uint32_t) (millis() / 1000);
  memcpy(plain, &ts, 4);
  size_t n = std::min(text.size(), sizeof(plain) - 4);
  memcpy(&plain[4], text.data(), n);

  uint8_t key32[32] = {0};
  memcpy(key32, ch->psk, 16);
  mc::Packet pkt;
  pkt.header = mc::ROUTE_TYPE_FLOOD | (mc::PAYLOAD_TYPE_GRP_TXT << mc::PH_TYPE_SHIFT) | (mc::PAYLOAD_VER_1 << mc::PH_VER_SHIFT);
  pkt.payload[0] = ch->hash;
  int enc_len = mc_crypto::encrypt_then_mac(key32, &pkt.payload[1], plain, 4 + n);
  pkt.payload_len = 1 + enc_len;

  return this->transmit_(pkt);
}

bool MeshCoreComponent::send_direct_text(const uint8_t dest_pub_key[mc::PUB_KEY_SIZE], const std::string &text) {
  mc::Identity dest(dest_pub_key);
  uint8_t secret[32];
  this->identity_.calc_shared_secret(secret, dest);

  uint8_t plain[4 + mc::MAX_PACKET_PAYLOAD];
  uint32_t ts = (uint32_t) (millis() / 1000);
  memcpy(plain, &ts, 4);
  size_t n = std::min(text.size(), sizeof(plain) - 4);
  memcpy(&plain[4], text.data(), n);

  mc::Packet pkt;
  pkt.header = mc::ROUTE_TYPE_FLOOD | (mc::PAYLOAD_TYPE_TXT_MSG << mc::PH_TYPE_SHIFT) | (mc::PAYLOAD_VER_1 << mc::PH_VER_SHIFT);
  pkt.payload[0] = dest.hash_byte();
  pkt.payload[1] = this->identity_.hash_byte();
  int enc_len = mc_crypto::encrypt_then_mac(secret, &pkt.payload[2], plain, 4 + n);
  pkt.payload_len = 2 + enc_len;

  return this->transmit_(pkt);
  // NOTE: this always floods rather than building a discovered path, so it
  // works but is less efficient than a real MeshCore client on a large mesh.
}

// --- flood dedup + relay ----------------------------------------------------
bool MeshCoreComponent::already_seen_(const uint8_t hash[mc::MAX_HASH_SIZE]) {
  uint32_t now = millis();
  for (auto it = this->seen_cache_.begin(); it != this->seen_cache_.end();) {
    if (now - it->seen_at_ms > DEDUP_EXPIRE_MS) {
      it = this->seen_cache_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto &s : this->seen_cache_) {
    if (memcmp(s.hash.data(), hash, mc::MAX_HASH_SIZE) == 0)
      return true;
  }
  return false;
}

void MeshCoreComponent::remember_seen_(const uint8_t hash[mc::MAX_HASH_SIZE]) {
  if (this->seen_cache_.size() >= DEDUP_CACHE_SIZE)
    this->seen_cache_.erase(this->seen_cache_.begin());
  SeenPacket sp;
  memcpy(sp.hash.data(), hash, mc::MAX_HASH_SIZE);
  sp.seen_at_ms = millis();
  this->seen_cache_.push_back(sp);
}

void MeshCoreComponent::maybe_relay_(mc::Packet &pkt) {
  if (!this->is_repeater_)
    return;
  if (!pkt.is_route_flood())
    return;  // direct-routed relay needs the path logic this port doesn't have yet
  if (pkt.get_path_byte_len() + mc::PATH_HASH_SIZE > mc::MAX_PATH_SIZE) {
    ESP_LOGV(TAG, "Dropping flood packet — path already at max length");
    return;
  }
  // append our own hash byte to the path, matching MeshCore's flood-path build-up
  uint8_t new_path[mc::MAX_PATH_SIZE];
  memcpy(new_path, pkt.path, pkt.get_path_byte_len());
  new_path[pkt.get_path_byte_len()] = this->identity_.hash_byte();
  memcpy(pkt.path, new_path, pkt.get_path_byte_len() + 1);
  pkt.set_path_hash_count(pkt.get_path_hash_count() + 1);

  // simple randomized delay to reduce collision with other repeaters — real
  // MeshCore scales this off measured airtime/SNR; we just jitter.
  delay(random_uint32() % 250);
  this->transmit_(pkt);
}

void MeshCoreComponent::handle_packet_(mc::Packet &pkt, float rssi, float snr) {
  uint8_t hash[mc::MAX_HASH_SIZE];
  // dedup hash = sha256(payload_type [+ path_len if TRACE] + payload), matching Packet::calculatePacketHash
  uint8_t type = pkt.get_payload_type();
  if (type == mc::PAYLOAD_TYPE_TRACE) {
    uint8_t buf[2 + mc::MAX_PACKET_PAYLOAD];
    memcpy(buf, &pkt.path_len, 2);
    memcpy(&buf[2], pkt.payload, pkt.payload_len);
    mc_crypto::sha256(hash, mc::MAX_HASH_SIZE, &type, 1, buf, 2 + pkt.payload_len);
  } else {
    mc_crypto::sha256(hash, mc::MAX_HASH_SIZE, &type, 1, pkt.payload, pkt.payload_len);
  }

  if (this->already_seen_(hash)) {
    ESP_LOGV(TAG, "Duplicate packet, ignoring");
    return;
  }
  this->remember_seen_(hash);

  switch (type) {
    case mc::PAYLOAD_TYPE_ADVERT:
      this->handle_advert_(pkt);
      break;
    case mc::PAYLOAD_TYPE_GRP_TXT:
      this->handle_group_text_(pkt);
      break;
    case mc::PAYLOAD_TYPE_TXT_MSG:
      this->handle_direct_text_(pkt);
      break;
    default:
      ESP_LOGV(TAG, "Unhandled payload type 0x%02X (len=%u) — relaying only", type, pkt.payload_len);
      break;
  }

  this->maybe_relay_(pkt);
}

#if defined(MC_USE_SX126X) || defined(MC_USE_SX127X)
void MeshCoreComponent::on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) {
  if (packet.size() > 255)
    return;
  mc::Packet pkt;
  if (!pkt.read_from(packet.data(), (uint8_t) packet.size())) {
    ESP_LOGV(TAG, "Bad packet encoding, dropping");
    return;
  }
  pkt.snr = (int8_t) (snr * 4);
  this->handle_packet_(pkt, rssi, snr);
}
#endif

}  // namespace meshcore
}  // namespace esphome
