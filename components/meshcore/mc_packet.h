#pragma once
// Ported 1:1 from meshcore-dev/MeshCore src/Packet.h + Packet.cpp (MIT licensed).
// This is the actual on-air wire format used by real MeshCore firmware —
// not a guess. Keeping the field names/macros identical to upstream on
// purpose, so this stays diffable against the source of truth as MeshCore
// evolves.
#include <cstdint>
#include <cstring>

namespace esphome {
namespace meshcore {
namespace mc {

static constexpr uint8_t MAX_HASH_SIZE = 8;
static constexpr uint8_t PUB_KEY_SIZE = 32;
static constexpr uint8_t PRV_KEY_SIZE = 64;
static constexpr uint8_t SIGNATURE_SIZE = 64;
static constexpr uint8_t MAX_ADVERT_DATA_SIZE = 32;
static constexpr uint8_t CIPHER_KEY_SIZE = 16;
static constexpr uint8_t CIPHER_BLOCK_SIZE = 16;
// V1 wire format constants (this port targets V1 — see MeshCore's own
// "V2 protocol spec" roadmap item; that is not yet finalised upstream)
static constexpr uint8_t CIPHER_MAC_SIZE = 2;
static constexpr uint8_t PATH_HASH_SIZE = 1;

static constexpr uint16_t MAX_PACKET_PAYLOAD = 184;
static constexpr uint8_t MAX_PATH_SIZE = 64;

// header bitfields
static constexpr uint8_t PH_ROUTE_MASK = 0x03;
static constexpr uint8_t PH_TYPE_SHIFT = 2;
static constexpr uint8_t PH_TYPE_MASK = 0x0F;
static constexpr uint8_t PH_VER_SHIFT = 6;
static constexpr uint8_t PH_VER_MASK = 0x03;

enum RouteType : uint8_t {
  ROUTE_TYPE_TRANSPORT_FLOOD = 0x00,
  ROUTE_TYPE_FLOOD = 0x01,
  ROUTE_TYPE_DIRECT = 0x02,
  ROUTE_TYPE_TRANSPORT_DIRECT = 0x03,
};

enum PayloadType : uint8_t {
  PAYLOAD_TYPE_REQ = 0x00,
  PAYLOAD_TYPE_RESPONSE = 0x01,
  PAYLOAD_TYPE_TXT_MSG = 0x02,
  PAYLOAD_TYPE_ACK = 0x03,
  PAYLOAD_TYPE_ADVERT = 0x04,
  PAYLOAD_TYPE_GRP_TXT = 0x05,
  PAYLOAD_TYPE_GRP_DATA = 0x06,
  PAYLOAD_TYPE_ANON_REQ = 0x07,
  PAYLOAD_TYPE_PATH = 0x08,
  PAYLOAD_TYPE_TRACE = 0x09,
  PAYLOAD_TYPE_MULTIPART = 0x0A,
  PAYLOAD_TYPE_CONTROL = 0x0B,
  PAYLOAD_TYPE_RAW_CUSTOM = 0x0F,
};

enum PayloadVer : uint8_t {
  PAYLOAD_VER_1 = 0x00,  // 1-byte src/dest hashes, 2-byte MAC
};

// Advert flags (byte after pub_key+timestamp+signature in an ADVERT payload)
static constexpr uint8_t ADV_TYPE_MASK = 0x03;
enum AdvType : uint8_t {
  ADV_TYPE_NONE = 0x00,
  ADV_TYPE_CHAT = 0x01,
  ADV_TYPE_REPEATER = 0x02,
  ADV_TYPE_ROOM = 0x03,
};
static constexpr uint8_t ADV_LATLON_MASK = 0x10;
static constexpr uint8_t ADV_BATTERY_MASK = 0x20;
static constexpr uint8_t ADV_TEMPERATURE_MASK = 0x40;
static constexpr uint8_t ADV_NAME_MASK = 0x80;

class Packet {
 public:
  uint8_t header{0};
  uint16_t payload_len{0};
  uint16_t path_len{0};
  uint16_t transport_codes[2]{0, 0};
  uint8_t path[MAX_PATH_SIZE]{};
  uint8_t payload[MAX_PACKET_PAYLOAD]{};
  int8_t snr{0};

  uint8_t get_route_type() const { return header & PH_ROUTE_MASK; }
  bool is_route_flood() const {
    return get_route_type() == ROUTE_TYPE_FLOOD || get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD;
  }
  bool is_route_direct() const {
    return get_route_type() == ROUTE_TYPE_DIRECT || get_route_type() == ROUTE_TYPE_TRANSPORT_DIRECT;
  }
  bool has_transport_codes() const {
    return get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD || get_route_type() == ROUTE_TYPE_TRANSPORT_DIRECT;
  }
  uint8_t get_payload_type() const { return (header >> PH_TYPE_SHIFT) & PH_TYPE_MASK; }
  uint8_t get_payload_ver() const { return (header >> PH_VER_SHIFT) & PH_VER_MASK; }

  uint8_t get_path_hash_size() const { return (path_len >> 6) + 1; }
  uint8_t get_path_hash_count() const { return path_len & 63; }
  uint8_t get_path_byte_len() const { return get_path_hash_count() * get_path_hash_size(); }
  void set_path_hash_count(uint8_t n) {
    path_len &= ~63;
    path_len |= n;
  }
  void set_path_hash_size_and_count(uint8_t sz, uint8_t n) { path_len = ((sz - 1) << 6) | (n & 63); }

  static bool is_valid_path_len(uint8_t plen) {
    uint8_t hash_count = plen & 63;
    uint8_t hash_size = (plen >> 6) + 1;
    if (hash_size == 4)
      return false;  // reserved
    return (uint16_t) hash_count * hash_size <= MAX_PATH_SIZE;
  }

  int get_raw_length() const { return 2 + get_path_byte_len() + payload_len + (has_transport_codes() ? 4 : 0); }

  // MeshCore's flood-dedup hash: sha256(payload_type [+ path_len if TRACE] + payload)
  // truncated to MAX_HASH_SIZE. Implemented against real mbedtls sha256 in mc_crypto.*
  void calculate_packet_hash(uint8_t *dest_hash) const;

  // Encode/decode exactly as MeshCore's Packet::writeTo / readFrom.
  uint8_t write_to(uint8_t dest[]) const {
    uint8_t i = 0;
    dest[i++] = header;
    if (has_transport_codes()) {
      memcpy(&dest[i], &transport_codes[0], 2);
      i += 2;
      memcpy(&dest[i], &transport_codes[1], 2);
      i += 2;
    }
    dest[i++] = (uint8_t) path_len;
    uint8_t bl = get_path_byte_len();
    memcpy(&dest[i], path, bl);
    i += bl;
    memcpy(&dest[i], payload, payload_len);
    i += payload_len;
    return i;
  }

  bool read_from(const uint8_t src[], uint8_t len) {
    uint8_t i = 0;
    header = src[i++];
    if (has_transport_codes()) {
      memcpy(&transport_codes[0], &src[i], 2);
      i += 2;
      memcpy(&transport_codes[1], &src[i], 2);
      i += 2;
    } else {
      transport_codes[0] = transport_codes[1] = 0;
    }
    path_len = src[i++];
    if (!is_valid_path_len((uint8_t) path_len))
      return false;
    uint8_t bl = get_path_byte_len();
    memcpy(path, &src[i], bl);
    i += bl;
    if (i >= len)
      return false;
    payload_len = len - i;
    if (payload_len > sizeof(payload))
      return false;
    memcpy(payload, &src[i], payload_len);
    return true;
  }
};

}  // namespace mc
}  // namespace meshcore
}  // namespace esphome
