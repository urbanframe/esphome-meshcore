# esphome-meshcore

An ESPHome external component that turns an ESP32 + SX126x/SX127x LoRa radio
into a native [MeshCore](https://github.com/meshcore-dev/MeshCore) node —
built the same way `esphome-meshtastic` drives the radio directly, rather
than bridging to an already-flashed device.

## What's actually real here vs. what's scaffolded

I built this against MeshCore's real upstream source (cloned from
`meshcore-dev/MeshCore`, not from memory), and verified the core logic by
compiling and running it standalone:

| Piece | Status |
|---|---|
| Wire packet format (`mc_packet.h`) | Ported line-for-line from `src/Packet.h`/`.cpp`. Round-trip tested. |
| SHA256 packet-hash dedup | Matches `Packet::calculatePacketHash`. Tested. |
| AES-128-ECB + HMAC-SHA256 truncated-MAC scheme | Matches `Utils::encrypt`/`encryptThenMAC`/`MACThenDecrypt`. Encrypt→decrypt round-trip **and** tamper-detection tested. |
| Ed25519 identity: keygen / sign / verify / X25519 ECDH | Uses the *same* vendored `orlp/ed25519` library MeshCore itself uses (`lib/ed25519`), so it isn't a second, possibly-divergent crypto implementation. Sign/verify and two-way ECDH agreement tested. |
| ADVERT build + signature verify | Implemented against MeshCore's advert layout as documented/inferred from source. **Not cross-tested against a real device** — see Known gaps. |
| Channel (group) text messages, both directions | Implemented and internally round-trip tested. |
| Flood relay with hash dedup, path byte append | Implemented per `Packet`'s flood/path model. |
| Direct (1:1) message send | Sends correctly, but see contact-table gap below. |
| SX126x/SX127x radio glue | Mirrors the exact `register_listener`/`transmit_packet`/`on_packet` calls used by the real `esphome-meshtastic` component, so it's wired the way ESPHome expects. |

**What I have not been able to do:** test any of this against a real
MeshCore device over the air. Everything above is verified for internal
consistency (packets I encode, I can decode; messages I encrypt, I can
decrypt; signatures I make, verify) but I have no hardware-in-the-loop
confirmation that this interoperates with genuine MeshCore firmware. Treat
this as a strong first cut to validate against real hardware, not a
finished, field-proven implementation.

## Single-peer mode

If you only ever need to talk to one other MeshCore node whose public key
you already have, set `peer_public_key` in YAML. This sidesteps MeshCore's
whole contact-table problem: direct messages are addressed on the wire by
just a 1-byte hash of the sender's public key, which normally isn't enough
on its own to redo the ECDH key exchange (you need the sender's *full*
pubkey, usually learned from an earlier ADVERT, and a contact store to
remember it). With exactly one legitimate sender configured, there's
nothing to disambiguate — any direct message whose src_hash matches your
peer's pubkey is decrypted against that peer, and any message from someone
else is dropped. Use `meshcore.send_message` / the `on_message` trigger.

You still need your own `public_key`/`private_key` pinned (not just the
peer's) — see "Getting a node identity" below — since messages are
addressed to hashes of *your* key too.

## Known gaps (the "major undertaking" part that's still ahead)

1. **No general contact table.** Fine for single-peer mode above; if you
   later want to talk to more than one node, you'd need to extend
   `peer_public_key` into a proper list/lookup and handle ambiguity when
   two contacts collide on the same 1-byte hash (rare, but possible).
2. **No path-based direct routing.** All sends here flood. Real MeshCore
   builds and reuses discovered paths (`PAYLOAD_TYPE_PATH`, path hashes) for
   efficiency on larger meshes. This component only appends its own hash to
   a flood packet's path as it relays — it doesn't do path discovery or
   direct-route sends.
3. **No transport codes, multi-part packets, or repeater/room-server ACLs.**
   Out of scope for a first cut.
4. **Timestamps use `millis()/1000`, not wall-clock time.** MeshCore uses
   real UNIX time for replay protection on some payload types. If you have
   `time:` configured in ESPHome, wire that in before relying on this in a
   mesh with other strict/room-server nodes.
5. **The advert payload layout (field order/flags) was built from reading
   MeshCore's headers, not from a byte-level capture of a real advert
   packet.** It's my best-faith reconstruction, not a confirmed match. If
   ADVERTs from real devices fail signature verification once you test this,
   this layout is the first thing to check against a live capture.
6. **`sync_value` in the example YAML is a guess** — confirm it against
   whatever the current MeshCore firmware's LoRa radio init actually uses
   before assuming two devices will hear each other.
7. **MeshCore's own "V2 protocol spec" is still an open roadmap item.** This
   targets V1 (`PAYLOAD_VER_1`), which is what's shipping today, but the
   wire format isn't frozen forever.

## Layout

```
components/meshcore/
  mc_packet.h       — wire format (header-only, no radio/crypto deps)
  mc_crypto.h/.cpp   — AES/SHA256/HMAC via mbedTLS (already on ESP32)
  mc_identity.h/.cpp — Ed25519 wrapper
  ed25519/           — vendored orlp/ed25519 (zlib-style license, see license.txt)
  meshcore.h/.cpp     — the ESPHome component itself
  __init__.py         — ESPHome config schema / codegen
tools/generate_identity.py — generates a real keypair for secrets.yaml
meshcore-example.yaml
```

## Getting a node identity

Run `python3 tools/generate_identity.py` (needs a C compiler on PATH — it
builds the same vendored ed25519 library the ESP32 side uses, so the output
format is guaranteed consistent). Put the two resulting hex strings in your
`secrets.yaml` as shown in the example, or the component will generate a
throwaway identity every boot and your node's "address" on the mesh will
change every reboot.

## Suggested next steps, in order

1. Flash it, and using MeshCore's own web flasher tools, watch actual air
   traffic (there's a public web-based packet sniffer/companion app) to
   confirm your ADVERT layout and frequency/SF/BW settings actually match
   what a real device sends before debugging anything else.
2. Get channel (group) text working two-way with a real MeshCore phone app
   client on the same PSK-configured channel.
3. Add the contact table + direct-message decrypt.
4. Only then look at path-based routing efficiency — flooding will work
   correctly on a small mesh, it's just not what a "real" node does at scale.
