# Handshake and crypto: CRYPTO frames, key derivation, packet protection

How an in-kernel QUIC connection gets its keys and how every packet is
protected. QUIC's cryptographic handshake is TLS 1.3, and in this implementation
**the TLS handshake runs in userspace** (via the kernel `handshake` netlink
upcall / a userspace TLS library); the kernel's job is to carry handshake bytes
in CRYPTO frames, derive the QUIC traffic keys from the TLS secrets, and do the
per-packet AEAD + header protection. This doc is the crypto counterpart to the
packet doc (`03_packet.md`) and the frame doc (`04_frame.md`).

Spec: RFC 9001 (QUIC-TLS), RFC 9000 §17 (packet protection context), RFC 9369
(QUIC v2), RFC 8446 §7.1 (HKDF-Expand-Label).
Code: `net/quic/crypto.c`, `net/quic/crypto.h`, CRYPTO-frame handling in
`net/quic/frame.c`, the no-encryption negotiation in `net/quic/inqueue.c` and
`net/quic/packet.c`.

## Where the handshake actually happens

The kernel does not implement TLS. The userspace handshake library drives it and
feeds the kernel the negotiated traffic secrets through
`setsockopt(QUIC_SOCKOPT_CRYPTO_SECRET)` carrying a `struct quic_crypto_secret`
(`include/uapi/linux/quic.h:120-127`: `send`, `level`, cipher `type`, and a
48-byte `secret`). Handshake message bytes themselves travel in CRYPTO frames,
tagged with a crypto level via the `QUIC_HANDSHAKE_INFO` cmsg
(`quic_handshake_info.crypto_level`, uapi:56-58). The four levels are
`QUIC_CRYPTO_APP / INITIAL / HANDSHAKE / EARLY` (uapi:48-54); each has its own
`struct quic_crypto` instance (`quic_sk->crypto[QUIC_CRYPTO_MAX]`, selected by
`quic_crypto(sk, level)` in socket.h:181).

So the fuzzing-relevant split: Initial keys are derivable by *anyone* from the
client's first Destination Connection ID (no secret), but Handshake and 1-RTT
(App) keys require the TLS handshake to have produced secrets. A stateless
syscall fuzzer can reach the Initial-packet decrypt path with no cooperation;
everything past it needs the real handshake to have installed secrets.

## Initial keys: derivable from the DCID alone

`quic_crypto_initial_keys_install()` (crypto.c:921) implements the RFC 9001 §5.2
pseudocode (quoted at crypto.c:931-951). The salt is a fixed per-version
constant:

- `QUIC_INITIAL_SALT_V1` (crypto.c:910, 20 bytes, `38 76 2c f7 …`), selected by
  default.
- `QUIC_INITIAL_SALT_V2` (crypto.c:914, `0d ed e3 de …`), used when
  `version == QUIC_VERSION_V2` (crypto.c:960-962).

The initial secret is `HKDF-Extract(salt, client_DCID)`
(`quic_crypto_hkdf_extract`, crypto.c:966), then the client/server directional
secrets are expanded with labels `"client in"` / `"server in"`; `is_serv`
decides which is TX and which is RX (crypto.c:953-959 — a server transmits with
`"server in"` and receives with `"client in"`). The cipher for Initial space is
hardcoded to AES-GCM-128 regardless of what is later negotiated (crypto.c:972,
`TLS_CIPHER_AES_GCM_128`), exactly as RFC 9001 requires. Because the DCID is on
the wire in the clear, **Initial-packet protection is obfuscation, not secrecy**
— any observer can derive these keys.

## HKDF and the label set

- `quic_crypto_hkdf_extract()` (crypto.c:25) = `HMAC(salt, IKM)` via a shash tfm.
- `quic_crypto_hkdf_expand()` (crypto.c:42) = HKDF-Expand-Label per RFC 8446
  §7.1: it builds `HkdfLabel = len(2) || "tls13 "+label || context` (prefix
  `"tls13 "` at crypto.c:50) into a ≤256-byte info buffer and runs the standard
  `T(i) = HMAC(secret, T(i-1) || info || i)` loop (crypto.c:80-109).
- `quic_crypto_keys_derive()` (crypto.c:136) derives {key, iv, hp-key} from a
  secret via three expands, choosing the label set by version (crypto.c:154-158):

  | purpose | v1 label | v2 label |
  |---------|----------|----------|
  | AEAD key | `"quic key"` (crypto.c:116) | `"quicv2 key"` (crypto.c:129) |
  | AEAD iv  | `"quic iv"` (crypto.c:117)  | `"quicv2 iv"` (crypto.c:130) |
  | header-protection key | `"quic hp"` (crypto.c:118) | `"quicv2 hp"` (crypto.c:131) |
  | key-update | `"quic ku"` (crypto.c:120) | `"quicv2 ku"` (crypto.c:133) |

  The hp-key is only (re)derived when deriving into the *current* key phase
  (crypto.c:205); a key update must not change the header-protection key, so the
  update path passes `hp == NULL`.

## The cipher suites

`ciphers[]` (crypto.c:244-254, built by a `CIPHER_DESC` macro) covers four TLS
1.3 suites; `quic_crypto_set_cipher()` (crypto.c:707) allocates the tfms:

| suite | AEAD (payload) | skcipher (header prot.) | hash (KDF) | secretlen |
|-------|----------------|-------------------------|------------|-----------|
| TLS_CIPHER_AES_GCM_128 | `gcm(aes)` | `ecb(aes)` | `hmac(sha256)` | 32 |
| TLS_CIPHER_AES_GCM_256 | `gcm(aes)` | `ecb(aes)` | `hmac(sha384)` | 48 |
| TLS_CIPHER_AES_CCM_128 | `ccm(aes)` | `ecb(aes)` | `hmac(sha256)` | 32 |
| TLS_CIPHER_CHACHA20_POLY1305 | `rfc7539(chacha20,poly1305)` | `chacha20` | `hmac(sha256)` | 32 |

Each `quic_crypto` holds two AEAD tfms per direction (`tx_tfm[2]`, `rx_tfm[2]`,
one per key phase), one HP skcipher per direction, and the secret/iv arrays
(`crypto.h:30-60`). Fixed sizes: `QUIC_TAG_LEN 16`, `QUIC_IV_LEN 12`,
`QUIC_KEY_LEN 32`, `QUIC_SECRET_LEN 48` (crypto.h:11-14).

`quic_crypto_set_secret()` (crypto.c:770) is the install entry from the
CRYPTO_SECRET sockopt: it lazily sets the cipher if unset, then derives and
installs keys into the TX or RX slot of the *current* phase and sets
`send_ready` / `recv_ready`.

## Per-packet protection: AEAD payload + header protection

Two layers, both in crypto.c, each a single function shared by encrypt/decrypt:

**Payload — `quic_crypto_payload_protect()` (crypto.c:469).** AEAD over the
packet payload. The nonce is `base_iv XOR left-padded-big-endian(packet_number)`
(RFC 9001 §5.3, crypto.c:530-533); for CCM a fixed `TLS_AES_CCM_IV_B0_BYTE` is
prepended (crypto.c:536). The associated data is the packet header up to the end
of the packet-number field (`hlen = number_offset + number_len`, crypto.c:539).
On encrypt it grows the skb by `QUIC_TAG_LEN` and stamps the key-phase bit into
the short header (crypto.c:490-495); on decrypt it requires at least
`QUIC_TAG_LEN` trailing bytes (crypto.c:502) or returns `-EINVAL`. Crypto can run
**async** (hardware offload) with a completion callback
(`quic_crypto_done`, crypto.c:451) tracked by `async_pending[phase]`, or
**sync** when `cb->sync` is set (crypto.c:541).

**Header — `quic_crypto_header_protect()` (crypto.c:326).** RFC 9001 §5.4: a
16-byte *sample* is taken from the ciphertext at `number_offset + QUIC_PN_MAX_LEN`
(crypto.c:374) and run through the HP cipher to produce a mask. The first byte is
masked with `0x0f` (long header) or `0x1f` (short header) (crypto.c:399-401), and
the packet-number bytes are XORed with `mask[1..number_len]` (crypto.c:407-409).
On decrypt the header is unprotected *first* so `number_len` and (for short
headers) the key-phase bit can be read (crypto.c:403-405), then
`quic_crypto_get_number()` (crypto.c:298) reconstructs the full 62-bit packet
number from the truncated on-wire value against the highest seen PN
(RFC 9000 §17.1 / Appendix A). ChaCha20 vs AES selects whether the sample feeds
the nonce or the ECB block (crypto.c:337, 375).

Top-level entries: `quic_crypto_encrypt()` (crypto.c:577) and
`quic_crypto_decrypt()` (crypto.c:610). Failure of the decrypt is what drives
`QUIC_MIB_PKT_DECDROP` (see `10_mib.md`).

## The disable_1rtt_encryption "fake-key" path

QUIC has a draft extension (`draft-banks-quic-disable-encryption`) that turns off
**1-RTT (App-level) protection** for debugging/testing. This implementation
supports it, and it is a prime fuzzing lever because it lets you read and mutate
1-RTT packets in the clear. Mechanism (note: crypto.c itself has no reference to
it — it is implemented by *zeroing the tag length* so the crypto calls are
skipped):

1. **Negotiation (both sides must opt in).** The transport parameter
   `QUIC_TRANSPORT_PARAM_DISABLE_1RTT_ENCRYPTION = 0xbaad` (frame.h:71) is built
   at frame.c:3026 and parsed at frame.c:3317. On parse, a client is not allowed
   to send a non-zero value — `!is_serv && valuelen` is rejected
   (frame.c:3320-3321); otherwise `params->disable_1rtt_encryption = 1`.
2. **Applying it.** `quic_inq_set_param()` (inqueue.c:570), when applying the
   peer's params, sets `taglen[SHORT] = 0` via `quic_packet_set_taglen()` only if
   *both* the local inqueue flag and the peer's advertised flag are set
   (inqueue.c:583-584). Only the SHORT/App form is affected; Initial, Handshake,
   and 0-RTT keep real AEAD. `taglen[]` defaults to `QUIC_TAG_LEN` for both forms
   (packet.c:2948-2949), so this is an opt-in downgrade.
3. **Send.** `quic_packet_xmit()` skips `quic_crypto_encrypt()` entirely when the
   form's taglen is 0 (`if (!packet->taglen[...]) goto xmit;`, packet.c:2825).
4. **Receive.** The short-header RX path sets `cb->resume = 1` when taglen is 0
   (packet.c:2041-2046); `quic_crypto_decrypt()` then takes the `cb->resume` fast
   path (crypto.c:621-626) — it only reconstructs the packet number and skips both
   header-protection removal and AEAD, reading the packet as plaintext.

So "fake keys" is really "no tag, no crypto calls" for 1-RTT, gated behind a
mutual transport-parameter negotiation.

## Key update (RFC 9001 §6)

`quic_crypto_key_update()` (crypto.c:836): derives the next-phase secret with the
`"quic ku"` / `"quicv2 ku"` label (crypto.c:838, 865-866) into the `!phase` slot
and installs new AEAD keys *without* changing the HP key (crypto.c:873). It is
idempotent — no-ops if `key_derived` already set (crypto.c:846) — and guarded by
`key_pending` / `recv_ready` (crypto.c:844). The actual phase flip happens in the
decrypt path (crypto.c:686) when a packet arrives with the opposite key-phase
bit; that trigger packet is forced synchronous (`cb->sync = 1`, crypto.c:656).
Old keys are retained for a window and released once
`now - key_update_send_time >= key_update_time` (crypto.c:696-702). (The source
of `key_update_time`'s value was not located in crypto.c — likely a sockopt/
default set in the socket layer; **verify before relying on it**.)

## Address validation: tokens and Retry

Server-side anti-amplification / address validation (RFC 9000 §8, RFC 9001 §5.8):

- `quic_crypto_set_token_secret()` (crypto.c:808) lazily seeds a random,
  long-lived token-signing secret into the otherwise-unused phase-1 Initial slot
  (`tx_secret[1]`, crypto.c:816-817), always with v1 labels (crypto.c:822; read
  as intentional version-independent listener state — **not independently
  confirmed**).
- `quic_crypto_generate_token()` (crypto.c:1138) / `quic_crypto_verify_token()`
  (crypto.c:1181): token layout `[flag][client addr][timestamp(8)][orig DCID]
  [tag(16)]` (crypto.c:1128-1134). Verify does a constant-time address compare
  (`crypto_memneq`, crypto.c:1205) and a freshness check against
  `QUIC_TOKEN_TIMEOUT_RETRY` (3 s) or `QUIC_TOKEN_TIMEOUT_REGULAR` (600 s)
  depending on `flag` (crypto.h:16-19, crypto.c:1210-1212). An embedded timestamp
  is folded into the AEAD nonce (crypto.c:1101-1109).
- `quic_crypto_get_retry_tag()` (crypto.c:1004) computes the Retry Integrity Tag
  (RFC 9001 §5.8) with the **published fixed** key/nonce constants
  (`QUIC_RETRY_KEY_V1/V2`, `QUIC_RETRY_NONCE_V1/V2`, crypto.c:995-1001), AES-128-
  GCM over the Retry Pseudo-Packet (ODCID-prefixed), zero-length plaintext. These
  constants are the same for every connection — the Retry tag authenticates the
  server's Retry, it is not a secret.
- `QUIC_TOKEN_FLAG_REGULAR = 0` (a NEW_TOKEN token) vs `QUIC_TOKEN_FLAG_RETRY = 1`
  (a Retry token) (crypto.h:16-17).

## CRYPTO frames (frame.c)

- `quic_frame_crypto_create()` (frame.c:389) emits `[type][offset][length][data]`
  (RFC 9000 §19.6) where offset is `crypto->send_offset` (frame.c:408); on a
  client Initial it reserves 256 bytes of frame budget for a possible Retry token
  (frame.c:399-401). Handshake bytes are copied from the user iterator.
- `quic_frame_crypto_process()` (frame.c:992) parses the offset/length varints and
  rejects `offset + length > 2^62-1` with `QUIC_TRANSPORT_ERROR_FRAME_ENCODING`
  (RFC 9000 §19.6). It is zero-copy: the received frame references the skb data
  (`skb_get`, frame.c:1023) and is handed to `quic_inq_handshake_recv()`
  (frame.c:1032) for offset-ordered reassembly into the handshake list (see
  `05_streams.md`), from which userspace reads it with `recvmsg` +
  `QUIC_HANDSHAKE_INFO`.

## Fuzzing relevance

The Initial decrypt path is reachable with no secrets (keys derive from the DCID
on the wire), so header-parse and Initial-packet validation are fuzzable blind.
Everything at Handshake/App level requires real TLS secrets installed via the
CRYPTO_SECRET sockopt, which a stateful harness supplies by driving (or faking)
the userspace handshake. `disable_1rtt_encryption` is the shortcut to exercise
1-RTT frame processing without that: negotiate it on both ends and 1-RTT packets
flow in the clear.

## Cross-references

- Where protected packets are parsed/assembled and the PN spaces: `03_packet.md`.
- CRYPTO frame reassembly in the inqueue, and streams: `05_streams.md`.
- The drop counters these paths feed (DECDROP, INVHDRDROP): `10_mib.md`.
- Connection IDs that seed Initial keys and stateless-reset tokens: `06_connid.md`.
