# WFBX Stats Packet Specification

Version: 1.0

## Overview

This document defines the binary container used by all WFBX modules (TX, RX, MX, …) to emit per-period statistics over UDP. The goal is to standardize the packet layout so the receiver can parse a single record without reassembly and without guessing the module-specific payload. Reference implementations live in `src/wfbx_stats_core.{h,c}` (core helpers), `src/wfbx_stats_mx.h` for MX-specific structures, and the Python equivalents under `wfbx_server/wfbxlib/stats/`.

Each stats datagram consists of a fixed-size packet header followed by a sequence of sections (TLV-style records). All values use network byte order (big-endian) unless stated otherwise. Strings are ASCII, padded with `\0` when shorter than the fixed length.

```
+----------------------+----------------------+------------------------+
| PacketHeader (48 B) | Section[0]           | Section[1] ...         |
+----------------------+----------------------+------------------------+
```

## Packet Header

| Offset | Field         | Type          | Description                                         |
|--------|---------------|---------------|-----------------------------------------------------|
| 0      | `magic`       | char[4]       | Always `"WFBX"`                                     |
| 4      | `version`     | uint8         | Packet format version (start with 1)                |
| 5      | `module_type` | uint8         | Module code: 1=TX, 2=RX, 3=MX, etc.                 |
| 6      | `module_id`   | char[24]      | ASCII identifier (from config), `\0` padded         |
| 30     | `host_id`     | char[16]      | ASCII host identifier, `\0` padded (empty if unset) |
| 46     | `tick_id`     | uint32        | Monotonic period counter                            |
| 50     | `timestamp_us`| uint64        | Timestamp in microseconds (e.g. `CLOCK_MONOTONIC`)  |
| 58     | `flags`       | uint16        | Bit flags; reserved bits must be zero               |
| 60     | `section_count`| uint16       | Number of sections that follow                      |
| 62     | `payload_len` | uint32        | Length in bytes of all sections combined            |
| 66     | `reserved`    | uint16        | Reserved for future use; set to zero                |
| 68     | `crc32`       | uint32        | Optional CRC32 over header+payload (0 if unused)    |

Total header size: **72 bytes**.

### Bit Flags (`flags`)

| Bit | Meaning                        |
|-----|--------------------------------|
| 0   | Debug metrics included         |
| 1   | Extended IF/antenna sections   |
| 2-15| Reserved (must be zero)        |

## Sections

Immediately after the header, `section_count` records are packed back-to-back. Each section has its own TLV-like miniature header:

| Offset | Field     | Type    | Description                           |
|--------|-----------|---------|---------------------------------------|
| 0      | `type`    | uint16  | Section identifier                    |
| 2      | `length`  | uint16  | Size of section payload in bytes      |
| 4      | `payload` | bytes[] | `length` bytes of data (aligned byte)  |

### Module Type Legend

| Value | Module                                   |
|-------|------------------------------------------|
| 0x01  | `WFBX_TX` — **legacy** wfb_tx (classic uni-directional) |
| 0x02  | `WFBX_RX` — **legacy** wfb_rx                      |
| 0x03  | `WFBX_MX`                                        |
| 0x04  | `WFBX_PTX`                                       |
| 0x05  | `WFBX_UPRX`                                      |
| 0x06  | `WFBX_UFRX`                                      |
| 0x07  | `WFBX_XTX` — mesh-aware wfbx_tx                   |
| 0x08  | `WFBX_XRX` — mesh-aware wfbx_rx                   |
| 0x09  | `WFBX_L2_TAP`                                    |
| 0xFF  | Reserved / unknown                               |

> **Note**
>
> * `wfb_tx`/`wfb_rx` (legacy classic link) report as module types `WFBX_TX` / `WFBX_RX`.
> * `wfbx_tx`/`wfbx_rx` (mesh-capable pipeline) report as `WFBX_XTX` / `WFBX_XRX`.
> * PTX uses `WFBX_PTX` and exposes pre-TX multiplexer stats.

Sections are not padded. Receivers should skip unknown section `type`s by advancing `length` bytes.

### Defined Section Types

| Type  | Name                | Description                                                 |
|-------|---------------------|-------------------------------------------------------------|
| 0x0001| `SUMMARY`           | Module-wide summary (one fixed struct)                      |
| 0x0002| `TX_SUMMARY`        | Array of per-TX aggregates                                  |
| 0x0003| `GLOBAL_DEBUG`      | Optional debug metrics (enabled by flag bit 0)              |
| 0x0010| `IF_DETAIL`         | Per-interface statistics (may be repeated per TX)           |
| 0x0020| `ANT_DETAIL`        | Per-antenna statistics (per interface)                      |
| 0x00F0| `TEXT_PREVIEW`      | Null-terminated ASCII snippet (optional)                    |

Modules may extend the list by allocating new type codes. Values `0xF000-0xFFFF` are reserved for experimentation.

### Example Payload Structures

#### Section 0x0001 — `SUMMARY`

```
struct summary_section {
    uint32_t dt_ms;            // length of stats window
    uint32_t packets_total;    // number of packets processed this window
    uint32_t bytes_total;      // total bytes processed
    uint32_t ctrl_epoch_sent;  // MX-specific counter (0 for other modules)
    uint16_t iface_count;      // number of interfaces involved
    uint16_t tx_count;         // number of TX entries in subsequent sections
    uint16_t flags;            // copy of header flags (optional)
    uint16_t reserved;         // align to 4-byte boundary
};
```

#### Section 0x0002 — `TX_SUMMARY`

Payload is an array of the following 24-byte struct:

```
struct tx_summary_entry {
    uint8_t  tx_id;
    uint8_t  if_count;
    uint16_t state_flags;
    uint32_t packets;
    uint32_t lost;
    int16_t  rssi_q8;          // RSSI * 256
    uint16_t quality_permille; // 0..1000
    int32_t  rate_kbps;
    int32_t  debug_real_delta_q4; // optional, scaled value
    int32_t  debug_e_delta_q4;    // optional, scaled value
};
```

`state_flags` can indicate whether optional fields are valid (e.g. bit0 = debug metrics present).

#### Section 0x0010 — `IF_DETAIL`

```
struct if_detail_header {
    uint8_t tx_id;
    uint8_t iface_id;
    uint8_t chain_count;
    uint8_t reserved;
    uint32_t packets;
    uint32_t lost;
    uint16_t quality_permille;
    int16_t  best_chain_rssi_q8;
    // Followed by chain_count entries of struct chain_detail
};

struct chain_detail {
    uint8_t  chain_id;
    uint8_t  ant_id;
    uint16_t quality_permille;
    int16_t  rssi_min_q8;
    int16_t  rssi_avg_q8;
    int16_t  rssi_max_q8;
    uint16_t packets;
    uint16_t lost;
};
```

#### Section 0x0003 — `GLOBAL_DEBUG`

```
struct global_debug_section {
    int32_t real_delta_avg_q4;
    int32_t real_delta_min_q4;
    int32_t real_delta_max_q4;
    uint32_t real_delta_samples;
    int32_t e_delta_avg_q4;
    int32_t e_delta_min_q4;
    int32_t e_delta_max_q4;
    uint32_t e_delta_samples;
    int32_t e_epoch_avg_q4;
    int32_t e_epoch_min_q4;
    int32_t e_epoch_max_q4;
    uint32_t e_epoch_samples;
    int32_t e_epoch_last_avg_q4;
    int32_t e_epoch_last_min_q4;
    int32_t e_epoch_last_max_q4;
    uint32_t e_epoch_last_samples;
};

### MX-Specific Section Usage

Current MX implementation is expected to emit:

- `SUMMARY` (0x0001) — per-tick global summary.
- `TX_SUMMARY` (0x0002) — array of per-TX aggregates.
- `IF_DETAIL` (0x0010) — optional, repeated per `(tx, iface)`, with embedded `chain_detail` records.
- `GLOBAL_DEBUG` (0x0003) — optional diagnostics when debug flag is set.

Additional sections may be defined for MX as the telemetry evolves.
```

## Packet Size Considerations

- Target total size ≤ 1300 bytes to remain within a single Ethernet MTU after UDP/IP headers.
- Optional sections should be omitted when empty or disabled via flags to keep packets compact.
- If a dataset cannot fit within a single datagram (e.g. hundreds of antennas), the module should split it into multiple packets with the same `tick_id` and use section flags to signal continuation.

## Versioning

- `magic` + `version` gate parsing. Increment `version` only when the header layout changes in a backward-incompatible way.
- Section types can evolve independently; new receivers ignore unknown `type`s.
- When introducing new fields within an existing section, guard them with `state_flags` or increase `version`.

## CRC and Integrity

- `crc32` is optional; when used, compute CRC over the entire packet with the `crc32` field set to zero during calculation.
- If CRC is zero, receivers may optionally skip integrity checking.

## Example Layout

```
Header:
  magic="WFBX", version=1, module_type=3 (MX), module_id="mx_main"...
  tick_id=1024, timestamp_us=123456789000, flags=0x0001, section_count=3, payload_len=320
Section[0]: type=0x0001 (SUMMARY), length=32
Section[1]: type=0x0002 (TX_SUMMARY), length=120
Section[2]: type=0x0010 (IF_DETAIL), length=168
```

This structure ensures consistent parsing across modules and allows receivers to evolve independently from emitters.
