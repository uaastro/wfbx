#pragma once
/* Minimal shared Wi‑Fi Broadcast defs for RX/TX (Radiotap + 802.11) */
#include <stdint.h>
#include <stddef.h>

/* ---- Radiotap field indexes (subset we use) ---- */
#ifndef IEEE80211_RADIOTAP_TSFT
#define IEEE80211_RADIOTAP_TSFT              0
#define IEEE80211_RADIOTAP_FLAGS             1
#define IEEE80211_RADIOTAP_RATE              2
#define IEEE80211_RADIOTAP_CHANNEL           3
#define IEEE80211_RADIOTAP_FHSS              4
#define IEEE80211_RADIOTAP_DBM_ANTSIGNAL     5
#define IEEE80211_RADIOTAP_DBM_ANTNOISE      6
#define IEEE80211_RADIOTAP_LOCK_QUALITY      7
#define IEEE80211_RADIOTAP_TX_ATTENUATION    8
#define IEEE80211_RADIOTAP_DB_TX_ATTENUATION 9
#define IEEE80211_RADIOTAP_DBM_TX_POWER      10
#define IEEE80211_RADIOTAP_ANTENNA           11
#define IEEE80211_RADIOTAP_DB_ANTSIGNAL      12
#define IEEE80211_RADIOTAP_DB_ANTNOISE       13
#define IEEE80211_RADIOTAP_RX_FLAGS          14
#define IEEE80211_RADIOTAP_TX_FLAGS          15
#define IEEE80211_RADIOTAP_MCS               19
#endif

/* Radiotap Flags byte (rx) */
#ifndef RADIOTAP_F_BITS
#define RADIOTAP_F_CFP      0x01
#define RADIOTAP_F_SHORTPRE 0x02
#define RADIOTAP_F_WEP      0x04
#define RADIOTAP_F_FRAG     0x08
#define RADIOTAP_F_FCS      0x10  /* FCS included at end of frame */
#define RADIOTAP_F_DATAPAD  0x20  /* 802.11 header padded to 32-bit */
#define RADIOTAP_F_BADFCS   0x40  /* bad FCS on receive */
#endif

/* Minimal Radiotap header (with present chain) */
#pragma pack(push,1)
struct wfb_radiotap_hdr_min {
  uint8_t  it_version;   /* 0 */
  uint8_t  it_pad;
  uint16_t it_len;       /* total radiotap header length */
  uint32_t it_present;   /* may extend via bit31 */
};
#pragma pack(pop)

/* 802.11 MAC Data header (no QoS/HT-Control here) */
#pragma pack(push,1)
struct wfb_dot11_hdr {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;     /* [15:4]=seq, [3:0]=frag */
};
#pragma pack(pop)

/* Chains/antennas upper bound used in project */
#ifndef RX_ANT_MAX
#define RX_ANT_MAX 4
#endif

/* Radiotap alignment and size helpers (only fields we use) */
static inline size_t wfb_rt_align(uint8_t field_idx, size_t off) {
  size_t align = 1;
  switch (field_idx) {
    case IEEE80211_RADIOTAP_TSFT: align = 8; break;
    case IEEE80211_RADIOTAP_CHANNEL:
    case IEEE80211_RADIOTAP_FHSS:
    case IEEE80211_RADIOTAP_LOCK_QUALITY:
    case IEEE80211_RADIOTAP_TX_ATTENUATION:
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
    case IEEE80211_RADIOTAP_RX_FLAGS:
    case IEEE80211_RADIOTAP_TX_FLAGS:
      align = 2; break;
    default: align = 1; break;
  }
  size_t rem = off % align;
  if (rem) off += (align - rem);
  return off;
}
static inline size_t wfb_rt_size(uint8_t field_idx) {
  switch (field_idx) {
    case IEEE80211_RADIOTAP_TSFT: return 8;
    case IEEE80211_RADIOTAP_FLAGS: return 1;
    case IEEE80211_RADIOTAP_RATE: return 1;
    case IEEE80211_RADIOTAP_CHANNEL: return 4;
    case IEEE80211_RADIOTAP_FHSS: return 2;
    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: return 1;
    case IEEE80211_RADIOTAP_DBM_ANTNOISE: return 1;
    case IEEE80211_RADIOTAP_LOCK_QUALITY: return 2;
    case IEEE80211_RADIOTAP_TX_ATTENUATION: return 2;
    case IEEE80211_RADIOTAP_DB_TX_ATTENUATION: return 2;
    case IEEE80211_RADIOTAP_DBM_TX_POWER: return 1;
    case IEEE80211_RADIOTAP_ANTENNA: return 1;
    case IEEE80211_RADIOTAP_DB_ANTSIGNAL: return 1;
    case IEEE80211_RADIOTAP_DB_ANTNOISE: return 1;
    case IEEE80211_RADIOTAP_RX_FLAGS: return 2;
    case IEEE80211_RADIOTAP_TX_FLAGS: return 2;
    case IEEE80211_RADIOTAP_MCS: return 3;
    default: return 0;
  }
}

/* TX-side: Radiotap MCS “known” bits and flags */
#ifndef WFB_MCS_BITS
#define WFB_MCS_KNOWN_BW    0x01
#define WFB_MCS_KNOWN_MCS   0x02
#define WFB_MCS_KNOWN_GI    0x04
#define WFB_MCS_KNOWN_FEC   0x10
#define WFB_MCS_KNOWN_STBC  0x20
#define WFB_MCS_FLAGS_BW40      0x01  /* 0=20, 1=40 */
#define WFB_MCS_FLAGS_SGI       0x04
#define WFB_MCS_FLAGS_LDPC      0x10
#define WFB_MCS_FLAGS_STBC_SHIFT 5    /* 2 bits */
#endif

/* TX-side: Radiotap TX_FLAGS bits */
#ifndef WFB_TXF_BITS
#define WFB_TXF_NOACK      0x0008
#define WFB_TXF_NOSEQ      0x0010
#define WFB_TXF_NOAGG      0x0080
#define WFB_TXF_FIXED_RATE 0x0100
#endif

/* ---------- Radiotap MCS + TX definitions ---------- */

/* TX flags */
#ifndef IEEE80211_RADIOTAP_F_TX_NOACK
#define IEEE80211_RADIOTAP_F_TX_NOACK      0x0008
#endif
#ifndef IEEE80211_RADIOTAP_F_TX_NOSEQ
#define IEEE80211_RADIOTAP_F_TX_NOSEQ      0x0010
#endif
#ifndef IEEE80211_RADIOTAP_F_TX_FIXED_RATE
#define IEEE80211_RADIOTAP_F_TX_FIXED_RATE 0x0100
#endif

/* MCS known bits */
#ifndef IEEE80211_RADIOTAP_MCS_HAVE_MCS
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS    0x02
#endif
#ifndef IEEE80211_RADIOTAP_MCS_HAVE_BW
#define IEEE80211_RADIOTAP_MCS_HAVE_BW     0x01
#endif
#ifndef IEEE80211_RADIOTAP_MCS_HAVE_GI
#define IEEE80211_RADIOTAP_MCS_HAVE_GI     0x04
#endif
#ifndef IEEE80211_RADIOTAP_MCS_HAVE_FEC
#define IEEE80211_RADIOTAP_MCS_HAVE_FEC    0x10
#endif
#ifndef IEEE80211_RADIOTAP_MCS_HAVE_STBC
#define IEEE80211_RADIOTAP_MCS_HAVE_STBC   0x20
#endif

/* MCS flags */
#ifndef IEEE80211_RADIOTAP_MCS_BW_20
#define IEEE80211_RADIOTAP_MCS_BW_20       0
#endif
#ifndef IEEE80211_RADIOTAP_MCS_BW_40
#define IEEE80211_RADIOTAP_MCS_BW_40       1
#endif
#ifndef IEEE80211_RADIOTAP_MCS_SGI
#define IEEE80211_RADIOTAP_MCS_SGI         0x04
#endif
#ifndef IEEE80211_RADIOTAP_MCS_FEC_LDPC
#define IEEE80211_RADIOTAP_MCS_FEC_LDPC    0x10
#endif
#ifndef IEEE80211_RADIOTAP_MCS_STBC_MASK
#define IEEE80211_RADIOTAP_MCS_STBC_MASK   0x60
#endif

/* Radiotap TX header */
struct wfb_radiotap_tx {
  uint8_t  it_version;
  uint8_t  it_pad;
  uint16_t it_len;
  uint32_t it_present;

  uint16_t tx_flags; /* IEEE80211_RADIOTAP_TX_FLAGS */

  struct {
    uint8_t known;
    uint8_t flags;
    uint8_t mcs;
  } mcs; /* IEEE80211_RADIOTAP_MCS */
} __attribute__((packed));
