// wfbx_mx.c — Mesh manager (RX side groundwork)
/* Feature test macros: expose BSD/GNU/POSIX APIs (u_char/usleep/inet_aton) */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
// - Accepts any packets (tx_id filter defaults to ANY)
// - Adds RX radiotap MCS parsing and airtime (A_us) computation for HT (802.11n) PHY
// - Future work: estimate T_epoch, apply EMA, TDMA coordination

/* Ensure BSD typedefs (u_char/u_short/u_int) are available for libpcap */
#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <strings.h>
#include <sys/un.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>

#include "wfbx_stats_pkt.h"
#include "wfbx_ifutil.h"

#ifdef __linux__
  #include <endian.h>
#else
  #include <sys/endian.h>
#endif

#ifndef le16toh
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define le16toh(x) (x)
    #define le32toh(x) (x)
  #else
    #define le16toh(x) __builtin_bswap16(x)
    #define le32toh(x) __builtin_bswap32(x)
  #endif
#endif

#ifndef le64toh
  #if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define le64toh(x) (x)
  #else
    #define le64toh(x) __builtin_bswap64((uint64_t)(x))
  #endif
#endif

#include "wfb_defs.h"

#ifndef RX_ANT_MAX
#define RX_ANT_MAX 4
#endif

#define MAX_IFS 8

static const char* g_dest_ip_default   = "127.0.0.1";
static const int   g_dest_port_default = 5600;

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static inline uint64_t mono_us_raw(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

/* Global Epoch instant tracker across all TX and IFs (modernized algorithm) */
static int      g_have_epoch_inst = 0;
static uint8_t  g_cur_tx_id = 0;
static uint64_t g_cur_epoch_tx_us = 0;
static uint64_t g_epoch_instant_us = 0;
/* Global e_epoch (after tracker update): e_epoch = g_epoch_instant_us - epoch_tx_us */
static int64_t  g_e_epoch_sum = 0;
static int64_t  g_e_epoch_min = INT64_C(0);
static int64_t  g_e_epoch_max = INT64_C(0);
static uint64_t g_e_epoch_samples = 0;
/* Global e_epoch_last: captured at the moment of switching (prev key's last e_epoch) */
static int64_t  g_e_epoch_last_sum = 0;
static int64_t  g_e_epoch_last_min = INT64_C(0);
static int64_t  g_e_epoch_last_max = INT64_C(0);
static uint64_t g_e_epoch_last_samples = 0;

#define WFBX_MX_STATS_MAX_PACKET 1400

static uint8_t g_mx_stats_packet[WFBX_MX_STATS_MAX_PACKET];
static size_t g_mx_stats_packet_len = 0;
static uint32_t g_mx_stats_tick_id = 0;
static char g_mx_stats_module_id[24] = "mx";

static void stats_send_packet(int sock, const struct sockaddr_in* addr);

typedef struct {
    wfbx_mx_tx_summary_t summary;
} mx_tx_entry_t;

typedef struct {
    wfbx_mx_if_detail_t detail;
    wfbx_mx_chain_detail_t chains[RX_ANT_MAX];
} mx_if_entry_t;

#define MX_MAX_IF_ENTRIES (MAX_TX_IDS * MAX_IFS)

static inline uint16_t clamp_u16(uint32_t v) { return (uint16_t)(v > 0xFFFFu ? 0xFFFFu : v); }
static inline uint32_t clamp_u32(uint64_t v) { return (uint32_t)(v > 0xFFFFFFFFu ? 0xFFFFFFFFu : v); }

static inline uint16_t clamp_permille(int value)
{
    if (value < 0) return 0;
    if (value > 1000) return 1000;
    return (uint16_t)value;
}

static inline int16_t to_q8(double value)
{
    long temp = lrint(value * 256.0);
    if (temp < INT16_MIN) temp = INT16_MIN;
    if (temp > INT16_MAX) temp = INT16_MAX;
    return (int16_t)temp;
}

static inline int32_t to_q4(double value)
{
    long temp = lrint(value * 16.0);
    if (temp < INT32_MIN) temp = INT32_MIN;
    if (temp > INT32_MAX) temp = INT32_MAX;
    return (int32_t)temp;
}

static inline int32_t to_q4_from_i64(int64_t value)
{
    long long temp = value * 16ll;
    if (temp < INT32_MIN) temp = INT32_MIN;
    if (temp > INT32_MAX) temp = INT32_MAX;
    return (int32_t)temp;
}

static int append_section(uint8_t* dst, size_t* offset, size_t cap, uint16_t type, const uint8_t* data, uint16_t length)
{
    if (!dst || !offset) return -1;
    if (*offset + 4u + length > cap) return -1;
    dst[*offset + 0] = (uint8_t)(type >> 8);
    dst[*offset + 1] = (uint8_t)(type & 0xFF);
    dst[*offset + 2] = (uint8_t)(length >> 8);
    dst[*offset + 3] = (uint8_t)(length & 0xFF);
    if (length > 0 && data) memcpy(dst + *offset + 4, data, length);
    *offset += 4u + length;
    return 0;
}

/* ---- Global dedup per TX (12-bit seq) and stats containers ---- */
struct seq_window {
  uint16_t base;      /* first seq covered by bit0 */
  uint64_t bits[2];   /* 128 bits window */
};
static void seqwin_init(struct seq_window* w){ w->base = 0; w->bits[0]=w->bits[1]=0; }
static inline uint16_t mod_fwd(uint16_t a, uint16_t b){ return (uint16_t)((b - a) & 0x0FFF); }
/* test/set; returns 1 if already seen, 0 if newly set */
static int seqwin_check_set(struct seq_window* w, uint16_t s)
{
  uint16_t d = mod_fwd(w->base, s);
  if (d < 4096) {
    if (d >= 128) {
      uint16_t shift = (uint16_t)(d - 127);
      if (shift >= 128) { w->bits[0]=w->bits[1]=0; w->base = (uint16_t)((w->base + shift) & 0x0FFF); }
      else {
        uint64_t new0, new1;
        if (shift >= 64) { new0 = w->bits[1] >> (shift - 64); new1 = 0; }
        else { new0 = (w->bits[0] >> shift) | (w->bits[1] << (64 - shift)); new1 = (w->bits[1] >> shift); }
        w->bits[0]=new0; w->bits[1]=new1;
        w->base = (uint16_t)((w->base + shift) & 0x0FFF);
      }
      d = 127;
    }
    uint64_t* word = (d < 64) ? &w->bits[0] : &w->bits[1];
    int bit = (d < 64) ? d : (d - 64);
    uint64_t mask = (uint64_t)1 << bit;
    int already = ((*word) & mask) ? 1 : 0;
    *word |= mask;
    return already;
  }
  return 0;
}

#define MAX_TX_IDS 256
#define MAX_RADIO_PORTS 256
struct tx_stats {
  uint64_t pkts;            /* unique pkts (dedup across ifaces) */
  int rssi_min;             /* best-chain RSSI */
  int rssi_max;
  int64_t rssi_sum;
  uint32_t rssi_samples;
  /* Epoch estimator per TX */
  int have_epoch;
  uint64_t epoch_hat_us;    /* smoothed */
};

struct if_stats {
  uint64_t pkts;            /* pkts seen on this iface (no dedup across ifaces) */
  int rssi_min;             /* best-chain RSSI */
  int rssi_max;
  int64_t rssi_sum;
  uint32_t rssi_samples;
};

/* Per-chain accumulators per (TX,IF) */
struct ant_port_detail {
  uint32_t packets;
  int have_seq;
  uint16_t expect_seq;
  uint32_t lost;
};

struct ant_stats {
  uint8_t ant_id;          /* radiotap ANTENNA (last seen) */
  int rssi_min;
  int rssi_max;
  int64_t rssi_sum;
  uint32_t rssi_samples;
  int have_seq;
  uint16_t expect_seq;
  uint32_t lost;
  struct ant_port_detail ports[MAX_RADIO_PORTS];
};

/* Epoch stats container */
struct epoch_stats {
  uint64_t epoch_sum;      /* instant epoch (us) sum */
  uint64_t epoch_min;
  uint64_t epoch_max;
  uint64_t epoch_samples;
  int64_t  real_delta_sum; /* t_loc - A_us - t_send (us) */
  int64_t  real_delta_min;
  int64_t  real_delta_max;
  uint64_t real_delta_samples;
  int64_t  e_delta_sum;    /* delta_cfg - real_delta */
  int64_t  e_delta_min;
  int64_t  e_delta_max;
  uint64_t e_delta_samples;
  int64_t  e_epoch_sum;    /* epoch_instant - epoch_tx */
  int64_t  e_epoch_min;
  int64_t  e_epoch_max;
  uint64_t e_epoch_samples;
};

struct port_detail {
  uint64_t unique_pkts;
  uint64_t bytes;
  int      have_seq;
  uint16_t expect_seq;
  uint32_t lost;
};

/* Per-interface detail within a TX */
struct if_detail {
  uint64_t pkts;
  /* interface-level loss tracking */
  int have_seq;
  uint16_t expect_seq;
  uint32_t lost;
  /* per-chain */
  struct port_detail ports[MAX_RADIO_PORTS];
  struct ant_stats ant[RX_ANT_MAX];
  /* per-interface epoch metrics for this TX */
  struct epoch_stats es;
};

/* Per-TX aggregate across interfaces */
struct tx_detail {
  uint64_t unique_pkts;       /* dedup across ifaces */
  uint64_t bytes;             /* deduped payload bytes (per period) */
  struct if_detail ifs[MAX_IFS];
  struct epoch_stats es_overall; /* earliest-arrival based */
  struct port_detail ports[MAX_RADIO_PORTS];
  /* Modernized epoch tracking per TX: keep current epoch key and minimal T_epoch_instant_pkt */
  int      have_cur_epoch;
  uint64_t cur_epoch_tx_us;      /* epoch_tx_us key from trailer */
  uint64_t cur_epoch_instant_us; /* minimal T_epoch_instant_pkt observed for this (tx,epoch) */
};

static struct tx_stats TX[MAX_TX_IDS];
static struct if_stats IFST[MAX_IFS];
static struct tx_detail TXD[MAX_TX_IDS];
static struct seq_window SWG[MAX_TX_IDS][MAX_RADIO_PORTS];
/* Control epoch send counter (per reporting period) */
static uint64_t g_ctrl_epoch_send_period = 0;

static void stats_reset_period(int n_if)
{
  for (int t=0;t<MAX_TX_IDS;++t) {
    TX[t].pkts = 0;
    TX[t].rssi_min = 127;
    TX[t].rssi_max = -127;
    TX[t].rssi_sum = 0;
    TX[t].rssi_samples = 0;
    /* keep epoch state across periods */
    TXD[t].unique_pkts = 0;
    TXD[t].bytes = 0;
    /* zero per-TX epoch aggregates */
    memset(&TXD[t].es_overall, 0, sizeof(TXD[t].es_overall));
    for (int p = 0; p < MAX_RADIO_PORTS; ++p) {
      struct port_detail* P = &TXD[t].ports[p];
      memset(P, 0, sizeof(*P));
    }
    for (int i=0;i<n_if;i++) {
      struct if_detail* D = &TXD[t].ifs[i];
      D->pkts = 0; D->have_seq = 0; D->expect_seq = 0; D->lost = 0;
      memset(D->ports, 0, sizeof(D->ports));
      memset(&D->es, 0, sizeof(D->es));
      for (int c=0;c<RX_ANT_MAX;c++) {
        D->ant[c].ant_id = 0xff;
        D->ant[c].rssi_min = 127;
        D->ant[c].rssi_max = -127;
        D->ant[c].rssi_sum = 0;
        D->ant[c].rssi_samples = 0;
        D->ant[c].have_seq = 0;
        D->ant[c].expect_seq = 0;
        D->ant[c].lost = 0;
        memset(D->ant[c].ports, 0, sizeof(D->ant[c].ports));
      }
    }
  }
  for (int i=0;i<n_if;++i) {
    IFST[i].pkts = 0;
    IFST[i].rssi_min = 127;
    IFST[i].rssi_max = -127;
    IFST[i].rssi_sum = 0;
    IFST[i].rssi_samples = 0;
  }
}

/* Radiotap RX parse with MCS */
struct rt_stats {
  uint16_t rt_len;
  uint8_t  flags;                 /* RADIOTAP_F_* */
  uint8_t  antenna[RX_ANT_MAX];
  int8_t   rssi[RX_ANT_MAX];
  int8_t   noise[RX_ANT_MAX];
  int      chains;

  /* Optional TSFT (us) */
  uint64_t tsft_us;
  int      has_tsft;

  /* RX MCS (802.11n HT) */
  int      has_mcs;               /* presence of IEEE80211_RADIOTAP_MCS */
  uint8_t  mcs_known;             /* HAVE_* bits */
  uint8_t  mcs_flags;             /* BW/SGI/LDPC/STBC */
  uint8_t  mcs_index;             /* 0..31 (we support up to 4SS by scaling) */
};

static int parse_radiotap_rx(const uint8_t* p, size_t caplen, struct rt_stats* rs)
{
  if (caplen < sizeof(struct wfb_radiotap_hdr_min)) return -1;
  const struct wfb_radiotap_hdr_min* rh = (const struct wfb_radiotap_hdr_min*)p;
  uint16_t it_len = rh->it_len;
  if (it_len > caplen || it_len < sizeof(struct wfb_radiotap_hdr_min)) return -1;

  memset(rs, 0, sizeof(*rs));
  rs->rt_len = it_len;
  for (int i=0;i<RX_ANT_MAX;i++){ rs->antenna[i]=0xff; rs->rssi[i]=SCHAR_MIN; rs->noise[i]=SCHAR_MAX; }

  uint32_t presents[8]; int np=0;
  size_t poff = offsetof(struct wfb_radiotap_hdr_min, it_present);
  do {
    if (poff + 4 > it_len) break;
    uint32_t v;
    memcpy(&v, p + poff, 4);
    presents[np++] = v;
    poff += 4;
  } while (np < 8 && (presents[np-1] & 0x80000000u));

  size_t off = poff;
  int ant_idx = 0;

  for (int wi=0; wi<np; ++wi) {
    uint32_t pres = presents[wi];
    for (uint8_t f=0; f<32; ++f) {
      if (!(pres & (1u<<f))) continue;
      off = wfb_rt_align(f, off);
      size_t sz = wfb_rt_size(f);
      if (sz==0 || off + sz > it_len) { off += sz; continue; }
      const uint8_t* field = p + off;

      switch (f) {
        case IEEE80211_RADIOTAP_FLAGS:        rs->flags = *field; break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:if (ant_idx < RX_ANT_MAX) {rs->rssi[ant_idx] = (int8_t)*field;} break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE: if (ant_idx < RX_ANT_MAX) {rs->noise[ant_idx] = (int8_t)*field;} break;
        case IEEE80211_RADIOTAP_ANTENNA:      if (ant_idx < RX_ANT_MAX) { rs->antenna[ant_idx] = *field; ant_idx++; } break;
        case IEEE80211_RADIOTAP_TSFT:
          if (sz == 8) { uint64_t v; memcpy(&v, field, 8); rs->tsft_us = le64toh(v); rs->has_tsft = 1; }
          break;
        case IEEE80211_RADIOTAP_MCS:
          if (sz == 3) {
            rs->has_mcs = 1;
            rs->mcs_known = field[0];
            rs->mcs_flags = field[1];
            rs->mcs_index = field[2];
          }
          break;
        default: break;
      }
      off += sz;
    }
  }
  rs->chains = ant_idx;
  return 0;
}

/* 802.11 header view */
struct wfb_pkt_view {
  const struct wfb_dot11_hdr* h;
  const uint8_t* payload;
  size_t payload_len;
  uint16_t seq12;
};

static int extract_dot11(const uint8_t* pkt, size_t caplen, const struct rt_stats* rs, struct wfb_pkt_view* out)
{
  if (rs->rt_len >= caplen) return -1;
  const uint8_t* dot11 = pkt + rs->rt_len;
  size_t dlen = caplen - rs->rt_len;
  if (dlen < sizeof(struct wfb_dot11_hdr)) return -1;

  const struct wfb_dot11_hdr* h = (const struct wfb_dot11_hdr*)dot11;
  uint16_t fc = le16toh(h->frame_control);
  uint8_t type = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;
  if (type != 2) return -1; /* only Data */

  size_t hdr_len = sizeof(struct wfb_dot11_hdr);
  int qos = (subtype & 0x08) ? 1 : 0;
  if (qos) { if (dlen < hdr_len + 2) return -1; hdr_len += 2; }
  int order = (fc & 0x8000) ? 1 : 0;
  if (order) { if (dlen < hdr_len + 4) return -1; hdr_len += 4; }

  if (rs->flags & RADIOTAP_F_DATAPAD) {
    size_t aligned = (hdr_len + 3u) & ~3u;
    if (aligned > dlen) return -1;
    hdr_len = aligned;
  }

  const uint8_t* payload = dot11 + hdr_len;
  size_t payload_len = dlen - hdr_len;
  if ((rs->flags & RADIOTAP_F_FCS) && payload_len >= 4) payload_len -= 4;
  if (payload_len == 0) return -1;

  out->h = h;
  out->payload = payload;
  out->payload_len = payload_len;
  out->seq12 = (le16toh(h->seq_ctrl) >> 4) & 0x0FFF;
  return 0;
}

/* ---- RX airtime (A_us) computation for HT (802.11n) ---- */

/* Base rates (Mbps) for NSS=1, MCS0..7
 * Indexed by [bw40?1:0][sgi?1:0][mcs_mod (0..7)]
 * Values per IEEE 802.11n HT Mixed Mode tables.
 */
static const double ht_mbps[2][2][8] = {
  /* 20 MHz */
  { /* LGI */ {6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0},
    /* SGI */ {7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65.0, 72.2} },
  /* 40 MHz */
  { /* LGI */ {13.5, 27.0, 40.5, 54.0, 81.0, 108.0, 121.5, 135.0},
    /* SGI */ {15.0, 30.0, 45.0, 60.0, 90.0, 120.0, 135.0, 150.0} }
};

/* Compute airtime (microseconds) for one MPDU using HT MCS radiotap.
 * Approximation assumptions:
 *  - HT Mixed Mode preamble 36us for 1SS, +4us per extra SS (additional HT-LTF)
 *  - Tail+SERVICE overhead ~22 bits (single encoder)
 *  - No aggregation, no RTS/CTS, FCS not included in payload_len
 */
static uint32_t airtime_us_rx_ht(size_t mpdu_len, const struct rt_stats* rs)
{
  if (!rs || !rs->has_mcs) return 0;
  const int bw40 = (rs->mcs_flags & WFB_MCS_FLAGS_BW40) ? 1 : 0;
  const int sgi  = (rs->mcs_flags & WFB_MCS_FLAGS_SGI)  ? 1 : 0;
  uint8_t mcs = rs->mcs_index;
  if (mcs > 31) return 0; /* support up to 4SS */

  int nss = (mcs / 8) + 1; if (nss < 1) nss = 1; if (nss > 4) nss = 4;
  int mod = mcs % 8; /* 0..7 */

  double base_rate = ht_mbps[bw40][sgi][mod];
  double rate_mbps = base_rate * nss; /* scales linearly with spatial streams in HT */
  if (rate_mbps <= 0.0) return 0;

  /* Bits to send: payload + SERVICE(16) + TAIL(6) */
  double bits = 8.0 * (double)mpdu_len + 22.0;
  double t_data_us = bits / rate_mbps; /* since 1 Mbps = 1 bit/us */

  /* Round up to full OFDM symbols (3.6us SGI, 4us LGI) */
  const double t_sym = sgi ? 3.6 : 4.0;
  uint64_t nsym = (uint64_t)((t_data_us + t_sym - 1e-9) / t_sym); /* ceil */
  if (nsym * t_sym < t_data_us) nsym += 1;
  double t_data_rounded = (double)nsym * t_sym;

  /* HT Mixed preamble: 36us + 4us per extra SS */
  double t_preamble_us = 36.0 + 4.0 * (double)(nss - 1);

  double total = t_preamble_us + t_data_rounded;
  if (total < 0.0) total = 0.0;
  if (total > (double)UINT32_MAX) total = (double)UINT32_MAX;
  return (uint32_t)(total + 0.5); /* round to nearest us */
}

/* Wrapper: compute RX airtime in microseconds from radiotap. Currently HT only. */
static inline uint32_t airtime_us_rx(size_t mpdu_len, const struct rt_stats* rs)
{
  return airtime_us_rx_ht(mpdu_len, rs);
}

/* ---- Simple main loop (packet drain + debug print of A_us) ---- */

enum { TXF_ANY = 0, TXF_INCLUDE = 1, TXF_EXCLUDE = 2 };
struct txid_filter { int mode; uint64_t map[4]; };
static void txf_clear_all(struct txid_filter* f){ f->map[0]=f->map[1]=f->map[2]=f->map[3]=0; }
static void txf_set(struct txid_filter* f, unsigned v) { if (v<=255) f->map[v>>6] |= (uint64_t)1ull << (v & 63); }
static int txf_test(const struct txid_filter* f, unsigned v) { if (v>255) return 0; return (int)((f->map[v>>6] >> (v & 63)) & 1ull); }
static int parse_uint_u8(const char* s, unsigned* out){ char* e=NULL; long v=strtol(s,&e,0); if (!s||s==e||v<0||v>255) return -1; *out=(unsigned)v; return 0; }
/* Parse spec: "any" | "-1" | list | "!list", where list = "n[,m][,a-b]..." */
static int txf_parse(struct txid_filter* f, const char* spec)
{
  txf_clear_all(f);
  if (!spec || !*spec) { f->mode = TXF_INCLUDE; txf_set(f, 0); return 0; }
  while (isspace((unsigned char)*spec)) ++spec;
  if (strcmp(spec, "any")==0 || strcmp(spec, "-1")==0) { f->mode = TXF_ANY; return 0; }
  int excl = 0; if (spec[0]=='!'){ excl=1; ++spec; }
  f->mode = excl ? TXF_EXCLUDE : TXF_INCLUDE;
  char buf[256]; strncpy(buf, spec, sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  char* save=NULL; char* tok=strtok_r(buf, ",", &save);
  while (tok) {
    while (isspace((unsigned char)*tok)) ++tok;
    char* dash = strchr(tok, '-');
    if (dash) {
      *dash=0; unsigned a,b; if (parse_uint_u8(tok,&a)==0 && parse_uint_u8(dash+1,&b)==0) {
        if (a<=b) { for (unsigned v=a; v<=b; ++v) txf_set(f,v); }
        else      { for (unsigned v=b; v<=a; ++v) txf_set(f,v); }
      }
    } else { unsigned v; if (parse_uint_u8(tok,&v)==0) txf_set(f,v); }
    tok = strtok_r(NULL, ",", &save);
  }
  return 0;
}
static int txf_match(const struct txid_filter* f, uint8_t tx)
{
  if (f->mode == TXF_ANY) return 1;
  int present = txf_test(f, tx);
  return (f->mode == TXF_INCLUDE) ? present : !present;
}

static volatile int g_run = 1; static void on_sigint(int){ g_run = 0; }

struct cli_cfg {
  int n_if; const char* ifname[MAX_IFS];
  const char* ip; int port; struct txid_filter txf; const char* tx_filter_spec; int group_id; int stat_period_ms;
  /* Mesh time sync params */
  int    tau_us;   /* propagation (us) */
  int    delta_us; /* stack latency (us) */
  /* Control channel */
  const char* ctrl_addr;    /* abstract UDS address (e.g. @wfbx.mx) */
  uint32_t epoch_len_us;    /* publish superframe length */
  uint32_t epoch_gi_us;     /* publish inter-superframe guard */
  double  d_max_km;         /* max distance (km) ⇒ tau_us */
  int debug_stats;          /* enable extended epoch diagnostics */
  const char* stat_ip;      /* stats server IP */
  int stat_port;            /* stats server port */
  const char* stat_id;      /* stats module id override */
};

static void print_help(const char* prog)
{
  printf("Usage: sudo %s [options] <wlan_iface1> [<wlan_iface2> ...>\n"
         "Options:\n"
         "  --ip <addr>         UDP destination IP (default: %s)\n"
         "  --port <num>        UDP destination port (default: %d)\n"
         "  --stat_ip <addr>    Stats server IP (default: 127.0.0.1)\n"
         "  --stat_port <num>   Stats server port (default: 9601)\n"
         "  --stat_id <name>    Stats module identifier (default: mx)\n"
         "  --tx_id <list>      Filter by TX IDs: 'any' | '1,2,10-12' | '!3,7' (default: any)\n"
         "  --group_id <id>     Filter by Group ID (addr1[5]); -1 disables (default: any)\n"
         "  --delta_us <num>    Stack latency in us (default: 700)\n"
         "  --ctrl <@name>      Control UDS abstract address (default: @wfbx.mx)\n"
         "  --d_max <km>        Max distance in km (sets tau_us = round(d_max*3.335641))\n"
         "  --stat_period <ms>  Stats period in milliseconds (default: %d)\n"
         "  --debug <on|off>    Enable extended epoch diagnostics (default: off)\n"
         "  --help              Show this help and exit\n",
         prog, g_dest_ip_default, g_dest_port_default, 1000);
}

static int parse_cli(int argc, char** argv, struct cli_cfg* cfg)
{
  cfg->ip = g_dest_ip_default; cfg->port = g_dest_port_default; cfg->n_if = 0; cfg->stat_period_ms = 1000; cfg->txf.mode = TXF_ANY; cfg->tx_filter_spec = "any"; cfg->group_id = -1;
  cfg->stat_ip = "127.0.0.1"; cfg->stat_port = 9601; cfg->stat_id = NULL;
  cfg->tau_us = 0; cfg->delta_us = 700; cfg->ctrl_addr = "@wfbx.mx"; cfg->epoch_len_us = 0; cfg->epoch_gi_us = 0; cfg->d_max_km = 0.0;
  cfg->debug_stats = 0;
  static struct option longopts[] = {
    {"ip",           required_argument, 0, 0},
    {"port",         required_argument, 0, 0},
    {"tx_id",        required_argument, 0, 0},
    {"group_id",     required_argument, 0, 0},
    {"stat_ip",     required_argument, 0, 0},
    {"stat_port",   required_argument, 0, 0},
    {"stat_id",     required_argument, 0, 0},
    {"delta_us",     required_argument, 0, 0},
    {"ctrl",         required_argument, 0, 0},
    {"d_max",        required_argument, 0, 0},
    {"stat_period",  required_argument, 0, 0},
    {"debug",        required_argument, 0, 0},
    {"help",         no_argument,       0, 0},
    {0,0,0,0}
  };
  int optidx = 0; while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx); if (c==-1) break; if (c==0) {
      const char* name = longopts[optidx].name; const char* val = optarg?optarg:"";
      if      (strcmp(name,"ip")==0)          cfg->ip = val;
      else if (strcmp(name,"port")==0)        cfg->port = atoi(val);
      else if (strcmp(name,"tx_id")==0)       { cfg->tx_filter_spec = val; txf_parse(&cfg->txf, val); }
      else if (strcmp(name,"group_id")==0)    cfg->group_id = atoi(val);
      else if (strcmp(name,"stat_ip")==0)     cfg->stat_ip = val;
      else if (strcmp(name,"stat_port")==0)   cfg->stat_port = atoi(val);
      else if (strcmp(name,"stat_id")==0)     cfg->stat_id = val;
      else if (strcmp(name,"delta_us")==0)    cfg->delta_us = atoi(val);
      else if (strcmp(name,"ctrl")==0)        cfg->ctrl_addr = val;
      else if (strcmp(name,"d_max")==0)       cfg->d_max_km = atof(val);
      else if (strcmp(name,"stat_period")==0) cfg->stat_period_ms = atoi(val);
      else if (strcmp(name,"debug")==0) {
        if (strcasecmp(val, "on") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0)
          cfg->debug_stats = 1;
        else if (strcasecmp(val, "off") == 0 || strcmp(val, "0") == 0 || strcasecmp(val, "false") == 0)
          cfg->debug_stats = 0;
        else
          fprintf(stderr, "Unknown --debug value '%s' (use on/off)\n", val);
      }
      else if (strcmp(name,"help")==0) { print_help(argv[0]); exit(0); }
    }
  }
  /* If d_max provided, derive tau_us = round(d_max_km * 3.335641 us/km) */
  if (cfg->d_max_km > 0.0) {
    double tau = cfg->d_max_km * 3.335641;
    if (tau < 0.0) tau = 0.0;
    if (tau > (double)INT_MAX) tau = (double)INT_MAX;
    cfg->tau_us = (int)(tau + 0.5);
  }
  if (optind >= argc) { fprintf(stderr, "Error: missing <wlan_iface>. Use --help for usage.\n"); return -1; }
  for (int i=optind; i<argc && cfg->n_if < MAX_IFS; ++i) cfg->ifname[cfg->n_if++] = argv[i];
  if (cfg->n_if == 0) { fprintf(stderr, "Error: no interfaces.\n"); return -1; }
  if (cfg->stat_period_ms <= 0) cfg->stat_period_ms = 1000;
  return 0;
}

int main(int argc, char** argv)
{
  struct cli_cfg cli; if (parse_cli(argc, argv, &cli) != 0) return 1; signal(SIGINT, on_sigint);

  /* UDP out socket (optional forward) */
  int us = socket(AF_INET, SOCK_DGRAM, 0); if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in dst; memset(&dst, 0, sizeof(dst)); dst.sin_family = AF_INET; dst.sin_port = htons(cli.port);
  if (!inet_aton(cli.ip, &dst.sin_addr)) { fprintf(stderr, "inet_aton failed for %s\n", cli.ip); return 1; }

  int stat_sock = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in stat_addr; memset(&stat_addr, 0, sizeof(stat_addr)); stat_addr.sin_family = AF_INET; stat_addr.sin_port = htons(cli.stat_port);
  if (stat_sock >= 0) {
    if (!inet_aton(cli.stat_ip, &stat_addr.sin_addr)) {
      fprintf(stderr, "inet_aton failed for stats server %s\n", cli.stat_ip);
      close(stat_sock);
      stat_sock = -1;
    } else {
      fprintf(stderr, "[STATS] MX stats socket created -> %s:%d (fd=%d)\n",
              cli.stat_ip, cli.stat_port, stat_sock);
    }
  } else {
    perror("stats socket");
  }

  /* Open PCAP for each interface */
  pcap_t* ph[MAX_IFS] = {0}; int fds[MAX_IFS]; for (int i=0;i<MAX_IFS;i++) fds[i] = -1; int n_open = 0; char err[PCAP_ERRBUF_SIZE]={0};
  for (int i=0;i<cli.n_if; ++i) {
    pcap_t* p = pcap_create(cli.ifname[i], err); if (!p) { fprintf(stderr, "pcap_create(%s): %s\n", cli.ifname[i], err); continue; }
    (void)pcap_set_immediate_mode(p, 1); if (pcap_activate(p) != 0) { fprintf(stderr, "pcap_activate(%s): %s\n", cli.ifname[i], pcap_geterr(p)); pcap_close(p); continue; }
    (void)pcap_setnonblock(p, 1, err); int fd = pcap_get_selectable_fd(p); if (fd < 0) { fprintf(stderr, "pcap_get_selectable_fd(%s) failed; skipped\n", cli.ifname[i]); pcap_close(p); continue; }
    ph[n_open]=p; fds[n_open]=fd; n_open++;
  }
  if (n_open == 0) { fprintf(stderr, "No usable interfaces opened.\n"); return 1; }

  fprintf(stderr, "MX RX on: "); for (int i=0;i<n_open;i++) fprintf(stderr, "%s%s", cli.ifname[i], (i+1<n_open?", ":""));
  const char* group_txt = "any";
  char group_buf[8];
  if (cli.group_id >= 0 && cli.group_id <= 255) {
    snprintf(group_buf, sizeof(group_buf), "%d", cli.group_id);
    group_txt = group_buf;
  }
  fprintf(stderr, " | UDP %s:%d | stat %d ms | group=%s | delta_us=%d tau_us=%d | ctrl=%s | stats -> %s:%d\n",
          cli.ip, cli.port, cli.stat_period_ms, group_txt, cli.delta_us, cli.tau_us,
          cli.ctrl_addr, cli.stat_ip, cli.stat_port);
  fprintf(stderr, "Debug epoch stats: %s\n", cli.debug_stats ? "on" : "off");
  if (cli.stat_id && *cli.stat_id) {
    snprintf(g_mx_stats_module_id, sizeof(g_mx_stats_module_id), "%.*s", (int)(sizeof(g_mx_stats_module_id)-1), cli.stat_id);
  } else {
    snprintf(g_mx_stats_module_id, sizeof(g_mx_stats_module_id), "mx");
  }


  uint64_t t0 = now_ms();
  uint64_t pkts = 0;
  uint64_t bytes_forwarded = 0;
  /* Init dedup windows per TX and reset per-period stats */
  for (int t=0;t<MAX_TX_IDS;++t) {
    for (int p=0;p<MAX_RADIO_PORTS;++p) {
      seqwin_init(&SWG[t][p]);
    }
  }
  stats_reset_period(n_open);
  /* Real delta_us statistics */
  int64_t real_delta_sum = 0;
  int64_t real_delta_min = INT64_C(0);
  int64_t real_delta_max = INT64_C(0);
  uint64_t real_delta_samples = 0;
  /* Deprecated e_us removed */
  /* e_delta = delta_us - real_delta_us statistics */
  int64_t e_delta_sum = 0;
  int64_t e_delta_min = INT64_C(0);
  int64_t e_delta_max = INT64_C(0);
  uint64_t e_delta_samples = 0;
  /* Epoch vs TX-epoch detailed stats removed; use global e_epoch only */

  /* Control socket setup (abstract UDS) */
  int cs = -1; struct sockaddr_un mx_sa; socklen_t mx_sl = 0;
  if (cli.ctrl_addr && *cli.ctrl_addr) {
    memset(&mx_sa, 0, sizeof(mx_sa)); mx_sa.sun_family = AF_UNIX; mx_sa.sun_path[0] = '\0';
    const char* nm = cli.ctrl_addr; if (nm[0] == '@') nm++;
    size_t maxpath = sizeof(mx_sa.sun_path) - 2;
    size_t nmlen = strlen(nm);
    if (nmlen > maxpath) nmlen = maxpath;
    if (nmlen > 0) memcpy(mx_sa.sun_path+1, nm, nmlen);
    mx_sl = (socklen_t)offsetof(struct sockaddr_un, sun_path) + 1 + (socklen_t)nmlen;
    cs = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (cs >= 0) {
      if (bind(cs, (struct sockaddr*)&mx_sa, mx_sl) != 0) { perror("ctrl bind"); close(cs); cs = -1; }
      else { int fl = fcntl(cs, F_GETFL, 0); if (fl>=0) fcntl(cs, F_SETFL, fl|O_NONBLOCK); }
    }
  }
  struct { struct sockaddr_un sa; socklen_t sl; char name[108]; int active; } subs[64];
  for (int i=0;i<64;i++){ memset(&subs[i],0,sizeof(subs[i])); subs[i].sa.sun_family=AF_UNIX; }
  uint32_t epoch_seq = 0;

  int fatal_iface_error = 0;
  while (g_run && !fatal_iface_error) {
    fd_set rfds; FD_ZERO(&rfds); int maxfd=-1; for (int i=0;i<n_open;i++){ FD_SET(fds[i], &rfds); if (fds[i]>maxfd) maxfd=fds[i]; }
    if (cs >= 0) { FD_SET(cs, &rfds); if (cs > maxfd) maxfd = cs; }
    struct timeval tv; uint64_t now = now_ms(); uint64_t ms_left = (t0 + (uint64_t)cli.stat_period_ms > now) ? (t0 + (uint64_t)cli.stat_period_ms - now) : 0;
    tv.tv_sec = (time_t)(ms_left/1000ull); tv.tv_usec = (suseconds_t)((ms_left%1000ull)*1000ull);
    int sel = select(maxfd+1, &rfds, NULL, NULL, &tv);
    if (sel < 0) { if (errno == EINTR) goto stats_tick; perror("select"); break; }

    /* Control drain (SUB) */
    if (cs >= 0 && sel > 0 && FD_ISSET(cs, &rfds)) {
      uint8_t bufc[256]; struct sockaddr_un from; socklen_t fl = sizeof(from);
      ssize_t n = recvfrom(cs, bufc, sizeof(bufc), 0, (struct sockaddr*)&from, &fl);
      if (n >= (ssize_t)sizeof(struct wfbx_ctrl_hdr)) {
        const struct wfbx_ctrl_hdr* h = (const struct wfbx_ctrl_hdr*)bufc;
        if (h->magic == WFBX_CTRL_MAGIC && h->ver == WFBX_CTRL_VER && h->type == WFBX_CTRL_SUB && (size_t)n >= sizeof(struct wfbx_ctrl_sub)) {
          const struct wfbx_ctrl_sub* s = (const struct wfbx_ctrl_sub*)bufc;
          struct sockaddr_un sa; socklen_t sl; memset(&sa,0,sizeof(sa)); sa.sun_family=AF_UNIX; sa.sun_path[0]='\0';
          const char* nm2 = s->name; if (!nm2) nm2 = ""; if (nm2[0]=='@') nm2++;
          size_t maxpath2 = sizeof(sa.sun_path) - 2; size_t plen = strlen(nm2);
          if (plen > maxpath2) plen = maxpath2;
          if (plen > 0) memcpy(sa.sun_path+1, nm2, plen);
          sl = (socklen_t)offsetof(struct sockaddr_un, sun_path) + 1 + (socklen_t)plen;
          int placed = 0; for (int k=0;k<64;k++) if (subs[k].active && strcmp(subs[k].name, nm2?nm2:"")==0) { subs[k].sa=sa; subs[k].sl=sl; placed=1; break; }
          if (!placed) for (int k=0;k<64;k++) if (!subs[k].active) {
            subs[k].active=1; subs[k].sa=sa; subs[k].sl=sl;
            /* Cap copied name to buffer size to avoid truncation warnings */
            snprintf(subs[k].name, sizeof(subs[k].name), "%.*s",
                     (int)(sizeof(subs[k].name)-1), nm2?nm2:"");
            break;
          }
        }
      }
    }

    for (int i=0;i<n_open && g_run;i++) {
      if (fds[i] < 0) continue;
      if (sel == 0 || !FD_ISSET(fds[i], &rfds)) continue;
      while (g_run) {
        struct pcap_pkthdr* hdr = NULL;
        const u_char* pkt = NULL;
        int rc = pcap_next_ex(ph[i], &hdr, &pkt);
        if (rc == 0) break;
        if (rc == PCAP_ERROR || rc == PCAP_ERROR_BREAK || rc == -2) {
          const char* perr = pcap_geterr(ph[i]);
          fprintf(stderr, "[FATAL] pcap_next_ex(%s) failed (rc=%d): %s\n",
                  cli.ifname[i], rc, perr ? perr : "unknown error");
          fatal_iface_error = 1;
          g_run = 0;
          break;
        }
        struct rt_stats rs;
        if (parse_radiotap_rx(pkt, hdr->caplen, &rs) != 0) continue;
        struct wfb_pkt_view v;
        if (extract_dot11(pkt, hdr->caplen, &rs, &v) != 0) continue;
        /* TX-ID filter: use addr2[5] */
        uint8_t tx_id = v.h ? v.h->addr2[5] : 0;
        uint8_t group_id = v.h ? v.h->addr1[5] : 0;
        uint8_t radio_port = v.h ? v.h->addr3[5] : 0;
        if (!txf_match(&cli.txf, tx_id)) continue;
        if (cli.group_id >= 0 && group_id != (uint8_t)cli.group_id) continue;

        /* Timestamps from driver-provided trailer: epoch_tx, ts_tx, ts_rx */
        uint32_t TS_tx_us = 0; int have_ts_tx = 0;
        uint64_t epoch_tx_us = 0; int have_epoch_tx = 0;
        uint64_t t_send_tx_us = 0;
        uint64_t t_recv_rx_us = 0;
        size_t trailer_found = 0;
        if (v.payload_len >= WFBX_TRAILER_BYTES) {
          uint64_t e_le, tx_le, rx_le;
          memcpy(&e_le,  v.payload + (v.payload_len - WFBX_TRAILER_BYTES), 8);
          memcpy(&tx_le, v.payload + (v.payload_len - WFBX_TRAILER_BYTES + 8), 8);
          memcpy(&rx_le, v.payload + (v.payload_len - WFBX_TRAILER_BYTES + 16), 8);
          epoch_tx_us  = le64toh(e_le);  have_epoch_tx = 1;
          t_send_tx_us = le64toh(tx_le);
          t_recv_rx_us = le64toh(rx_le);
          if (t_send_tx_us >= epoch_tx_us) TS_tx_us = (uint32_t)(t_send_tx_us - epoch_tx_us);
          else TS_tx_us = 0;
          have_ts_tx = 1;
          trailer_found = WFBX_TRAILER_BYTES;
        }
        /* Use driver RX timestamp if available, else fall back to local */
        uint64_t t_loc_us = (t_recv_rx_us != 0) ? t_recv_rx_us : mono_us_raw();

        /* Compute airtime from actual PHY (HT) */
        uint32_t A_us = airtime_us_rx(v.payload_len, &rs);

        /* Identify TX/IF */
        struct if_detail* DID = &TXD[tx_id].ifs[i];

        /* Per-interface packet/radio stats + per-chain */
        DID->pkts++;
        DID->have_seq = 1;
        for (int c=0;c<rs.chains && c<RX_ANT_MAX; ++c) {
          if (rs.rssi[c] == SCHAR_MIN) continue;
          struct ant_stats* AS = &DID->ant[c];
          int r = rs.rssi[c];
          if (r < AS->rssi_min) AS->rssi_min = r;
          if (r > AS->rssi_max) AS->rssi_max = r;
          AS->rssi_sum += r; AS->rssi_samples++;
          AS->ant_id = rs.antenna[c];
        }
        DID->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);

        /* Epoch metrics for this (TX,IF) */
        if (have_ts_tx) {
          int64_t inst = (int64_t)t_loc_us - (int64_t)cli.delta_us - (int64_t)A_us - (int64_t)cli.tau_us - (int64_t)TS_tx_us;
          uint64_t T_epoch_instant_pkt = (inst < 0) ? 0ull : (uint64_t)inst;
          int64_t real_du = (t_send_tx_us != 0) ? ((int64_t)t_loc_us - (int64_t)A_us - (int64_t)t_send_tx_us) : 0;
          int64_t e_d = (int64_t)cli.delta_us - real_du;
          int64_t e_e = (have_epoch_tx) ? ((int64_t)T_epoch_instant_pkt - (int64_t)epoch_tx_us) : 0;
          struct epoch_stats* ES = &DID->es;
          if (ES->epoch_samples == 0) { ES->epoch_min = T_epoch_instant_pkt; ES->epoch_max = T_epoch_instant_pkt; }
          if (T_epoch_instant_pkt < ES->epoch_min) ES->epoch_min = T_epoch_instant_pkt;
          if (T_epoch_instant_pkt > ES->epoch_max) ES->epoch_max = T_epoch_instant_pkt;
          ES->epoch_sum += T_epoch_instant_pkt; ES->epoch_samples++;
          if (t_send_tx_us != 0) {
            if (ES->real_delta_samples == 0) { ES->real_delta_min = real_du; ES->real_delta_max = real_du; }
            if (real_du < ES->real_delta_min) ES->real_delta_min = real_du;
            if (real_du > ES->real_delta_max) ES->real_delta_max = real_du;
            ES->real_delta_sum += real_du; ES->real_delta_samples++;
            if (ES->e_delta_samples == 0) { ES->e_delta_min = e_d; ES->e_delta_max = e_d; }
            if (e_d < ES->e_delta_min) ES->e_delta_min = e_d;
            if (e_d > ES->e_delta_max) ES->e_delta_max = e_d;
            ES->e_delta_sum += e_d; ES->e_delta_samples++;
          }
          if (have_epoch_tx) {
            if (ES->e_epoch_samples == 0) { ES->e_epoch_min = e_e; ES->e_epoch_max = e_e; }
            if (e_e < ES->e_epoch_min) ES->e_epoch_min = e_e;
            if (e_e > ES->e_epoch_max) ES->e_epoch_max = e_e;
            ES->e_epoch_sum += e_e; ES->e_epoch_samples++;
          }
          /* Modernized per-TX epoch selection (per iface): update minimal T_epoch_instant_pkt per (tx, epoch_tx_us) */
          if (have_epoch_tx) {
            if (!TXD[tx_id].have_cur_epoch || TXD[tx_id].cur_epoch_tx_us != epoch_tx_us) {
              TXD[tx_id].have_cur_epoch = 1;
              TXD[tx_id].cur_epoch_tx_us = epoch_tx_us;
              TXD[tx_id].cur_epoch_instant_us = (uint64_t)T_epoch_instant_pkt;
            } else {
              if ((uint64_t)T_epoch_instant_pkt < TXD[tx_id].cur_epoch_instant_us) {
                TXD[tx_id].cur_epoch_instant_us = (uint64_t)T_epoch_instant_pkt;
              }
            }
          }
          /* Global T_epoch_instant tracker (pre-dedup, across all IFs) */
          if (have_epoch_tx) {
            if (!g_have_epoch_inst) {
              g_have_epoch_inst = 1;
              g_cur_tx_id = tx_id;
              g_cur_epoch_tx_us = epoch_tx_us;
              g_epoch_instant_us = T_epoch_instant_pkt;
              /* Immediate publish: first epoch value established */
              if (cs >= 0) {
                struct wfbx_ctrl_epoch m; memset(&m, 0, sizeof(m));
                m.h.magic = WFBX_CTRL_MAGIC; m.h.ver = WFBX_CTRL_VER; m.h.type = WFBX_CTRL_EPOCH; m.h.seq = ++epoch_seq;
                m.epoch_us = g_epoch_instant_us; m.epoch_len_us = 0; m.epoch_gi_us = 0; m.issued_us = mono_us_raw();
                for (int k=0;k<64;k++) if (subs[k].active) { g_ctrl_epoch_send_period++; (void)sendto(cs, &m, sizeof(m), 0, (struct sockaddr*)&subs[k].sa, subs[k].sl); }
              }
            } else if (g_cur_tx_id == tx_id && g_cur_epoch_tx_us == epoch_tx_us) {
              if (T_epoch_instant_pkt < g_epoch_instant_us) {
                g_epoch_instant_us = T_epoch_instant_pkt;
                /* Immediate publish: refined earlier epoch */
                if (cs >= 0) {
                  struct wfbx_ctrl_epoch m; memset(&m, 0, sizeof(m));
                  m.h.magic = WFBX_CTRL_MAGIC; m.h.ver = WFBX_CTRL_VER; m.h.type = WFBX_CTRL_EPOCH; m.h.seq = ++epoch_seq;
                  m.epoch_us = g_epoch_instant_us; m.epoch_len_us = 0; m.epoch_gi_us = 0; m.issued_us = mono_us_raw();
                  for (int k=0;k<64;k++) if (subs[k].active) { g_ctrl_epoch_send_period++; (void)sendto(cs, &m, sizeof(m), 0, (struct sockaddr*)&subs[k].sa, subs[k].sl); }
                }
              }
            } else {
              /* Switching key: capture e_epoch_last for previous key before updating */
              int64_t last = (int64_t)g_epoch_instant_us - (int64_t)g_cur_epoch_tx_us;
              if (g_e_epoch_last_samples == 0) { g_e_epoch_last_min = last; g_e_epoch_last_max = last; }
              if (last < g_e_epoch_last_min) g_e_epoch_last_min = last;
              if (last > g_e_epoch_last_max) g_e_epoch_last_max = last;
              g_e_epoch_last_sum += last; g_e_epoch_last_samples++;
              /* Now switch current key and seed with this packet */
              g_cur_tx_id = tx_id;
              g_cur_epoch_tx_us = epoch_tx_us;
              g_epoch_instant_us = T_epoch_instant_pkt;
              /* Immediate publish: new epoch key established */
              if (cs >= 0) {
                struct wfbx_ctrl_epoch m; memset(&m, 0, sizeof(m));
                m.h.magic = WFBX_CTRL_MAGIC; m.h.ver = WFBX_CTRL_VER; m.h.type = WFBX_CTRL_EPOCH; m.h.seq = ++epoch_seq;
                m.epoch_us = g_epoch_instant_us; m.epoch_len_us = 0; m.epoch_gi_us = 0; m.issued_us = mono_us_raw();
                for (int k=0;k<64;k++) if (subs[k].active) { g_ctrl_epoch_send_period++; (void)sendto(cs, &m, sizeof(m), 0, (struct sockaddr*)&subs[k].sa, subs[k].sl); }
              }
            }
            /* After tracker update, compute global e_epoch for this packet */
            int64_t eglob = (int64_t)g_epoch_instant_us - (int64_t)epoch_tx_us;
            if (g_e_epoch_samples == 0) { g_e_epoch_min = eglob; g_e_epoch_max = eglob; }
            if (eglob < g_e_epoch_min) g_e_epoch_min = eglob;
            if (eglob > g_e_epoch_max) g_e_epoch_max = eglob;
            g_e_epoch_sum += eglob; g_e_epoch_samples++;
          }
        }

        /* Per-TX global dedup for unique pkt + earliest-arrival epoch accumulation */
        int dup_port = seqwin_check_set(&SWG[tx_id][radio_port], v.seq12);
        size_t unique_len = v.payload_len;
        if (trailer_found > 0 && unique_len >= trailer_found) unique_len -= trailer_found;

        /* Per-interface per-port tracking: allow each iface to account for quality independently */
        struct port_detail* PIF = &DID->ports[radio_port];
        int count_if_pkt = 1;
        if (!PIF->have_seq) {
          PIF->have_seq = 1;
          PIF->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
        } else {
          uint16_t diff = (uint16_t)((v.seq12 - PIF->expect_seq) & 0x0FFF);
          if (diff == 0) {
            PIF->expect_seq = (uint16_t)((PIF->expect_seq + 1) & 0x0FFF);
          } else if (diff & 0x0800) {
            count_if_pkt = 0; /* old/duplicate frame for this iface */
          } else {
            PIF->lost += diff;
            DID->lost += diff;
            PIF->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
          }
        }
        if (count_if_pkt) {
          PIF->unique_pkts++;
          PIF->bytes += unique_len;
        }

        for (int c = 0; c < rs.chains && c < RX_ANT_MAX; ++c) {
          if (rs.rssi[c] == SCHAR_MIN) continue;
          struct ant_stats* AS = &DID->ant[c];
          struct ant_port_detail* AP = &AS->ports[radio_port];
          int count_chain_pkt = 1;
          if (!AP->have_seq) {
            AP->have_seq = 1;
            AP->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
          } else {
            uint16_t diff = (uint16_t)((v.seq12 - AP->expect_seq) & 0x0FFF);
            if (diff == 0) {
              AP->expect_seq = (uint16_t)((AP->expect_seq + 1) & 0x0FFF);
            } else if (diff & 0x0800) {
              count_chain_pkt = 0;
            } else {
              AP->lost += diff;
              AS->lost += diff;
              AP->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            }
          }
          if (count_chain_pkt) {
            AP->packets++;
          }
        }

        if (!dup_port) {
          struct port_detail* PD = &TXD[tx_id].ports[radio_port];
          int count_tx_pkt = 1;
          if (!PD->have_seq) {
            PD->have_seq = 1;
            PD->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
          } else {
            uint16_t diff = (uint16_t)((v.seq12 - PD->expect_seq) & 0x0FFF);
            if (diff == 0) {
              PD->expect_seq = (uint16_t)((PD->expect_seq + 1) & 0x0FFF);
            } else if (diff & 0x0800) {
              count_tx_pkt = 0; /* stale frame outside dedup window */
            } else {
              PD->lost += diff;
              PD->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            }
          }
          if (count_tx_pkt) {
            int pkt_best = -127; int have_pkt_best = 0;
            for (int c=0;c<rs.chains && c<RX_ANT_MAX; ++c) {
              if (rs.rssi[c] == SCHAR_MIN) continue;
              if (!have_pkt_best || rs.rssi[c] > pkt_best) {
                pkt_best = rs.rssi[c];
                have_pkt_best = 1;
              }
            }
            TX[tx_id].pkts++;
            if (have_pkt_best) {
              if (pkt_best < TX[tx_id].rssi_min) TX[tx_id].rssi_min = pkt_best;
              if (pkt_best > TX[tx_id].rssi_max) TX[tx_id].rssi_max = pkt_best;
              TX[tx_id].rssi_sum += pkt_best; TX[tx_id].rssi_samples++;
            }
            PD->unique_pkts++;
            PD->bytes += unique_len;
            TXD[tx_id].unique_pkts++;
            TXD[tx_id].bytes += unique_len;
            if (have_ts_tx) {
              int64_t inst = (int64_t)t_loc_us - (int64_t)cli.delta_us - (int64_t)A_us - (int64_t)cli.tau_us - (int64_t)TS_tx_us;
              uint64_t T_epoch_instant_pkt = (inst < 0) ? 0ull : (uint64_t)inst;
              int64_t real_du = (t_send_tx_us != 0) ? ((int64_t)t_loc_us - (int64_t)A_us - (int64_t)t_send_tx_us) : 0;
              int64_t e_d = (int64_t)cli.delta_us - real_du;
              int64_t e_e = (have_epoch_tx) ? ((int64_t)T_epoch_instant_pkt - (int64_t)epoch_tx_us) : 0;
              struct epoch_stats* ES = &TXD[tx_id].es_overall;
              if (ES->epoch_samples == 0) { ES->epoch_min = T_epoch_instant_pkt; ES->epoch_max = T_epoch_instant_pkt; }
              if (T_epoch_instant_pkt < ES->epoch_min) ES->epoch_min = T_epoch_instant_pkt;
              if (T_epoch_instant_pkt > ES->epoch_max) ES->epoch_max = T_epoch_instant_pkt;
              ES->epoch_sum += T_epoch_instant_pkt; ES->epoch_samples++;
              if (t_send_tx_us != 0) {
                if (ES->real_delta_samples == 0) { ES->real_delta_min = real_du; ES->real_delta_max = real_du; }
                if (real_du < ES->real_delta_min) ES->real_delta_min = real_du;
                if (real_du > ES->real_delta_max) ES->real_delta_max = real_du;
                ES->real_delta_sum += real_du; ES->real_delta_samples++;
                if (ES->e_delta_samples == 0) { ES->e_delta_min = e_d; ES->e_delta_max = e_d; }
                if (e_d < ES->e_delta_min) ES->e_delta_min = e_d;
                if (e_d > ES->e_delta_max) ES->e_delta_max = e_d;
                ES->e_delta_sum += e_d; ES->e_delta_samples++;
              }
              if (have_epoch_tx) {
                if (ES->e_epoch_samples == 0) { ES->e_epoch_min = e_e; ES->e_epoch_max = e_e; }
                if (e_e < ES->e_epoch_min) ES->e_epoch_min = e_e;
                if (e_e > ES->e_epoch_max) ES->e_epoch_max = e_e;
                ES->e_epoch_sum += e_e; ES->e_epoch_samples++;
                /* Also refine per-TX minimal epoch across ifaces for this epoch key */
                if (!TXD[tx_id].have_cur_epoch || TXD[tx_id].cur_epoch_tx_us != epoch_tx_us) {
                  TXD[tx_id].have_cur_epoch = 1;
                  TXD[tx_id].cur_epoch_tx_us = epoch_tx_us;
                  TXD[tx_id].cur_epoch_instant_us = (uint64_t)T_epoch_instant_pkt;
                } else {
                  if ((uint64_t)T_epoch_instant_pkt < TXD[tx_id].cur_epoch_instant_us) {
                    TXD[tx_id].cur_epoch_instant_us = (uint64_t)T_epoch_instant_pkt;
                  }
                }
              }
            }
          }
        }

        /* Real delta_us (host-host), using TX send timestamp */
        if (t_send_tx_us != 0) {
          int64_t real_du = (int64_t)t_loc_us - (int64_t)A_us - (int64_t)t_send_tx_us; /* tau_us≈0 per test */
          if (real_delta_samples == 0) { real_delta_min = real_du; real_delta_max = real_du; }
          if (real_du < real_delta_min) real_delta_min = real_du;
          if (real_du > real_delta_max) real_delta_max = real_du;
          real_delta_sum += real_du;
          real_delta_samples++;
          /* e_delta = configured delta_us - measured real_du */
          int64_t e_d = (int64_t)cli.delta_us - real_du;
          if (e_delta_samples == 0) { e_delta_min = e_d; e_delta_max = e_d; }
          if (e_d < e_delta_min) e_delta_min = e_d;
          if (e_d > e_delta_max) e_delta_max = e_d;
          e_delta_sum += e_d;
          e_delta_samples++;
        }

        /* Epoch comparisons against TX-provided epoch handled above when computing EMA */

        /* Optional: forward payload without trailer (trim what we actually found) */
        size_t fwd_len = v.payload_len;
        if (trailer_found > 0 && fwd_len >= trailer_found) fwd_len -= trailer_found;
        bytes_forwarded += fwd_len;
        (void)sendto(us, v.payload, fwd_len, 0, (struct sockaddr*)&dst, sizeof(dst));
        pkts++;
        if (fatal_iface_error || !g_run) break;
      }
      if (fatal_iface_error || !g_run) break;
    }

stats_tick:
    if (!g_run || fatal_iface_error) break;
    {
      uint64_t t1 = now_ms(); if (t1 - t0 >= (uint64_t)cli.stat_period_ms) {
        double avg_real_du = 0.0;
        double avg_e_delta = 0.0;
        if (cli.debug_stats) {
          if (real_delta_samples > 0) avg_real_du = (double)real_delta_sum / (double)real_delta_samples;
          if (e_delta_samples > 0)    avg_e_delta = (double)e_delta_sum / (double)e_delta_samples;
        }
        double avg_e_epoch_glob = 0.0;
        double avg_e_epoch_last = 0.0;
        if (cli.debug_stats) {
          if (g_e_epoch_samples > 0) avg_e_epoch_glob = (double)g_e_epoch_sum / (double)g_e_epoch_samples;
          if (g_e_epoch_last_samples > 0) avg_e_epoch_last = (double)g_e_epoch_last_sum / (double)g_e_epoch_last_samples;
        }

        mx_tx_entry_t tx_entries[MAX_TX_IDS];
        size_t tx_entry_count = 0;
        mx_if_entry_t if_entries[MX_MAX_IF_ENTRIES];
        size_t if_entry_count = 0;
        int iface_freq_mhz[MAX_IFS];
        for (int i = 0; i < n_open; ++i) {
          iface_freq_mhz[i] = wfbx_if_get_frequency_mhz(cli.ifname[i]);
        }

        for (int tX = 0; tX < MAX_TX_IDS; ++tX) {
          int tx_active = (TX[tX].pkts > 0) || (TXD[tX].unique_pkts > 0);
          if (!tx_active) continue;
          if (tx_entry_count >= MAX_TX_IDS) continue;
          mx_tx_entry_t* tx_entry = &tx_entries[tx_entry_count];
          memset(tx_entry, 0, sizeof(*tx_entry));
          tx_entry->summary.tx_id = (uint8_t)tX;
          uint64_t unique_total = 0;
          uint64_t lost_total = 0;
          for (int rp = 0; rp < MAX_RADIO_PORTS; ++rp) {
            unique_total += TXD[tX].ports[rp].unique_pkts;
            lost_total += TXD[tX].ports[rp].lost;
          }
          uint32_t packets_unique = (unique_total > UINT32_MAX) ? UINT32_MAX : (uint32_t)unique_total;
          uint32_t lost_clamped = (lost_total > UINT32_MAX) ? UINT32_MAX : (uint32_t)lost_total;
          tx_entry->summary.packets = packets_unique;
          tx_entry->summary.lost = lost_clamped;
          uint64_t exp_tx_total = unique_total + lost_total;
          double qlt_tx = (exp_tx_total > 0) ? ((double)unique_total * 1000.0 / (double)exp_tx_total) : 1000.0;
          tx_entry->summary.quality_permille = clamp_permille((int)lrint(qlt_tx));
          double rate_kbps = 0.0;
          if (cli.stat_period_ms > 0) {
            rate_kbps = ((double)TXD[tX].bytes * 8.0) / (double)cli.stat_period_ms;
          }
          if (rate_kbps > (double)INT32_MAX) rate_kbps = (double)INT32_MAX;
          tx_entry->summary.rate_kbps = (int32_t)lrint(rate_kbps);
          int best_chain_avg = -127;
          for (int i2 = 0; i2 < n_open; ++i2) {
            for (int c = 0; c < RX_ANT_MAX; ++c) {
              struct ant_stats* AS = &TXD[tX].ifs[i2].ant[c];
              if (AS->rssi_samples > 0) {
                int avgc = (int)((AS->rssi_sum + (AS->rssi_samples > 0 ? (AS->rssi_samples / 2) : 0)) / (AS->rssi_samples ? AS->rssi_samples : 1));
                if (avgc > best_chain_avg) best_chain_avg = avgc;
              }
            }
          }
          tx_entry->summary.rssi_q8 = to_q8((double)best_chain_avg);
          if (cli.debug_stats) {
            tx_entry->summary.state_flags |= WFBX_MX_TX_FLAG_DEBUG;
            struct epoch_stats* ES = &TXD[tX].es_overall;
            double avg_real = (ES->real_delta_samples > 0) ? ((double)ES->real_delta_sum / (double)ES->real_delta_samples) : 0.0;
            double avg_ed   = (ES->e_delta_samples > 0) ? ((double)ES->e_delta_sum / (double)ES->e_delta_samples) : 0.0;
            tx_entry->summary.debug_real_delta_q4 = to_q4(avg_real);
            tx_entry->summary.debug_e_delta_q4 = to_q4(avg_ed);
          }
          uint8_t iface_counter = 0;
          for (int i2 = 0; i2 < n_open; ++i2) {
            struct if_detail* D = &TXD[tX].ifs[i2];
            uint64_t if_unique = 0;
            uint64_t if_lost = 0;
            for (int rp = 0; rp < MAX_RADIO_PORTS; ++rp) {
              if_unique += D->ports[rp].unique_pkts;
              if_lost += D->ports[rp].lost;
            }
            if (if_unique == 0 && if_lost == 0 && D->es.epoch_samples == 0) continue;
            if (if_entry_count >= MX_MAX_IF_ENTRIES) continue;
            mx_if_entry_t* if_entry = &if_entries[if_entry_count];
            memset(if_entry, 0, sizeof(*if_entry));
            if_entry->detail.tx_id = (uint8_t)tX;
            if_entry->detail.iface_id = (uint8_t)i2;
            if_entry->detail.packets = clamp_u32(if_unique);
            if_entry->detail.lost = clamp_u32(if_lost);
            if_entry->detail.reserved0 = 0;
            uint64_t exp_total = if_unique + if_lost;
            double qlt = (exp_total > 0) ? ((double)if_unique * 1000.0 / (double)exp_total) : 1000.0;
            if_entry->detail.quality_permille = clamp_permille((int)lrint(qlt));
            if_entry->detail.freq_mhz = (uint16_t)(iface_freq_mhz[i2]);
            if_entry->detail.reserved1 = 0;
            int best_chain_avg_if = -127;
            for (int c = 0; c < RX_ANT_MAX; ++c) {
              struct ant_stats* AS = &D->ant[c];
              if (AS->rssi_samples > 0) {
                int avgc = (int)((AS->rssi_sum + (AS->rssi_samples > 0 ? (AS->rssi_samples / 2) : 0)) / (AS->rssi_samples ? AS->rssi_samples : 1));
                if (avgc > best_chain_avg_if) best_chain_avg_if = avgc;
              }
            }
            if_entry->detail.best_chain_rssi_q8 = to_q8((double)best_chain_avg_if);
            for (int c = 0; c < RX_ANT_MAX; ++c) {
              struct ant_stats* AS = &D->ant[c];
              uint64_t packets_ch = 0;
              uint64_t lost_ch = 0;
              for (int rp = 0; rp < MAX_RADIO_PORTS; ++rp) {
                packets_ch += AS->ports[rp].packets;
                lost_ch += AS->ports[rp].lost;
              }
              if (packets_ch == 0 && lost_ch == 0) continue;
              if (if_entry->detail.chain_count >= RX_ANT_MAX) continue;
              wfbx_mx_chain_detail_t* chain = &if_entry->chains[if_entry->detail.chain_count];
              chain->chain_id = (uint8_t)c;
              chain->ant_id = (uint8_t)AS->ant_id;
              uint64_t exp_chain = packets_ch + lost_ch;
              double q_chain = (exp_chain > 0) ? ((double)packets_ch * 1000.0 / (double)exp_chain) : 1000.0;
              chain->quality_permille = clamp_permille((int)lrint(q_chain));
              double rssi_avg = (AS->rssi_samples > 0) ? ((double)AS->rssi_sum / (double)AS->rssi_samples) : 0.0;
              chain->rssi_min_q8 = to_q8((double)AS->rssi_min);
              chain->rssi_avg_q8 = to_q8(rssi_avg);
              chain->rssi_max_q8 = to_q8((double)AS->rssi_max);
              chain->packets = clamp_u16((packets_ch > 0xFFFFu) ? 0xFFFFu : (uint32_t)packets_ch);
              chain->lost = clamp_u16((lost_ch > 0xFFFFu) ? 0xFFFFu : (uint32_t)lost_ch);
              if_entry->detail.chain_count++;
            }
            if (if_entry->detail.chain_count > 0 || if_entry->detail.packets > 0 || if_entry->detail.lost > 0) {
              iface_counter++;
              if_entry_count++;
            }
          }
          tx_entry->summary.if_count = iface_counter;
          tx_entry_count++;
        }

        wfbx_mx_global_debug_t debug_payload;
        memset(&debug_payload, 0, sizeof(debug_payload));
        bool have_debug_payload = false;
        if (cli.debug_stats) {
          debug_payload.real_delta_avg_q4 = to_q4(avg_real_du);
          debug_payload.real_delta_min_q4 = to_q4_from_i64(real_delta_min);
          debug_payload.real_delta_max_q4 = to_q4_from_i64(real_delta_max);
          debug_payload.real_delta_samples = (uint32_t)real_delta_samples;
          debug_payload.e_delta_avg_q4 = to_q4(avg_e_delta);
          debug_payload.e_delta_min_q4 = to_q4_from_i64(e_delta_min);
          debug_payload.e_delta_max_q4 = to_q4_from_i64(e_delta_max);
          debug_payload.e_delta_samples = (uint32_t)e_delta_samples;
          debug_payload.e_epoch_avg_q4 = to_q4(avg_e_epoch_glob);
          debug_payload.e_epoch_min_q4 = to_q4_from_i64(g_e_epoch_min);
          debug_payload.e_epoch_max_q4 = to_q4_from_i64(g_e_epoch_max);
          debug_payload.e_epoch_samples = (uint32_t)g_e_epoch_samples;
          debug_payload.e_epoch_last_avg_q4 = to_q4(avg_e_epoch_last);
          debug_payload.e_epoch_last_min_q4 = to_q4_from_i64(g_e_epoch_last_min);
          debug_payload.e_epoch_last_max_q4 = to_q4_from_i64(g_e_epoch_last_max);
          debug_payload.e_epoch_last_samples = (uint32_t)g_e_epoch_last_samples;
          have_debug_payload = true;
        }

        fprintf(stderr, "\n[MX] dt=%llu ms | pkts=%llu | ifaces=%d\n",
                (unsigned long long)(t1-t0), (unsigned long long)pkts, n_open);
        /* Per-TX blocks first; inside each TX print per-IF details */
        for (int tX=0;tX<MAX_TX_IDS;tX++) {
          int tx_active = (TX[tX].pkts>0) || (TXD[tX].unique_pkts>0);
          if (!tx_active) continue;
          double avg_tx_rssi = (TX[tX].rssi_samples>0) ? ((double)TX[tX].rssi_sum / (double)TX[tX].rssi_samples) : 0.0;
          /* TX-level QLT: best chain avg across all IFs */
          int best_chain_avg = -127; int best_chain_valid = 0;
          for (int i2=0;i2<n_open;i2++) {
            for (int c=0;c<RX_ANT_MAX;c++) {
              struct ant_stats* AS = &TXD[tX].ifs[i2].ant[c];
              if (AS->rssi_samples>0) {
                int avgc = (int)((AS->rssi_sum + (AS->rssi_samples>0? (AS->rssi_samples/2):0)) / (AS->rssi_samples?AS->rssi_samples:1));
                if (!best_chain_valid || avgc > best_chain_avg) { best_chain_avg = avgc; best_chain_valid = 1; }
              }
            }
          }
          uint64_t unique_total = 0;
          uint64_t lost_total = 0;
          for (int rp = 0; rp < MAX_RADIO_PORTS; ++rp) {
            unique_total += TXD[tX].ports[rp].unique_pkts;
            lost_total += TXD[tX].ports[rp].lost;
          }
          /* TX-level QLT: based on deduped stream: unique / (unique + lost_total) */
          uint64_t exp_tx_total = unique_total + lost_total;
          double qlt_tx = (exp_tx_total>0) ? (100.0 * (double)unique_total / (double)exp_tx_total) : 0.0;
          fprintf(stderr, "\n  [TX %03d] upkts=%llu lost=%llu qlt=%.1f%% | RSSI min=%d avg=%.1f max=%d\n",
                  tX,(unsigned long long)unique_total,(unsigned long long)lost_total,qlt_tx,
                  (int)TX[tX].rssi_min,avg_tx_rssi,(int)TX[tX].rssi_max);
          if (cli.debug_stats) {
            struct epoch_stats* ES = &TXD[tX].es_overall;
            double avg_real = (ES->real_delta_samples>0) ? ((double)ES->real_delta_sum/(double)ES->real_delta_samples) : 0.0;
            double avg_ed   = (ES->e_delta_samples>0) ? ((double)ES->e_delta_sum/(double)ES->e_delta_samples) : 0.0;
            fprintf(stderr, "      real_delta avg=%.1f min=%lld max=%lld n=%llu\n      e_delta avg=%.1f min=%lld max=%lld n=%llu\n",
                    avg_real,(long long)ES->real_delta_min,(long long)ES->real_delta_max,(unsigned long long)ES->real_delta_samples,
                    avg_ed,(long long)ES->e_delta_min,(long long)ES->e_delta_max,(unsigned long long)ES->e_delta_samples);
          }
          /* Then per-interface detail for this TX */
          for (int i2=0;i2<n_open;i2++) {
            struct if_detail* D = &TXD[tX].ifs[i2];
            uint64_t if_unique = 0;
            uint64_t if_lost = 0;
            for (int rp = 0; rp < MAX_RADIO_PORTS; ++rp) {
              if_unique += D->ports[rp].unique_pkts;
              if_lost += D->ports[rp].lost;
            }
            if (if_unique==0 && if_lost==0 && D->es.epoch_samples==0) continue;
            uint64_t exp_total = if_unique + if_lost;
            double qlt = (exp_total>0) ? (100.0 * (double)if_unique / (double)exp_total) : 0.0;
            /* Best chain avg on this iface */
            int best_chain_avg_if = -127; int best_chain_id = -1; int best_valid=0;
            for (int c=0;c<RX_ANT_MAX;c++) {
              struct ant_stats* AS = &D->ant[c];
              if (AS->rssi_samples>0) {
                int avgc = (int)((AS->rssi_sum + (AS->rssi_samples>0? (AS->rssi_samples/2):0)) / (AS->rssi_samples?AS->rssi_samples:1));
                if (!best_valid || avgc > best_chain_avg_if) { best_chain_avg_if = avgc; best_chain_id = AS->ant_id; best_valid=1; }
              }
            }
            fprintf(stderr, "\n    [IF %d] pkts=%llu lost=%llu qlt=%.1f%% | bestChain=%s%d(avg %d dBm)\n",
                    i2,(unsigned long long)if_unique,(unsigned long long)if_lost,qlt,
                    (best_valid?"ANT":"n/a "), best_valid?(int)best_chain_id:0, best_valid?best_chain_avg_if:0);
            /* Per-antenna stats */
            for (int c=0;c<RX_ANT_MAX;c++) {
              struct ant_stats* AS = &D->ant[c];
              uint64_t packets_ch = 0;
              uint64_t lost_ch = 0;
              for (int rp = 0; rp < MAX_RADIO_PORTS; ++rp) {
                packets_ch += AS->ports[rp].packets;
                lost_ch += AS->ports[rp].lost;
              }
              if (packets_ch==0 && lost_ch==0) continue;
              double av = (AS->rssi_samples>0)?((double)AS->rssi_sum/(double)AS->rssi_samples):0.0;
              fprintf(stderr, "      ANTa%02d: rssi min=%d avg=%.1f max=%d | pkts=%llu lost=%llu\n",
                      (int)AS->ant_id,(int)AS->rssi_min,av,(int)AS->rssi_max,
                      (unsigned long long)packets_ch,(unsigned long long)lost_ch);
            }
            if (cli.debug_stats) {
              struct epoch_stats* EI = &D->es;
              double ar = (EI->real_delta_samples>0)?((double)EI->real_delta_sum/(double)EI->real_delta_samples):0.0;
              double ad = (EI->e_delta_samples>0)?((double)EI->e_delta_sum/(double)EI->e_delta_samples):0.0;
              fprintf(stderr, "      real_delta avg=%.1f min=%lld max=%lld n=%llu\n      e_delta avg=%.1f min=%lld max=%lld n=%llu\n",
                      ar,(long long)EI->real_delta_min,(long long)EI->real_delta_max,(unsigned long long)EI->real_delta_samples,
                      ad,(long long)EI->e_delta_min,(long long)EI->e_delta_max,(unsigned long long)EI->e_delta_samples);
            }
          }
        }
        if (cli.debug_stats) {
          fprintf(stderr, "\n      real_delta_us: avg=%.1f min=%lld max=%lld n=%llu\n",
                  avg_real_du, (long long)real_delta_min, (long long)real_delta_max,
                  (unsigned long long)real_delta_samples);
          fprintf(stderr, "      e_delta: avg=%.1f min=%lld max=%lld n=%llu\n",
                  avg_e_delta, (long long)e_delta_min, (long long)e_delta_max, (unsigned long long)e_delta_samples);
          /* Global e_epoch based on current tracker: e_epoch = g_epoch_instant_us - epoch_tx_us (aggregated) */
          avg_e_epoch_glob = (g_e_epoch_samples>0)?((double)g_e_epoch_sum/(double)g_e_epoch_samples):0.0;
          fprintf(stderr, "      e_epoch(glob): avg=%.1f min=%lld max=%lld n=%llu\n",
                  avg_e_epoch_glob, (long long)g_e_epoch_min, (long long)g_e_epoch_max, (unsigned long long)g_e_epoch_samples);
          /* Global e_epoch_last: last value before switching epoch key */
          avg_e_epoch_last = (g_e_epoch_last_samples>0)?((double)g_e_epoch_last_sum/(double)g_e_epoch_last_samples):0.0;
          fprintf(stderr, "      e_epoch_last:  avg=%.1f min=%lld max=%lld n=%llu\n",
                  avg_e_epoch_last, (long long)g_e_epoch_last_min, (long long)g_e_epoch_last_max, (unsigned long long)g_e_epoch_last_samples);
          fprintf(stderr, "      ctrl_epoch_sent=%llu\n", (unsigned long long)g_ctrl_epoch_send_period);
        }
        else {
          fprintf(stderr, "      ctrl_epoch_sent=%llu\n", (unsigned long long)g_ctrl_epoch_send_period);
        }
        uint16_t stats_flags = 0;
        if (cli.debug_stats) stats_flags |= 0x0001;
        if (if_entry_count > 0) stats_flags |= 0x0002;

        g_mx_stats_packet_len = 0;
        uint8_t payload[WFBX_MX_STATS_MAX_PACKET - WFBX_STATS_HEADER_SIZE];
        size_t payload_off = 0;
        uint16_t section_count = 0;
        int build_failed = 0;

        wfbx_mx_summary_t summary_host = {
          .dt_ms = (uint32_t)(t1 - t0),
          .packets_total = (uint32_t)pkts,
          .bytes_total = (uint32_t)(bytes_forwarded > UINT32_MAX ? UINT32_MAX : bytes_forwarded),
          .ctrl_epoch_sent = (uint32_t)g_ctrl_epoch_send_period,
          .iface_count = (uint16_t)n_open,
          .tx_count = (uint16_t)tx_entry_count,
          .flags = stats_flags,
          .reserved = 0
        };

        uint8_t summary_buf[sizeof(wfbx_mx_summary_t)];
        int summary_sz = wfbx_mx_summary_pack(summary_buf, sizeof(summary_buf), &summary_host);
        if (summary_sz <= 0 ||
            append_section(payload, &payload_off, sizeof(payload), WFBX_SECTION_SUMMARY, summary_buf, (uint16_t)sizeof(summary_buf)) != 0) {
          fprintf(stderr, "[STATS] summary append failed (size=%d)\n", summary_sz);
          build_failed = 1;
        } else {
          fprintf(stderr, "[STATS] summary appended size=%d payload_off=%zu\n", summary_sz, payload_off);
          section_count++;
        }

        if (!build_failed) {
          const char* tx_spec = (cli.tx_filter_spec && *cli.tx_filter_spec) ? cli.tx_filter_spec : "any";
          wfbx_mx_filter_info_t filter_info = {
            .version = 1,
            .tx_filter_mode = (uint8_t)cli.txf.mode,
            .group_id = (int16_t)cli.group_id
          };
          snprintf(filter_info.tx_filter_spec, sizeof(filter_info.tx_filter_spec), "%s", tx_spec);
          uint8_t filter_buf[5 + sizeof(filter_info.tx_filter_spec)];
          int filter_sz = wfbx_mx_filter_info_pack(filter_buf, sizeof(filter_buf), &filter_info);
          if (filter_sz <= 0 ||
              append_section(payload, &payload_off, sizeof(payload), WFBX_MX_SECTION_FILTER_INFO, filter_buf, (uint16_t)filter_sz) != 0) {
            fprintf(stderr, "[STATS] filter info append failed (size=%d)\n", filter_sz);
            build_failed = 1;
          } else {
            fprintf(stderr, "[STATS] filter info appended mode=%u group=%d spec=\"%s\" payload_off=%zu\n",
                    (unsigned)filter_info.tx_filter_mode, (int)filter_info.group_id,
                    filter_info.tx_filter_spec, payload_off);
            section_count++;
          }
        }

        uint8_t* tx_payload = NULL;
        size_t tx_payload_len = tx_entry_count * sizeof(wfbx_mx_tx_summary_t);
        if (!build_failed && tx_entry_count > 0) {
          if (tx_payload_len > UINT16_MAX) {
            build_failed = 1;
          } else {
            tx_payload = (uint8_t*)malloc(tx_payload_len);
            if (!tx_payload) {
              build_failed = 1;
            } else {
              size_t tx_offset = 0;
              for (size_t i = 0; i < tx_entry_count; ++i) {
                if (wfbx_mx_tx_summary_pack(tx_payload + tx_offset, tx_payload_len - tx_offset, &tx_entries[i].summary) < 0) {
                  build_failed = 1;
                  break;
                }
                tx_offset += sizeof(wfbx_mx_tx_summary_t);
              }
              if (!build_failed) {
                if (append_section(payload, &payload_off, sizeof(payload), WFBX_MX_SECTION_TX_SUMMARY, tx_payload, (uint16_t)tx_offset) != 0) {
                  fprintf(stderr, "[STATS] TX summary append failed (tx_offset=%zu)\n", tx_offset);
                  build_failed = 1;
                } else {
                  fprintf(stderr, "[STATS] TX summary appended chains=%zu payload_off=%zu\n", tx_entry_count, payload_off);
                  section_count++;
                }
              }
            }
          }
        }

        uint8_t* if_payload = NULL;
        size_t if_payload_len = 0;
        if (!build_failed && if_entry_count > 0) {
          for (size_t i = 0; i < if_entry_count; ++i) {
            if_payload_len += sizeof(wfbx_mx_if_detail_t) + if_entries[i].detail.chain_count * sizeof(wfbx_mx_chain_detail_t);
          }
          if (if_payload_len > UINT16_MAX) {
            build_failed = 1;
          } else {
            if_payload = (uint8_t*)malloc(if_payload_len);
            if (!if_payload) {
              build_failed = 1;
            } else {
              size_t if_offset = 0;
              for (size_t i = 0; i < if_entry_count && !build_failed; ++i) {
                int written = wfbx_mx_if_detail_pack(if_payload + if_offset, if_payload_len - if_offset,
                                                    &if_entries[i].detail, if_entries[i].chains);
                if (written < 0) build_failed = 1;
                else if_offset += (size_t)written;
              }
              if (!build_failed) {
                if (append_section(payload, &payload_off, sizeof(payload), WFBX_MX_SECTION_IF_DETAIL, if_payload, (uint16_t)if_payload_len) != 0) {
                  fprintf(stderr, "[STATS] IF detail append failed (len=%zu)\n", if_payload_len);
                  build_failed = 1;
                } else {
                  fprintf(stderr, "[STATS] IF detail appended count=%zu payload_off=%zu\n", if_entry_count, payload_off);
                  section_count++;
                }
              }
            }
          }
        }

        if (!build_failed && have_debug_payload) {
          uint8_t dbg_buf[sizeof(wfbx_mx_global_debug_t)];
          if (wfbx_mx_global_debug_pack(dbg_buf, sizeof(dbg_buf), &debug_payload) != 0 ||
              append_section(payload, &payload_off, sizeof(payload), WFBX_MX_SECTION_GLOBAL_DEBUG, dbg_buf, (uint16_t)sizeof(dbg_buf)) != 0) {
            fprintf(stderr, "[STATS] debug section append failed\n");
            build_failed = 1;
          } else {
            fprintf(stderr, "[STATS] debug section appended payload_off=%zu\n", payload_off);
            section_count++;
          }
        }

        if (tx_payload) free(tx_payload);
        if (if_payload) free(if_payload);

        if (!build_failed && payload_off + WFBX_STATS_HEADER_SIZE <= WFBX_MX_STATS_MAX_PACKET) {
          wfbx_stats_header_t header;
          wfbx_stats_header_init(&header, 1, WFBX_MODULE_MX, g_mx_stats_module_id,
                                 NULL,
                                 g_mx_stats_tick_id++, mono_us_raw(), stats_flags, section_count, (uint32_t)payload_off);
          uint8_t header_buf[WFBX_STATS_HEADER_SIZE];
          if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &header) == 0) {
            memcpy(g_mx_stats_packet, header_buf, WFBX_STATS_HEADER_SIZE);
            memcpy(g_mx_stats_packet + WFBX_STATS_HEADER_SIZE, payload, payload_off);
            g_mx_stats_packet_len = WFBX_STATS_HEADER_SIZE + payload_off;
            header.crc32 = wfbx_stats_crc32(g_mx_stats_packet, g_mx_stats_packet_len);
            if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &header) == 0)
              memcpy(g_mx_stats_packet, header_buf, WFBX_STATS_HEADER_SIZE);
            fprintf(stderr, "[STATS] packet ready len=%zu sections=%u\n", g_mx_stats_packet_len, section_count);
            if (stat_sock >= 0) {
              stats_send_packet(stat_sock, &stat_addr);
            } else {
              fprintf(stderr, "[STATS] stat_sock < 0, skip send\n");
            }
          } else {
            g_mx_stats_packet_len = 0;
          }
        } else {
          if (build_failed) fprintf(stderr, "[STATS] build_failed, skipping send\n");
          else fprintf(stderr, "[STATS] packet too large (%zu)\n", payload_off + WFBX_STATS_HEADER_SIZE);
          g_mx_stats_packet_len = 0;
        }

        t0 = t1; pkts = 0; bytes_forwarded = 0;
        /* Reset per-period iface/tx stats */
        stats_reset_period(n_open);
        real_delta_sum = 0; real_delta_samples = 0;
        e_delta_sum = 0; e_delta_samples = 0;
        g_e_epoch_sum = 0; g_e_epoch_samples = 0; g_e_epoch_min = 0; g_e_epoch_max = 0;
        g_e_epoch_last_sum = 0; g_e_epoch_last_samples = 0; g_e_epoch_last_min = 0; g_e_epoch_last_max = 0;
        g_ctrl_epoch_send_period = 0;

        /* Publish current T_epoch_instant to subscribers */
        if (cs >= 0 && g_have_epoch_inst) {
          struct wfbx_ctrl_epoch m; memset(&m, 0, sizeof(m));
          m.h.magic = WFBX_CTRL_MAGIC; m.h.ver = WFBX_CTRL_VER; m.h.type = WFBX_CTRL_EPOCH; m.h.seq = ++epoch_seq;
          m.epoch_us = g_epoch_instant_us; m.epoch_len_us = 0; m.epoch_gi_us = 0; m.issued_us = mono_us_raw();
          for (int k=0;k<64;k++) if (subs[k].active) { g_ctrl_epoch_send_period++; (void)sendto(cs, &m, sizeof(m), 0, (struct sockaddr*)&subs[k].sa, subs[k].sl); }
        }
      }
    }
  }

  for (int i=0;i<n_open;i++) if (ph[i]) pcap_close(ph[i]);
  close(us);
  if (stat_sock >= 0) close(stat_sock);
  if (cs >= 0) close(cs);
  return 0;
}
static void stats_send_packet(int sock, const struct sockaddr_in* addr)
{
    if (sock < 0 || !addr) return;
    if (g_mx_stats_packet_len == 0) return;
    char ipbuf[INET_ADDRSTRLEN];
    const char* ip = inet_ntop(AF_INET, &addr->sin_addr, ipbuf, sizeof(ipbuf));
    if (!ip) ip = "?";
    ssize_t sent = sendto(sock, g_mx_stats_packet, g_mx_stats_packet_len, 0,
                          (const struct sockaddr*)addr, sizeof(*addr));
    if (sent < 0) {
        perror("stats sendto");
        fprintf(stderr, "[STATS] sendto failed len=%zu dest=%s:%d\n",
                g_mx_stats_packet_len, ip, ntohs(addr->sin_port));
    } else {
        fprintf(stderr, "[STATS] sendto ok sent=%zd len=%zu dest=%s:%d\n",
                sent, g_mx_stats_packet_len, ip, ntohs(addr->sin_port));
    }
}
