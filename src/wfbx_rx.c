// wfbx_rx.c — multi-interface 802.11 capture ....
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
// - Supports multiple WLAN interfaces (positional args): receive diversity
// - A frame is accepted if received on at least one interface (dedup by 12-bit seq)
// - Per-antenna stats labeled ANTabc: a=iface index, bc=antenna index (00..99)
// - CLI: --ip, --port, --tx_id, --link_id, --radio_port, --stat_period, --help
// - TX filter supports: "any"/-1 (accept all), include-list "1,2,5,10-12", exclude-list "!3,7,20-25"
// - Periodic stats (default 1000 ms or --stat_period):
//     Global: packets, bytes, kbps, lost, quality, RSSI(best-chain) min/avg/max
//     Per-antenna (per interface): pkts, lost, quality, RSSI min/avg/max

/* Some libpcap headers rely on BSD types (u_char/u_short/u_int) from sys/types.h */
#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>     /* for SCHAR_MIN used in radiotap RSSI parsing */
#include <inttypes.h>   // For PRI* macros used in printf of 64-bit values
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
#include <limits.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>

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

// Fallback for le64toh on systems where it's missing.
// Converts a 64-bit little-endian value to host byte order.
#ifndef le64toh
  #if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define le64toh(x) (x)
  #else
    #define le64toh(x) __builtin_bswap64((uint64_t)(x))
  #endif
#endif

#ifndef TS_TAIL_BYTES
#define TS_TAIL_BYTES 8u  /* t0_ns tail size in bytes */
#endif

#include "wfb_defs.h"
#include "wfbx_stats_pkt.h"
#include "wfbx_ifutil.h"

/* ---- Defaults ---- */
#ifndef STATS_PERIOD_MS_DEFAULT
#define STATS_PERIOD_MS_DEFAULT 1000
#endif

/* Maximum number of distinct transmitters (tx_id is 0..255). */
#define MAX_TX_IDS 256

/* Per-interface dedup windows to prevent double-counting on the same iface. */
/* One 12-bit sequence sliding window per (tx_id, iface). */
struct seq_window; /* forward; already defined elsewhere */

/* Per-chain per-iface sequence state for loss accounting.
 * We update this only when a non-duplicate frame (for this iface) has an RSSI sample on that chain. */
struct per_chain_seq_state {
  int      have_seq;     /* whether we saw any frame on this (tx,iface,chain) */
  uint16_t expect_seq;   /* next expected 12-bit seq on this (tx,iface,chain) */
  uint32_t lost;         /* number of missing frames on this (tx,iface,chain) in current period */
};

/* Human-readable antenna label: 0XX for iface 0, 1XX for iface 1, etc. */
static inline int ant_label_id(int iface_idx, int chain_idx) {
  return iface_idx * 100 + chain_idx;
}

/* Maximum number of distinct transmitters (tx_id is 0..255). */
#define MAX_TX_IDS 256

/* Per-interface sequence tracker for per-TX per-iface loss accounting.
 * We keep expected seq per iface to estimate how many frames were missed by this iface. */
struct per_if_seq_state {
  int have_seq;          /* whether we saw any frame from this tx on this iface */
  uint16_t expect_seq;   /* next expected 12-bit seq on this iface */
  uint32_t lost;         /* number of missing frames on this iface for current period */
  uint32_t packets;      /* accepted packets for this iface within the period */
};

#define MAX_IFS 8

static const char* g_dest_ip_default   = "127.0.0.1";
static const int   g_dest_port_default = 5600;

static inline uint16_t clamp_u16(uint32_t v) { return (uint16_t)(v > 0xFFFFu ? 0xFFFFu : v); }

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

/* Monotonic milliseconds */
static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static inline uint64_t mono_us_raw(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
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

#define WFBX_RX_STATS_MAX_PACKET 1400

static uint8_t g_rx_stats_packet[WFBX_RX_STATS_MAX_PACKET];
static size_t  g_rx_stats_packet_len = 0;
static uint32_t g_rx_stats_tick_id = 0;
static char g_rx_stats_module_id[24] = "rx";

static void stats_send_packet(int sock, const struct sockaddr_in* addr);

typedef struct {
  wfbx_rx_if_detail_t detail;
  wfbx_rx_chain_detail_t chains[RX_ANT_MAX];
} rx_if_entry_t;

/* Radiotap RX parse */
struct rt_stats {
  uint16_t rt_len;
  uint8_t  flags;
  uint8_t  antenna[RX_ANT_MAX];
  int8_t   rssi[RX_ANT_MAX];   /* SCHAR_MIN => not present */
  int8_t   noise[RX_ANT_MAX];  /* SCHAR_MAX => not present */
  int      chains;

   /* ADD: TSFT support */
  uint64_t tsft_us;  /* radiotap TSFT in microseconds */
  int      has_tsft; /* 0/1 */
};

static int parse_radiotap_rx(const uint8_t* p, size_t caplen, struct rt_stats* rs)
{
  if (caplen < sizeof(struct wfb_radiotap_hdr_min)) return -1;
  const struct wfb_radiotap_hdr_min* rh = (const struct wfb_radiotap_hdr_min*)p;
  uint16_t it_len = rh->it_len;
  if (it_len > caplen || it_len < sizeof(struct wfb_radiotap_hdr_min)) return -1;

  rs->rt_len = it_len;
  rs->flags = 0;
  rs->chains = 0;
  rs->has_tsft = 0;
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
        case IEEE80211_RADIOTAP_ANTENNA: if (ant_idx < RX_ANT_MAX) { rs->antenna[ant_idx] = *field; ant_idx++; } break;
        case IEEE80211_RADIOTAP_TSFT:
            if (sz == 8) {
                uint64_t v;
                memcpy(&v, field, 8);
                rs->tsft_us = le64toh(v); /* TSFT always in us */
                rs->has_tsft = 1;
            } break;
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

/* ---- TX-ID FILTER ------------------------------------------------------- */

enum { TXF_ANY = 0, TXF_INCLUDE = 1, TXF_EXCLUDE = 2 };

struct txid_filter {
  int mode;          /* TXF_ANY / TXF_INCLUDE / TXF_EXCLUDE */
  uint64_t map[4];   /* 256-bit bitmap of IDs */
};

static void txf_set(struct txid_filter* f, unsigned v) {
  if (v > 255) return;
  f->map[v >> 6] |= (uint64_t)1ull << (v & 63);
}
static int txf_test(const struct txid_filter* f, unsigned v) {
  if (v > 255) return 0;
  return (f->map[v >> 6] >> (v & 63)) & 1ull;
}
static void txf_clear_all(struct txid_filter* f) { f->map[0]=f->map[1]=f->map[2]=f->map[3]=0; }
//static void txf_init_any(struct txid_filter* f)  { f->mode = TXF_ANY; txf_clear_all(f); }

static int parse_uint(const char* s, unsigned* out) {
  char* end = NULL;
  long v = strtol(s, &end, 0);
  if (!s || s==end || v < 0 || v > 255) return -1;
  *out = (unsigned)v;
  return 0;
}

/* Parse spec: "any" | "-1" | list | "!list", where list = "n[,m][,a-b]..." */
static int txf_parse(struct txid_filter* f, const char* spec)
{
  txf_clear_all(f);
  if (!spec || !*spec) { f->mode = TXF_INCLUDE; txf_set(f, 0); return 0; } /* default to {0} */

  while (isspace((unsigned char)*spec)) ++spec;

  if (strcmp(spec, "any") == 0 || strcmp(spec, "-1") == 0) {
    f->mode = TXF_ANY; return 0;
  }

  int excl = 0;
  if (spec[0] == '!') { excl = 1; ++spec; }

  f->mode = excl ? TXF_EXCLUDE : TXF_INCLUDE;

  char buf[256];
  strncpy(buf, spec, sizeof(buf)-1); buf[sizeof(buf)-1] = 0;

  char* saveptr = NULL;
  char* tok = strtok_r(buf, ",", &saveptr);
  while (tok) {
    while (isspace((unsigned char)*tok)) ++tok;
    /* range a-b? */
    char* dash = strchr(tok, '-');
    if (dash) {
      *dash = 0;
      const char* sA = tok;
      const char* sB = dash+1;
      unsigned a,b;
      if (parse_uint(sA, &a)==0 && parse_uint(sB, &b)==0) {
        if (a<=b) { for (unsigned v=a; v<=b; ++v) txf_set(f, v); }
        else      { for (unsigned v=b; v<=a; ++v) txf_set(f, v); }
      }
    } else {
      unsigned v;
      if (parse_uint(tok, &v)==0) txf_set(f, v);
    }
    tok = strtok_r(NULL, ",", &saveptr);
  }
  return 0;
}

static int txf_match(const struct txid_filter* f, uint8_t tx)
{
  if (f->mode == TXF_ANY) return 1;
  int present = txf_test(f, tx);
  return (f->mode == TXF_INCLUDE) ? present : !present;
}

/* ---- CLI ---------------------------------------------------------------- */

static volatile int g_run = 1;
static void on_sigint(int){ g_run = 0; }

struct cli_cfg {
  int n_if;
  const char* ifname[MAX_IFS];
  const char* ip;
  int port;
  struct txid_filter txf; /* NEW: flexible filter */
  int link_id;
  int group_id;
  int radio_port;
  int stat_period_ms;
  const char* stat_ip;
  int stat_port;
  const char* stat_id;
  const char* tx_filter_spec;
};

static void print_help(const char* prog)
{
  printf(
    "Usage: sudo %s [options] <wlan_iface1> [<wlan_iface2> ...]\n"
    "Options:\n"
    "  --ip <addr>         UDP destination IP (default: %s)\n"
    "  --port <num>        UDP destination port (default: %d)\n"
    "  --stat_ip <addr>    Stats server IP (default: 127.0.0.1)\n"
    "  --stat_port <num>   Stats server port (default: 9601)\n"
    "  --stat_id <name>    Stats module identifier (default: rx)\n"
    "  --tx_id <list>      Filter by transmitter IDs:\n"
    "                     'any' or '-1'               → accept all\n"
    "                      include list '1,2,5,10-12' → accept only listed IDs\n"
    "                      exclude list '!3,7,20-25   → accept all except listed IDs'\n"
    "                      (NOTE: use quotes or escape '!' in bash: --tx_id '!0,7' or --tx_id '\'!0,7)\n" 
    "                      (default: 0 — only tx_id=0)\n"
    "  --link_id <id>      Filter by Link ID (addr3[4]); -1 disables filter (default: 0)\n"
    "  --group_id <id>     Filter by Group ID (addr1[5]); -1 disables filter (default: any)\n"
    "  --radio_port <id>   Filter by Radio Port (addr3[5]); -1 disables filter (default: 0)\n"
    "  --stat_period <ms>  Stats period in milliseconds (default: %d)\n"
    "  --help              Show this help and exit\n"
    "\nExamples:\n"
    "  sudo %s --tx_id any wlan0\n"
    "  sudo %s --tx_id 1,2,10-12 wlan0 wlan1\n"
    "  sudo %s --tx_id !3,7,20-25 --link_id 0 --radio_port 0 wlan0\n",
    prog, g_dest_ip_default, g_dest_port_default, STATS_PERIOD_MS_DEFAULT,
    prog, prog, prog
  );
}

static int parse_cli(int argc, char** argv, struct cli_cfg* cfg)
{
  cfg->ip = g_dest_ip_default;
  cfg->port = g_dest_port_default;
  txf_parse(&cfg->txf, "0");   /* default: only tx_id=0 */
  cfg->tx_filter_spec = "0";
  cfg->link_id = 0;
  cfg->group_id = -1;
  cfg->radio_port = 0;
  cfg->n_if = 0;
  cfg->stat_period_ms = STATS_PERIOD_MS_DEFAULT;
  cfg->stat_ip = "127.0.0.1";
  cfg->stat_port = 9601;
  cfg->stat_id = "rx";

  static struct option longopts[] = {
    {"ip",           required_argument, 0, 0},
    {"port",         required_argument, 0, 0},
    {"stat_ip",      required_argument, 0, 0},
    {"stat_port",    required_argument, 0, 0},
    {"stat_id",      required_argument, 0, 0},
    {"tx_id",        required_argument, 0, 0},
    {"link_id",      required_argument, 0, 0},
    {"group_id",     required_argument, 0, 0},
    {"radio_port",   required_argument, 0, 0},
    {"stat_period",  required_argument, 0, 0},
    {"help",         no_argument,       0, 0},
    {0,0,0,0}
  };

  int optidx = 0;
  while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx);
    if (c == -1) break;
    if (c == 0) {
      const char* name = longopts[optidx].name;
      const char* val  = optarg ? optarg : "";
      if      (strcmp(name,"ip")==0)           cfg->ip = val;
      else if (strcmp(name,"port")==0)         cfg->port = atoi(val);
      else if (strcmp(name,"stat_ip")==0)      cfg->stat_ip = val;
      else if (strcmp(name,"stat_port")==0)    cfg->stat_port = atoi(val);
      else if (strcmp(name,"stat_id")==0)      cfg->stat_id = val;
      else if (strcmp(name,"tx_id")==0) { cfg->tx_filter_spec = val; txf_parse(&cfg->txf, val); }
      else if (strcmp(name,"link_id")==0)      cfg->link_id = atoi(val);
      else if (strcmp(name,"group_id")==0)     cfg->group_id = atoi(val);
      else if (strcmp(name,"radio_port")==0)   cfg->radio_port = atoi(val);
      else if (strcmp(name,"stat_period")==0)  cfg->stat_period_ms = atoi(val);
      else if (strcmp(name,"help")==0) { print_help(argv[0]); exit(0); }
    }
  }
  if (optind >= argc) {
    fprintf(stderr, "Error: missing <wlan_iface>. Use --help for usage.\n");
    return -1;
  }
  for (int i=optind; i<argc && cfg->n_if < MAX_IFS; ++i) {
    cfg->ifname[cfg->n_if++] = argv[i];
  }
  if (cfg->n_if == 0) {
    fprintf(stderr, "Error: no interfaces.\n");
    return -1;
  }
  if (cfg->stat_period_ms <= 0) cfg->stat_period_ms = STATS_PERIOD_MS_DEFAULT;
  return 0;
}

/* Per-antenna accumulators per interface for current stats period */
struct ant_stats {
  uint8_t ant_id;          /* radiotap ANTENNA (last seen) */
  int rssi_min;
  int rssi_max;
  int64_t rssi_sum;
  uint32_t rssi_samples;   /* pkts counted for this chain */
  int have_seq;
  uint16_t expect_seq;
  uint32_t lost;
};

static void ant_stats_reset(struct ant_stats A[MAX_IFS][RX_ANT_MAX], int n_if) {
  for (int a=0; a<n_if; ++a)
    for (int i=0;i<RX_ANT_MAX;i++) {
      A[a][i].ant_id = 0xff;
      A[a][i].rssi_min = 127;
      A[a][i].rssi_max = -127;
      A[a][i].rssi_sum = 0;
      A[a][i].rssi_samples = 0;
      A[a][i].have_seq = 0;
      A[a][i].expect_seq = 0;
      A[a][i].lost = 0;
    }
}

/* Clear one ant_stats accumulator:
 * - resets RSSI bounds to initial sentinel values
 * - zeroes counters for the current stats period
 */
static inline void ant_stats_clear(struct ant_stats* S) {
  if (!S) return;
  S->rssi_min     = 127;    /* sentinel "no samples yet" */
  S->rssi_max     = -127;   /* sentinel "no samples yet" */
  S->rssi_sum     = 0;
  S->rssi_samples = 0;
  S->lost         = 0;
}

/* Update one ant_stats with a single RSSI sample (in dBm). */
static inline void ant_stats_update_one(struct ant_stats* S, int rssi_dbm) {
  if (!S) return;
  if (rssi_dbm < S->rssi_min) S->rssi_min = rssi_dbm;
  if (rssi_dbm > S->rssi_max) S->rssi_max = rssi_dbm;
  S->rssi_sum += rssi_dbm;
  S->rssi_samples++;
}

/* Global dedup by 12-bit seq: sliding bitmap window of size 128 */
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

int main(int argc, char** argv)
{
  struct cli_cfg cli;
  if (parse_cli(argc, argv, &cli) != 0) return 1;

  signal(SIGINT, on_sigint);

  /* UDP out socket */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(cli.port);
  if (!inet_aton(cli.ip, &dst.sin_addr)) {
    fprintf(stderr, "inet_aton failed for %s\n", cli.ip);
    return 1;
  }

  int stat_sock = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in stat_addr;
  memset(&stat_addr, 0, sizeof(stat_addr));
  stat_addr.sin_family = AF_INET;
  stat_addr.sin_port = htons(cli.stat_port);
  if (stat_sock >= 0) {
    if (!inet_aton(cli.stat_ip, &stat_addr.sin_addr)) {
      fprintf(stderr, "inet_aton failed for stats server %s\n", cli.stat_ip);
      close(stat_sock);
      stat_sock = -1;
    } else {
      fprintf(stderr, "[STATS] RX stats socket created -> %s:%d (fd=%d)\n",
              cli.stat_ip, cli.stat_port, stat_sock);
    }
  } else {
    perror("stats socket");
  }

  if (cli.stat_id && *cli.stat_id) {
    snprintf(g_rx_stats_module_id, sizeof(g_rx_stats_module_id), "%.*s",
             (int)(sizeof(g_rx_stats_module_id) - 1), cli.stat_id);
  } else {
    snprintf(g_rx_stats_module_id, sizeof(g_rx_stats_module_id), "rx");
  }

  /* Open PCAP for each interface */
  pcap_t* ph[MAX_IFS] = {0};
  int fds[MAX_IFS]; for (int i=0;i<MAX_IFS;i++) fds[i] = -1;
  int n_open = 0;
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  for (int i=0;i<cli.n_if; ++i) {
    pcap_t* p = pcap_create(cli.ifname[i], errbuf);
    if (!p) { fprintf(stderr, "pcap_create(%s): %s\n", cli.ifname[i], errbuf); continue; }
    (void)pcap_set_immediate_mode(p, 1);
    if (pcap_activate(p) != 0) {
      fprintf(stderr, "pcap_activate(%s): %s\n", cli.ifname[i], pcap_geterr(p));
      pcap_close(p); continue;
    }
    (void)pcap_setnonblock(p, 1, errbuf);
    int fd = pcap_get_selectable_fd(p);
    if (fd < 0) {
      fprintf(stderr, "pcap_get_selectable_fd(%s) failed; interface skipped\n", cli.ifname[i]);
      pcap_close(p); continue;
    }
    ph[n_open]  = p;
    fds[n_open] = fd;
    n_open++;
  }
  if (n_open == 0) { fprintf(stderr, "No usable interfaces opened.\n"); return 1; }

  fprintf(stderr, "RX: ");
  for (int i=0;i<n_open;i++) fprintf(stderr, "%s%s", cli.ifname[i], (i+1<n_open?", ":""));
  fprintf(stderr, " -> UDP %s:%d | stats %d ms | filters: TX=%s LINK=%d GROUP=%d PORT=%d | stats -> %s:%d id=%s\n",
          cli.ip, cli.port, cli.stat_period_ms,
          (cli.txf.mode==TXF_ANY?"any":(cli.txf.mode==TXF_INCLUDE?"include":"exclude")),
          cli.link_id, cli.group_id, cli.radio_port,
          cli.stat_ip, cli.stat_port, cli.stat_id);

  /* Global period accumulators */
  uint64_t t0 = now_ms();
  uint64_t bytes_period = 0;
  uint32_t rx_pkts_period = 0;
  
  int rssi_min = 127;
  int rssi_max = -127;
  int64_t rssi_sum = 0;
  uint32_t rssi_samples = 0;

  /* Per-antenna per-interface accumulators (global, unchanged). */
  struct ant_stats A[MAX_IFS][RX_ANT_MAX];
  ant_stats_reset(A, n_open);

  /* Per-TX packet/bytes counters for the current stats period. */
  uint32_t pkts_tx[MAX_TX_IDS]  = {0};  /* accepted non-duplicates (global) */
  uint64_t bytes_tx[MAX_TX_IDS] = {0};  /* payload bytes minus TS tail */

  /* Global flag: becomes 1 after the very first accepted (non-duplicate) packet.
   * Used to print an "AWAITING" banner while no packets have ever been seen. */
  static int g_any_packets_seen = 0;
 
  /* NEW: last-seen bookkeeping (per tx_id) */
  uint64_t last_seen_ms[MAX_TX_IDS] = {0};      /* 0 => never seen */
  uint8_t  last_link_id[MAX_TX_IDS];            /* 0xFF => unknown */
  uint8_t  last_group_id[MAX_TX_IDS];           /* 0xFF => unknown */
  uint8_t  last_radio_port[MAX_TX_IDS];         /* 0xFF => unknown */
  for (int i=0;i<MAX_TX_IDS;i++) { last_link_id[i]=0xFF; last_group_id[i]=0xFF; last_radio_port[i]=0xFF; }


  /* Per-TX dedup windows (one 12-bit sequence space per tx_id). */
  struct seq_window SW[MAX_TX_IDS];  /* global dedup for forwarding and per-TX stats */
  /* Per-IFACE dedup windows (to compute per-iface/chain stats independently). */
  struct seq_window SWIF[MAX_TX_IDS][MAX_IFS]; /* dedup per (tx,iface) */
  /* Per-TX sequence tracking for global loss accounting. */
  struct { int have_seq; uint16_t expect_seq; uint32_t lost; } G[MAX_TX_IDS];
 
  /* Per-TX per-IFACE per-CHAIN sequence trackers for per-antenna loss. */
  struct per_chain_seq_state PC[MAX_TX_IDS][MAX_IFS][RX_ANT_MAX];
 

  /* Per-TX per-IFACE sequence trackers for interface-level loss metrics. */
  struct per_if_seq_state IFSTAT[MAX_TX_IDS][MAX_IFS];


  /* Per-TX per-IFACE per-CHAIN RSSI stats for the current period. */
  struct ant_stats ATX[MAX_TX_IDS][MAX_IFS][RX_ANT_MAX];

  /* Initialize per-TX state */
  for (int t = 0; t < MAX_TX_IDS; ++t) {      /* fill all possible tx_id slots */
    seqwin_init(&SW[t]);
    for (int a = 0; a < n_open; ++a) {seqwin_init(&SWIF[t][a]);}
    G[t].have_seq = 0;                 /* no seq seen yet for this tx_id */
    G[t].expect_seq = 0;               /* next expected 12-bit seq */
    G[t].lost = 0;                     /* period loss counter */
    for (int a = 0; a < n_open; ++a)
      for (int c = 0; c < RX_ANT_MAX; ++c) {
        PC[t][a][c].have_seq = 0;
        PC[t][a][c].expect_seq = 0;
        PC[t][a][c].lost = 0;
        ant_stats_clear(&ATX[t][a][c]); /* zero per-chain RSSI accumulators */
      }
    for (int a = 0; a < n_open; ++a) {
      IFSTAT[t][a].have_seq = 0;
      IFSTAT[t][a].expect_seq = 0;
      IFSTAT[t][a].lost = 0;
      IFSTAT[t][a].packets = 0;
    }
  }

  while (g_run) {
    uint64_t now = now_ms();
    uint64_t ms_left = (t0 + (uint64_t)cli.stat_period_ms > now) ? (t0 + (uint64_t)cli.stat_period_ms - now) : 0;
    struct timeval tv;
    tv.tv_sec = (time_t)(ms_left / 1000);
    tv.tv_usec = (suseconds_t)((ms_left % 1000) * 1000);

    fd_set rfds; FD_ZERO(&rfds);
    int maxfd = -1;
    for (int i=0;i<n_open;i++) { if (fds[i]>=0) { FD_SET(fds[i], &rfds); if (fds[i] > maxfd) maxfd = fds[i]; } }

    int sel = select(maxfd+1, &rfds, NULL, NULL, &tv);
    if (sel < 0) {
      if (errno == EINTR) goto stats_tick;
      perror("select");
      break;
    }

    for (int i=0;i<n_open;i++) {
      if (fds[i] < 0) continue;
      if (sel == 0 || !FD_ISSET(fds[i], &rfds)) continue;

      while (1) {
        struct pcap_pkthdr* hdr = NULL;
        const u_char* pkt = NULL;
        int rc = pcap_next_ex(ph[i], &hdr, &pkt);
        if (rc <= 0) break;
        /* RX host timestamp no longer needed; driver provides ts_rx in trailer */

        struct rt_stats rs;
        if (parse_radiotap_rx(pkt, hdr->caplen, &rs) != 0) continue;

        struct wfb_pkt_view v;
        if (extract_dot11(pkt, hdr->caplen, &rs, &v) != 0) continue;

        /* filters */
        uint8_t group_id_rx = v.h->addr1[5];
        uint8_t tx_id      = v.h->addr2[5];
        uint8_t link_id    = v.h->addr3[4];
        uint8_t radio_port = v.h->addr3[5];
        if (!txf_match(&cli.txf, tx_id)) continue;
        if (cli.link_id    >= 0 && link_id    != (uint8_t)cli.link_id)    continue;
        if (cli.group_id   >= 0 && group_id_rx != (uint8_t)cli.group_id) continue;
        if (cli.radio_port >= 0 && radio_port != (uint8_t)cli.radio_port) continue;

        /* Mark last-seen for this tx_id (after filters) */
        last_seen_ms[tx_id]   = now_ms();
        last_link_id[tx_id]   = link_id;
        last_group_id[tx_id]  = group_id_rx;
        last_radio_port[tx_id]= radio_port;

        /* Determine mesh trailer size for trimming (from wfb_defs.h) */
        size_t trailer_bytes = (v.payload_len >= WFBX_TRAILER_BYTES) ? (size_t)WFBX_TRAILER_BYTES : 0u;
        
        /* Global dedup by seq in the per-TX window. */
        int dup_global = seqwin_check_set(&SW[tx_id], v.seq12);
        const int should_forward = !dup_global; /* forward only once across all ifaces */
        if (should_forward) {
          /* Payload bytes minus the mesh trailer (reflect UDP payload rate). */
          size_t eff_len = v.payload_len;
          if (eff_len >= trailer_bytes) eff_len -= trailer_bytes;
          bytes_tx[tx_id] += (uint64_t)eff_len;
          pkts_tx[tx_id]  += 1;
          /* Mark that at least one valid packet has been seen globally. */
          g_any_packets_seen = 1;
        /* Per-TX loss tracking: count gaps within each tx_id sequence space. */
          if (!G[tx_id].have_seq) {
            G[tx_id].have_seq = 1;
            G[tx_id].expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
          } else {
            if (v.seq12 != G[tx_id].expect_seq) {
              uint16_t gap = (uint16_t)((v.seq12 - G[tx_id].expect_seq) & 0x0FFF);
              G[tx_id].lost += gap;  /* accumulate loss for this tx_id in current period */
              G[tx_id].expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            } else {
              G[tx_id].expect_seq = (uint16_t)((G[tx_id].expect_seq + 1) & 0x0FFF);
            }
          }        

        }

        /* Per-IFACE dedup window so that statistics are updated independently for each interface. */
        int dup_iface = seqwin_check_set(&SWIF[tx_id][i], v.seq12);
        if (!dup_iface) {
          struct per_if_seq_state* IS = &IFSTAT[tx_id][i];
          if (!IS->have_seq) {
            IS->have_seq = 1;
            IS->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
          } else {
            if (v.seq12 != IS->expect_seq) {
              uint16_t gap = (uint16_t)((v.seq12 - IS->expect_seq) & 0x0FFF);
              IS->lost += gap;
              IS->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            } else {
              IS->expect_seq = (uint16_t)((IS->expect_seq + 1) & 0x0FFF);
            }
          }
          IS->packets++;
          /* Per-CHAIN (on this iface) loss accounting and RSSI aggregation. */
          for (int c = 0; c < rs.chains && c < RX_ANT_MAX; ++c) {
            if (rs.rssi[c] == SCHAR_MIN) continue; /* chain not present in this frame */
            /* Update per-chain sequence state: count gaps since last seen seq on this chain. */
            struct per_chain_seq_state* Q = &PC[tx_id][i][c];
            if (!Q->have_seq) {
              Q->have_seq = 1;
              Q->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            } else {
              if (v.seq12 != Q->expect_seq) {
                uint16_t gap = (uint16_t)((v.seq12 - Q->expect_seq) & 0x0FFF);
                Q->lost += gap;
                Q->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
              } else {
                Q->expect_seq = (uint16_t)((Q->expect_seq + 1) & 0x0FFF);
              }
            }
            /* Accumulate per-chain RSSI for this tx_id on this iface. */
            ant_stats_update_one(&ATX[tx_id][i][c], (int)rs.rssi[c]);
          }
          
          /* global per-packet RSSI = best chain */
          int pkt_rssi_valid = 0;
          int pkt_rssi = -127;
          for (int c=0;c<rs.chains && c<RX_ANT_MAX; ++c) {
            if (rs.rssi[c] != SCHAR_MIN) { pkt_rssi_valid = 1; if (rs.rssi[c] > pkt_rssi) pkt_rssi = rs.rssi[c]; }
          }
          if (pkt_rssi_valid) {
            if (pkt_rssi < rssi_min) rssi_min = pkt_rssi;
            if (pkt_rssi > rssi_max) rssi_max = pkt_rssi;
            rssi_sum += pkt_rssi;
            rssi_samples++;
          }
        /* Forward only if not seen on another iface already */
        if (should_forward) {
          size_t out_len = v.payload_len;
          if (out_len >= trailer_bytes) out_len -= trailer_bytes;
          if (out_len > 0) {
            (void)sendto(us, v.payload, out_len, 0, (struct sockaddr*)&dst, sizeof(dst));
          }
        }

          rx_pkts_period += 1;
          bytes_period   += v.payload_len;
        }

        /* per-antenna per-interface stats */
        for (int c=0;c<rs.chains && c<RX_ANT_MAX; ++c) {
          if (rs.rssi[c] == SCHAR_MIN) continue;
          struct ant_stats* S = &A[i][c];
          if (!S->have_seq) { S->have_seq = 1; S->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF); }
          else {
            if (v.seq12 != S->expect_seq) {
              uint16_t gap = (uint16_t)((v.seq12 - S->expect_seq) & 0x0FFF);
              S->lost += gap;
              S->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            } else {
              S->expect_seq = (uint16_t)((S->expect_seq + 1) & 0x0FFF);
            }
          }
          int r = rs.rssi[c];
          if (r < S->rssi_min) S->rssi_min = r;
          if (r > S->rssi_max) S->rssi_max = r;
          S->rssi_sum += r;
          S->rssi_samples++;
          S->ant_id = rs.antenna[c];
        }
      } /* drain */
    } /* each iface */

stats_tick:
    uint64_t t1 = now_ms();
    if (t1 - t0 >= (uint64_t)cli.stat_period_ms) {
      
      double seconds = (double)(t1 - t0) / 1000.0;
      
      /* If nothing has ever been received yet, emit an 'AWAITING' banner with channel params. */
      if (!g_any_packets_seen) {
        /* Channel params come from current CLI filters: -1 means 'any'. */
        int ll = (cli.link_id    >= 0) ? cli.link_id    : -1;
        int rp = (cli.radio_port >= 0) ? cli.radio_port : -1;
        fprintf(stderr,
          "[AWAITING] no packets yet | link_id=%d | radio_port=%d\n",
          ll, rp);
        /* We still fall through; no per-TX lines will appear because ex==0 for all tx_id. */
      }

      int iface_freq_mhz[MAX_IFS];
      for (int i = 0; i < n_open; ++i) {
        iface_freq_mhz[i] = wfbx_if_get_frequency_mhz(cli.ifname[i]);
      }

      wfbx_rx_tx_summary_t tx_entries[MAX_TX_IDS];
      size_t tx_entry_count = 0;
      rx_if_entry_t if_entries[MAX_TX_IDS * MAX_IFS];
      size_t if_entry_count = 0;
      uint64_t bytes_total_sum = 0;
      uint32_t packets_total_sum = 0;

      /* Print per-TX blocks. Active means we saw pkts or losses this period. */
      for (int t = 0; t < MAX_TX_IDS; ++t) {
        uint32_t pk = pkts_tx[t];
        uint32_t ls = G[t].lost;
        uint32_t ex = pk + ls;
        if (ex == 0) {
          /* No packets and no inferred losses this period. If this tx_id was
             seen previously, emit a "signal lost" line with channel params. */
          if (last_seen_ms[t] != 0) {
            uint64_t idle_ms = t1 - last_seen_ms[t];
            int ll = (last_link_id[t]   == 0xFF) ? -1 : (int)last_link_id[t];
            int gp = (last_group_id[t]  == 0xFF) ? -1 : (int)last_group_id[t];
            int rp = (last_radio_port[t]== 0xFF) ? -1 : (int)last_radio_port[t];
            fprintf(stderr,
              "[TX %03d] dt=%llu ms | signal LOST | idle=%llu ms | link_id=%d | group_id=%d | radio_port=%d | rate=0.0 kbps | RSSI = n/a\n",
              t,
              (unsigned long long)(t1 - t0),
              (unsigned long long)idle_ms,
              ll, gp, rp);
          }
          continue; /* nothing else to print for this tx_id */
        }

        packets_total_sum += pk;
        bytes_total_sum += bytes_tx[t];

        /* Aggregate per-TX RSSI over all ifaces/chains for header line.
         * Show MAX of per-chain AVERAGES over the reporting period. */
        double tx_best_chain_avg = -127;
        int tx_have_samples = 0;
        for (int a=0; a<n_open; ++a) {
          for (int c=0; c<RX_ANT_MAX; ++c) {
            const struct ant_stats* S = &ATX[t][a][c];
            if (S->rssi_samples == 0) continue;
            double chain_avg = (double)S->rssi_sum / (double)S->rssi_samples;
            if (chain_avg > tx_best_chain_avg) tx_best_chain_avg = chain_avg;
            tx_have_samples = 1;
          }
        }

        if (!tx_have_samples) tx_best_chain_avg = -127;
        double tx_kbps = seconds > 0.0 ? (bytes_tx[t] * 8.0 / 1000.0) / seconds : 0.0;
        double tx_quality_permille = ex ? ((double)pk * 1000.0) / (double)ex : 1000.0;
        int tx_quality_percent = ex ? (int)((pk * 100.0) / ex + 0.5) : 100;

        fprintf(stderr,
          "[TX %03d] dt=%llu ms | pkts=%u lost=%u quality=%d%% | rate=%.1f kbps | RSSI = %.1f dBm\n",
          t, (unsigned long long)(t1 - t0), pk, ls, tx_quality_percent, tx_kbps, tx_best_chain_avg);

        uint8_t iface_counter = 0;

        for (int a=0; a<n_open; ++a) {
          uint32_t iface_packets = IFSTAT[t][a].packets;
          uint32_t iface_lost = IFSTAT[t][a].lost;
          wfbx_rx_chain_detail_t chain_tmp[RX_ANT_MAX];
          uint8_t chain_count = 0;
          double best_chain_avg_if = -127;

          for (int c=0; c<RX_ANT_MAX; ++c) {
            const struct ant_stats* S = &ATX[t][a][c];
            uint32_t lost_ch = PC[t][a][c].lost;
            if (S->rssi_samples == 0 && lost_ch == 0) continue;
            uint32_t exp_i = S->rssi_samples + lost_ch;
            double ravg = (S->rssi_samples>0) ? ((double)S->rssi_sum / (double)S->rssi_samples) : 0.0;
            if (S->rssi_samples > 0 && ravg > best_chain_avg_if) best_chain_avg_if = ravg;
            int q_i = exp_i ? (int)((S->rssi_samples * 100.0) / exp_i + 0.5) : 100;
            double q_chain_permille = exp_i ? ((double)S->rssi_samples * 1000.0) / (double)exp_i : 1000.0;
            if (chain_count < RX_ANT_MAX) {
              chain_tmp[chain_count].chain_id = (uint8_t)c;
              chain_tmp[chain_count].ant_id = (uint8_t)S->ant_id;
              chain_tmp[chain_count].quality_permille = clamp_permille((int)lrint(q_chain_permille));
              chain_tmp[chain_count].rssi_min_q8 = to_q8((double)S->rssi_min);
              chain_tmp[chain_count].rssi_avg_q8 = to_q8(ravg);
              chain_tmp[chain_count].rssi_max_q8 = to_q8((double)S->rssi_max);
              chain_tmp[chain_count].packets = clamp_u16(S->rssi_samples);
              chain_tmp[chain_count].lost = clamp_u16(lost_ch);
              chain_count++;
            }
            fprintf(stderr, "   [ANT%03d] pkts=%u lost=%u quality=%d%% | rssi min/avg/max = %d/%.1f/%d dBm\n",
                    ant_label_id(a,c), S->rssi_samples, lost_ch, q_i,
                    S->rssi_min, ravg, S->rssi_max);
          }

          if (iface_packets == 0 && iface_lost == 0 && chain_count == 0) continue;

          if (best_chain_avg_if == -127) best_chain_avg_if = 0.0;
          double iface_quality_permille = (iface_packets + iface_lost) ?
              ((double)iface_packets * 1000.0) / (double)(iface_packets + iface_lost) : 1000.0;

          if (if_entry_count < MAX_TX_IDS * MAX_IFS) {
            rx_if_entry_t* if_entry = &if_entries[if_entry_count];
            memset(if_entry, 0, sizeof(*if_entry));
            if_entry->detail.tx_id = (uint8_t)t;
            if_entry->detail.iface_id = (uint8_t)a;
            if_entry->detail.chain_count = chain_count;
            if_entry->detail.packets = iface_packets;
            if_entry->detail.lost = iface_lost;
            if_entry->detail.quality_permille = clamp_permille((int)lrint(iface_quality_permille));
            if_entry->detail.best_chain_rssi_q8 = to_q8(best_chain_avg_if);
            if_entry->detail.freq_mhz = (uint16_t)clamp_u16((iface_freq_mhz[a] > 0) ? (uint32_t)iface_freq_mhz[a] : 0u);
            memcpy(if_entry->chains, chain_tmp, (size_t)chain_count * sizeof(wfbx_rx_chain_detail_t));
            if_entry_count++;
          }

          iface_counter++;
        }

        if (tx_entry_count < MAX_TX_IDS) {
          wfbx_rx_tx_summary_t* tx_entry = &tx_entries[tx_entry_count++];
          memset(tx_entry, 0, sizeof(*tx_entry));
          tx_entry->tx_id = (uint8_t)t;
          tx_entry->iface_count = iface_counter;
          tx_entry->state_flags = 0;
          tx_entry->packets = pk;
          tx_entry->lost = ls;
          tx_entry->quality_permille = clamp_permille((int)lrint(tx_quality_permille));
          tx_entry->rssi_q8 = to_q8(tx_best_chain_avg);
          long rate_rounded = lrint(tx_kbps);
          if (rate_rounded > INT32_MAX) rate_rounded = INT32_MAX;
          if (rate_rounded < INT32_MIN) rate_rounded = INT32_MIN;
          tx_entry->rate_kbps = (int32_t)rate_rounded;
        }
      }

      uint16_t filter_flags = 0;
      if (cli.txf.mode != TXF_ANY) filter_flags |= 0x0001;
      if (cli.link_id >= 0)       filter_flags |= 0x0002;
      if (cli.radio_port >= 0)    filter_flags |= 0x0004;

      uint32_t dt_ms = (uint32_t)((t1 - t0) > UINT32_MAX ? UINT32_MAX : (t1 - t0));
      uint32_t packets_total32 = packets_total_sum > UINT32_MAX ? UINT32_MAX : packets_total_sum;
      uint32_t bytes_total32 = bytes_total_sum > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes_total_sum;

      wfbx_rx_summary_t summary_host = {
        .dt_ms = dt_ms,
        .packets_total = packets_total32,
        .bytes_total = bytes_total32,
        .iface_count = (uint16_t)n_open,
        .tx_count = (uint16_t)tx_entry_count,
        .filter_flags = filter_flags,
        .reserved = 0
      };

      uint8_t payload[WFBX_RX_STATS_MAX_PACKET - WFBX_STATS_HEADER_SIZE];
      size_t payload_off = 0;
      uint16_t section_count = 0;
      bool build_failed = false;

      uint8_t summary_buf[sizeof(wfbx_rx_summary_t)];
      if (wfbx_rx_summary_pack(summary_buf, sizeof(summary_buf), &summary_host) < 0 ||
          append_section(payload, &payload_off, sizeof(payload), WFBX_RX_SECTION_SUMMARY, summary_buf, (uint16_t)sizeof(summary_buf)) != 0) {
        fprintf(stderr, "[STATS] RX summary append failed\n");
        build_failed = true;
      } else {
        section_count++;
      }

      uint8_t* tx_payload = NULL;
      size_t tx_payload_len = tx_entry_count * sizeof(wfbx_rx_tx_summary_t);
      if (!build_failed && tx_entry_count > 0) {
        if (tx_payload_len > UINT16_MAX) {
          build_failed = true;
        } else {
          tx_payload = (uint8_t*)malloc(tx_payload_len);
          if (!tx_payload) {
            build_failed = true;
          } else {
            size_t tx_offset = 0;
            for (size_t i = 0; i < tx_entry_count && !build_failed; ++i) {
              if (wfbx_rx_tx_summary_pack(tx_payload + tx_offset, tx_payload_len - tx_offset, &tx_entries[i]) < 0) {
                build_failed = true;
                break;
              }
              tx_offset += sizeof(wfbx_rx_tx_summary_t);
            }
            if (!build_failed) {
              if (append_section(payload, &payload_off, sizeof(payload), WFBX_RX_SECTION_TX_SUMMARY, tx_payload, (uint16_t)tx_payload_len) != 0) {
                fprintf(stderr, "[STATS] RX TX summary append failed\n");
                build_failed = true;
              } else {
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
          if_payload_len += sizeof(wfbx_rx_if_detail_t) + if_entries[i].detail.chain_count * sizeof(wfbx_rx_chain_detail_t);
        }
        if (if_payload_len > UINT16_MAX) {
          build_failed = true;
        } else {
          if_payload = (uint8_t*)malloc(if_payload_len);
          if (!if_payload) {
            build_failed = true;
          } else {
            size_t if_offset = 0;
            for (size_t i = 0; i < if_entry_count && !build_failed; ++i) {
              int written = wfbx_rx_if_detail_pack(if_payload + if_offset, if_payload_len - if_offset,
                                                   &if_entries[i].detail, if_entries[i].chains);
              if (written < 0) {
                build_failed = true;
                break;
              }
              if_offset += (size_t)written;
            }
            if (!build_failed) {
              if (append_section(payload, &payload_off, sizeof(payload), WFBX_RX_SECTION_IF_DETAIL, if_payload, (uint16_t)if_payload_len) != 0) {
                fprintf(stderr, "[STATS] RX IF detail append failed\n");
                build_failed = true;
              } else {
                section_count++;
              }
            }
          }
        }
      }

      if (!build_failed) {
        wfbx_rx_filter_info_t filters = {
          .group_id = (cli.group_id >= 0 && cli.group_id <= 255) ? (uint8_t)cli.group_id : 0xFF,
          .txf_mode = (uint8_t)cli.txf.mode,
          .has_link_id = (cli.link_id >= 0) ? 1u : 0u,
          .has_radio_port = (cli.radio_port >= 0) ? 1u : 0u,
          .link_id = (int16_t)cli.link_id,
          .radio_port = (int16_t)cli.radio_port,
          .txf_spec = cli.tx_filter_spec
        };
        uint8_t filter_buf[512];
        int filter_sz = wfbx_rx_filter_info_pack(filter_buf, sizeof(filter_buf), &filters);
        if (filter_sz <= 0 || append_section(payload, &payload_off, sizeof(payload), WFBX_RX_SECTION_FILTERS, filter_buf, (uint16_t)filter_sz) != 0) {
          fprintf(stderr, "[STATS] RX filter section append failed\n");
          build_failed = true;
        } else {
          section_count++;
        }
      }

      if (tx_payload) free(tx_payload);
      if (if_payload) free(if_payload);

      if (!build_failed && payload_off + WFBX_STATS_HEADER_SIZE <= WFBX_RX_STATS_MAX_PACKET) {
        wfbx_stats_header_t header;
        wfbx_stats_header_init(&header, 1, WFBX_MODULE_RX, g_rx_stats_module_id,
                               NULL,
                               g_rx_stats_tick_id++, mono_us_raw(), 0, section_count, (uint32_t)payload_off);
        uint8_t header_buf[WFBX_STATS_HEADER_SIZE];
        if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &header) == 0) {
          memcpy(g_rx_stats_packet, header_buf, WFBX_STATS_HEADER_SIZE);
          memcpy(g_rx_stats_packet + WFBX_STATS_HEADER_SIZE, payload, payload_off);
          g_rx_stats_packet_len = WFBX_STATS_HEADER_SIZE + payload_off;
          header.crc32 = wfbx_stats_crc32(g_rx_stats_packet, g_rx_stats_packet_len);
          if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &header) == 0)
            memcpy(g_rx_stats_packet, header_buf, WFBX_STATS_HEADER_SIZE);
          if (stat_sock >= 0) {
            stats_send_packet(stat_sock, &stat_addr);
          } else {
            fprintf(stderr, "[STATS] stat_sock < 0, skip send\n");
          }
        } else {
          g_rx_stats_packet_len = 0;
        }
      } else {
        if (build_failed)
          fprintf(stderr, "[STATS] RX build_failed, skipping send\n");
        else
          fprintf(stderr, "[STATS] RX packet too large (%zu)\n", payload_off + WFBX_STATS_HEADER_SIZE);
        g_rx_stats_packet_len = 0;
      }

      /* reset period (keep per-TX/iface/chain expect_seq across periods) */
      t0 = t1;
      bytes_period = 0;
      rx_pkts_period = 0;
      
      for (int t = 0; t < MAX_TX_IDS; ++t) {
        G[t].lost    = 0;     /* clear per-TX period losses */
        pkts_tx[t]   = 0;     /* clear per-TX period packets */
        bytes_tx[t]  = 0;     /* clear per-TX period bytes */
      for (int a=0; a<n_open; ++a)
        for (int c=0; c<RX_ANT_MAX; ++c) {
          PC[t][a][c].lost = 0;          /* clear per-chain period losses (keep expect_seq) */
          ant_stats_clear(&ATX[t][a][c]);/* clear per-chain RSSI stats */
        }
      for (int a=0; a<n_open; ++a) {
        IFSTAT[t][a].lost = 0;
        IFSTAT[t][a].packets = 0;
      }
      }
      
      rssi_min = 127; rssi_max = -127; rssi_sum = 0; rssi_samples = 0;
      ant_stats_reset(A, n_open); /* keep global stats reset behavior, if still used elsewhere */
    }
  }

  for (int i=0;i<n_open;i++) if (ph[i]) pcap_close(ph[i]);
  close(us);
  if (stat_sock >= 0) close(stat_sock);
  return 0;
}

static void stats_send_packet(int sock, const struct sockaddr_in* addr)
{
  if (sock < 0 || !addr) return;
  if (g_rx_stats_packet_len == 0) return;
  char ipbuf[INET_ADDRSTRLEN];
  const char* ip = inet_ntop(AF_INET, &addr->sin_addr, ipbuf, sizeof(ipbuf));
  if (!ip) ip = "?";
  ssize_t sent = sendto(sock, g_rx_stats_packet, g_rx_stats_packet_len, 0,
                        (const struct sockaddr*)addr, sizeof(*addr));
  if (sent < 0) {
    perror("stats sendto");
    fprintf(stderr, "[STATS] sendto failed len=%zu dest=%s:%d\n",
            g_rx_stats_packet_len, ip, ntohs(addr->sin_port));
  } else {
    fprintf(stderr, "[STATS] sendto ok sent=%zd len=%zu dest=%s:%d\n",
            sent, g_rx_stats_packet_len, ip, ntohs(addr->sin_port));
  }
}
