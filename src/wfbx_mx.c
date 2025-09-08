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
#include <sys/un.h>
#include <fcntl.h>

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
struct ant_stats {
  uint8_t ant_id;          /* radiotap ANTENNA (last seen) */
  int rssi_min;
  int rssi_max;
  int64_t rssi_sum;
  uint32_t rssi_samples;
  /* Per-chain loss tracking (optional) */
  int have_seq;
  uint16_t expect_seq;
  uint32_t lost;
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

/* Per-interface detail within a TX */
struct if_detail {
  uint64_t pkts;
  /* interface-level loss tracking */
  int have_seq;
  uint16_t expect_seq;
  uint32_t lost;
  /* per-chain */
  struct ant_stats ant[RX_ANT_MAX];
  /* per-interface epoch metrics for this TX */
  struct epoch_stats es;
};

/* Per-TX aggregate across interfaces */
struct tx_detail {
  uint64_t unique_pkts;       /* dedup across ifaces */
  struct if_detail ifs[MAX_IFS];
  struct epoch_stats es_overall; /* earliest-arrival based */
  /* Global loss across interfaces (on deduped stream) */
  int have_seq_glob;
  uint16_t expect_seq_glob;
  uint32_t lost_glob;
};

static struct tx_stats TX[MAX_TX_IDS];
static struct if_stats IFST[MAX_IFS];
static struct tx_detail TXD[MAX_TX_IDS];
static struct seq_window SWG[MAX_TX_IDS];

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
    /* zero per-TX epoch aggregates */
    memset(&TXD[t].es_overall, 0, sizeof(TXD[t].es_overall));
    TXD[t].have_seq_glob = 0;
    TXD[t].expect_seq_glob = 0;
    TXD[t].lost_glob = 0;
    for (int i=0;i<n_if;i++) {
      struct if_detail* D = &TXD[t].ifs[i];
      D->pkts = 0; D->have_seq = 0; D->expect_seq = 0; D->lost = 0;
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
static __attribute__((unused)) void txf_clear_all(struct txid_filter* f){ f->map[0]=f->map[1]=f->map[2]=f->map[3]=0; }
static __attribute__((unused)) int txf_match(const struct txid_filter* f, uint8_t tx){ (void)tx; return f->mode==TXF_ANY ? 1 : 1; }

static volatile int g_run = 1; static void on_sigint(int){ g_run = 0; }

struct cli_cfg {
  int n_if; const char* ifname[MAX_IFS];
  const char* ip; int port; struct txid_filter txf; int stat_period_ms;
  /* Mesh time sync params */
  double alpha;    /* EMA coefficient */
  int    tau_us;   /* propagation (us) */
  int    delta_us; /* stack latency (us) */
  /* Control channel */
  const char* ctrl_addr;    /* abstract UDS address (e.g. @wfbx.mx) */
  uint32_t epoch_len_us;    /* publish superframe length */
  uint32_t epoch_gi_us;     /* publish inter-superframe guard */
  double  d_max_km;         /* max distance (km) ⇒ tau_us */
};

static void print_help(const char* prog)
{
  printf("Usage: sudo %s [options] <wlan_iface1> [<wlan_iface2> ...>\n"
         "Options:\n"
         "  --ip <addr>         UDP destination IP (default: %s)\n"
         "  --port <num>        UDP destination port (default: %d)\n"
         "  --alpha <0..1>      EMA coefficient for T_epoch (default: 0.3)\n"
         "  --delta_us <num>    Stack latency in us (default: 1500)\n"
         "  --ctrl <@name>      Control UDS abstract address (default: @wfbx.mx)\n"
         "  --d_max <km>        Max distance in km (sets tau_us = round(d_max*3.335641))\n"
         "  --stat_period <ms>  Stats period in milliseconds (default: %d)\n"
         "  --help              Show this help and exit\n",
         prog, g_dest_ip_default, g_dest_port_default, 1000);
}

static int parse_cli(int argc, char** argv, struct cli_cfg* cfg)
{
  cfg->ip = g_dest_ip_default; cfg->port = g_dest_port_default; cfg->n_if = 0; cfg->stat_period_ms = 1000; cfg->txf.mode = TXF_ANY;
  cfg->alpha = 0.3; cfg->tau_us = 0; cfg->delta_us = 700; cfg->ctrl_addr = "@wfbx.mx"; cfg->epoch_len_us = 0; cfg->epoch_gi_us = 0; cfg->d_max_km = 0.0;
  static struct option longopts[] = {
    {"ip",           required_argument, 0, 0},
    {"port",         required_argument, 0, 0},
    {"alpha",        required_argument, 0, 0},
    {"delta_us",     required_argument, 0, 0},
    {"ctrl",         required_argument, 0, 0},
    {"d_max",        required_argument, 0, 0},
    {"stat_period",  required_argument, 0, 0},
    {"help",         no_argument,       0, 0},
    {0,0,0,0}
  };
  int optidx = 0; while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx); if (c==-1) break; if (c==0) {
      const char* name = longopts[optidx].name; const char* val = optarg?optarg:"";
      if      (strcmp(name,"ip")==0)          cfg->ip = val;
      else if (strcmp(name,"port")==0)        cfg->port = atoi(val);
      else if (strcmp(name,"alpha")==0)       cfg->alpha = atof(val);
      else if (strcmp(name,"delta_us")==0)    cfg->delta_us = atoi(val);
      else if (strcmp(name,"ctrl")==0)        cfg->ctrl_addr = val;
      else if (strcmp(name,"d_max")==0)       cfg->d_max_km = atof(val);
      else if (strcmp(name,"stat_period")==0) cfg->stat_period_ms = atoi(val);
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
  fprintf(stderr, " | UDP %s:%d | stat %d ms | alpha=%.2f delta_us=%d tau_us=%d | ctrl=%s\n",
          cli.ip, cli.port, cli.stat_period_ms, cli.alpha, cli.delta_us, cli.tau_us,
          cli.ctrl_addr);

  uint64_t t0 = now_ms();
  uint64_t pkts = 0;
  /* Init dedup windows per TX and reset per-period stats */
  for (int t=0;t<MAX_TX_IDS;++t) seqwin_init(&SWG[t]);
  stats_reset_period(n_open);
  /* Epoch estimation state */
  int have_epoch = 0;
  uint64_t epoch_hat_us = 0; /* T̂_epoch */
  /* Real delta_us statistics */
  int64_t real_delta_sum = 0;
  int64_t real_delta_min = INT64_C(0);
  int64_t real_delta_max = INT64_C(0);
  uint64_t real_delta_samples = 0;
  /* Residual e_us = T_epoch_instant - T̂_epoch statistics */
  int64_t e_us_sum = 0;
  int64_t e_us_min = INT64_C(0);
  int64_t e_us_max = INT64_C(0);
  uint64_t e_us_samples = 0;
  /* e_delta = delta_us - real_delta_us statistics */
  int64_t e_delta_sum = 0;
  int64_t e_delta_min = INT64_C(0);
  int64_t e_delta_max = INT64_C(0);
  uint64_t e_delta_samples = 0;
  /* Epoch vs TX-epoch statistics */
  int64_t e_epoch_inst_sum = 0;
  int64_t e_epoch_inst_min = INT64_C(0);
  int64_t e_epoch_inst_max = INT64_C(0);
  uint64_t e_epoch_inst_samples = 0;
  int64_t e_epoch_hat_sum = 0;
  int64_t e_epoch_hat_min = INT64_C(0);
  int64_t e_epoch_hat_max = INT64_C(0);
  uint64_t e_epoch_hat_samples = 0;

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

  while (g_run) {
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

    for (int i=0;i<n_open;i++) {
      if (fds[i] < 0) continue;
      if (sel == 0 || !FD_ISSET(fds[i], &rfds)) continue;
      while (1) {
        struct pcap_pkthdr* hdr = NULL; const u_char* pkt = NULL; int rc = pcap_next_ex(ph[i], &hdr, &pkt); if (rc <= 0) break;
        struct rt_stats rs; if (parse_radiotap_rx(pkt, hdr->caplen, &rs) != 0) continue;
        struct wfb_pkt_view v; if (extract_dot11(pkt, hdr->caplen, &rs, &v) != 0) continue;

        /* Local RX software timestamp (end of delivery) */
        uint64_t t_loc_us = mono_us_raw();

        /* New trailer: last 8B = T_pkt_send_TX_us (driver), previous 8B = T_epoch_TX_us (app) */
        uint32_t TS_tx_us = 0; int have_ts_tx = 0;
        uint64_t epoch_tx_us = 0; int have_epoch_tx = 0;
        uint64_t t_send_tx_us = 0;
        size_t trailer_found = 0;
        if (v.payload_len >= 16) {
          uint64_t epoch_le, send_le;
          memcpy(&epoch_le, v.payload + (v.payload_len - 16), 8);
          memcpy(&send_le,  v.payload + (v.payload_len - 8),  8);
          epoch_tx_us = le64toh(epoch_le); have_epoch_tx = 1;
          t_send_tx_us = le64toh(send_le);
          TS_tx_us = (uint32_t)(t_send_tx_us - epoch_tx_us);
          have_ts_tx = 1;
          trailer_found = 16;
        }

        /* Compute airtime from actual PHY (HT) */
        uint32_t A_us = airtime_us_rx(v.payload_len, &rs);

        /* Identify TX/IF */
        uint8_t tx_id = v.h ? v.h->addr2[5] : 0;
        struct if_detail* DID = &TXD[tx_id].ifs[i];

        /* Per-interface packet/radio stats + per-chain */
        DID->pkts++;
        for (int c=0;c<rs.chains && c<RX_ANT_MAX; ++c) {
          if (rs.rssi[c] == SCHAR_MIN) continue;
          struct ant_stats* AS = &DID->ant[c];
          int r = rs.rssi[c];
          if (r < AS->rssi_min) AS->rssi_min = r;
          if (r > AS->rssi_max) AS->rssi_max = r;
          AS->rssi_sum += r; AS->rssi_samples++;
          AS->ant_id = rs.antenna[c];
          /* per-chain sequence loss (update only when chain present) */
          if (!AS->have_seq) { AS->have_seq = 1; AS->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF); }
          else {
            if (v.seq12 != AS->expect_seq) { uint16_t gap = (uint16_t)((v.seq12 - AS->expect_seq) & 0x0FFF); AS->lost += gap; AS->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF); }
            else { AS->expect_seq = (uint16_t)((AS->expect_seq + 1) & 0x0FFF); }
          }
        }
        /* per-interface sequence loss */
        if (!DID->have_seq) { DID->have_seq = 1; DID->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF); }
        else {
          if (v.seq12 != DID->expect_seq) { uint16_t gap = (uint16_t)((v.seq12 - DID->expect_seq) & 0x0FFF); DID->lost += gap; DID->expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF); }
          else { DID->expect_seq = (uint16_t)((DID->expect_seq + 1) & 0x0FFF); }
        }

        /* Epoch metrics for this (TX,IF) */
        if (have_ts_tx) {
          int64_t inst = (int64_t)t_loc_us - (int64_t)cli.delta_us - (int64_t)A_us - (int64_t)cli.tau_us - (int64_t)TS_tx_us;
          uint64_t T_epoch_instant = (inst < 0) ? 0ull : (uint64_t)inst;
          int64_t real_du = (t_send_tx_us != 0) ? ((int64_t)t_loc_us - (int64_t)A_us - (int64_t)t_send_tx_us) : 0;
          int64_t e_d = (int64_t)cli.delta_us - real_du;
          int64_t e_e = (have_epoch_tx) ? ((int64_t)T_epoch_instant - (int64_t)epoch_tx_us) : 0;
          struct epoch_stats* ES = &DID->es;
          if (ES->epoch_samples == 0) { ES->epoch_min = T_epoch_instant; ES->epoch_max = T_epoch_instant; }
          if (T_epoch_instant < ES->epoch_min) ES->epoch_min = T_epoch_instant;
          if (T_epoch_instant > ES->epoch_max) ES->epoch_max = T_epoch_instant;
          ES->epoch_sum += T_epoch_instant; ES->epoch_samples++;
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
        }

        /* Per-TX global dedup for unique pkt + earliest-arrival epoch accumulation */
        int dup_global = seqwin_check_set(&SWG[tx_id], v.seq12);
        if (!dup_global) {
          /* Per-TX lightweight RSSI (best-chain over iface bests): use per-packet best over present chains */
          int pkt_best = -127; int have_pkt_best = 0;
          for (int c=0;c<rs.chains && c<RX_ANT_MAX; ++c) if (rs.rssi[c] != SCHAR_MIN) { if (!have_pkt_best || rs.rssi[c] > pkt_best) { pkt_best = rs.rssi[c]; have_pkt_best = 1; } }
          TX[tx_id].pkts++;
          if (have_pkt_best) {
            if (pkt_best < TX[tx_id].rssi_min) TX[tx_id].rssi_min = pkt_best;
            if (pkt_best > TX[tx_id].rssi_max) TX[tx_id].rssi_max = pkt_best;
            TX[tx_id].rssi_sum += pkt_best; TX[tx_id].rssi_samples++;
          }
          TXD[tx_id].unique_pkts++;
          /* Global (deduped) loss tracking for TX */
          if (!TXD[tx_id].have_seq_glob) {
            TXD[tx_id].have_seq_glob = 1;
            TXD[tx_id].expect_seq_glob = (uint16_t)((v.seq12 + 1) & 0x0FFF);
          } else {
            if (v.seq12 != TXD[tx_id].expect_seq_glob) {
              uint16_t gap = (uint16_t)((v.seq12 - TXD[tx_id].expect_seq_glob) & 0x0FFF);
              TXD[tx_id].lost_glob += gap;
              TXD[tx_id].expect_seq_glob = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            } else {
              TXD[tx_id].expect_seq_glob = (uint16_t)((TXD[tx_id].expect_seq_glob + 1) & 0x0FFF);
            }
          }
          if (have_ts_tx) {
            int64_t inst = (int64_t)t_loc_us - (int64_t)cli.delta_us - (int64_t)A_us - (int64_t)cli.tau_us - (int64_t)TS_tx_us;
            uint64_t T_epoch_instant = (inst < 0) ? 0ull : (uint64_t)inst;
            int64_t real_du = (t_send_tx_us != 0) ? ((int64_t)t_loc_us - (int64_t)A_us - (int64_t)t_send_tx_us) : 0;
            int64_t e_d = (int64_t)cli.delta_us - real_du;
            int64_t e_e = (have_epoch_tx) ? ((int64_t)T_epoch_instant - (int64_t)epoch_tx_us) : 0;
            struct epoch_stats* ES = &TXD[tx_id].es_overall;
            if (ES->epoch_samples == 0) { ES->epoch_min = T_epoch_instant; ES->epoch_max = T_epoch_instant; }
            if (T_epoch_instant < ES->epoch_min) ES->epoch_min = T_epoch_instant;
            if (T_epoch_instant > ES->epoch_max) ES->epoch_max = T_epoch_instant;
            ES->epoch_sum += T_epoch_instant; ES->epoch_samples++;
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
        (void)sendto(us, v.payload, fwd_len, 0, (struct sockaddr*)&dst, sizeof(dst));
        pkts++;
      }
    }

stats_tick:
    {
      uint64_t t1 = now_ms(); if (t1 - t0 >= (uint64_t)cli.stat_period_ms) {
        double avg_real_du = (real_delta_samples > 0) ? ((double)real_delta_sum / (double)real_delta_samples) : 0.0;
        double avg_e_us    = (e_us_samples > 0) ? ((double)e_us_sum / (double)e_us_samples) : 0.0;
        double avg_e_delta = (e_delta_samples > 0) ? ((double)e_delta_sum / (double)e_delta_samples) : 0.0;
        fprintf(stderr, "[MX] dt=%llu ms | pkts=%llu | ifaces=%d\n",
                (unsigned long long)(t1-t0), (unsigned long long)pkts, n_open);
        /* Per-TX blocks first; inside each TX print per-IF details */
        for (int tX=0;tX<MAX_TX_IDS;tX++) {
          int tx_active = (TX[tX].pkts>0) || (TXD[tX].unique_pkts>0);
          if (!tx_active) continue;
          double avg_tx_rssi = (TX[tX].rssi_samples>0) ? ((double)TX[tX].rssi_sum / (double)TX[tX].rssi_samples) : 0.0;
          struct epoch_stats* ES = &TXD[tX].es_overall;
          double avg_epoch = (ES->epoch_samples>0) ? ((double)ES->epoch_sum/(double)ES->epoch_samples) : 0.0;
          double avg_real  = (ES->real_delta_samples>0) ? ((double)ES->real_delta_sum/(double)ES->real_delta_samples) : 0.0;
          double avg_ed    = (ES->e_delta_samples>0) ? ((double)ES->e_delta_sum/(double)ES->e_delta_samples) : 0.0;
          double avg_ee    = (ES->e_epoch_samples>0) ? ((double)ES->e_epoch_sum/(double)ES->e_epoch_samples) : 0.0;
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
          /* TX-level QLT: based on deduped stream: unique / (unique + lost_glob) */
          uint64_t exp_tx_total = TXD[tX].unique_pkts + (uint64_t)TXD[tX].lost_glob;
          double qlt_tx = (exp_tx_total>0) ? (100.0 * (double)TXD[tX].unique_pkts / (double)exp_tx_total) : 0.0;
          fprintf(stderr, "  [TX %03d] upkts=%llu lost=%u qlt=%.1f%% | RSSI min=%d avg=%.1f max=%d\n",
                  tX,(unsigned long long)TXD[tX].unique_pkts,(unsigned)TXD[tX].lost_glob,qlt_tx,
                  (int)TX[tX].rssi_min,avg_tx_rssi,(int)TX[tX].rssi_max);
          /* Exclude epoch absolute values from stats output; keep timing error metrics only */
          fprintf(stderr, "      real_delta avg=%.1f min=%lld max=%lld n=%llu\n      e_delta avg=%.1f min=%lld max=%lld n=%llu\n      e_epoch avg=%.1f min=%lld max=%lld n=%llu\n",
                  avg_real,(long long)ES->real_delta_min,(long long)ES->real_delta_max,(unsigned long long)ES->real_delta_samples,
                  avg_ed,(long long)ES->e_delta_min,(long long)ES->e_delta_max,(unsigned long long)ES->e_delta_samples,
                  avg_ee,(long long)ES->e_epoch_min,(long long)ES->e_epoch_max,(unsigned long long)ES->e_epoch_samples);
          /* Then per-interface detail for this TX */
          for (int i2=0;i2<n_open;i2++) {
            struct if_detail* D = &TXD[tX].ifs[i2];
            if (D->pkts==0 && D->es.epoch_samples==0) continue;
            uint64_t exp_total = (uint64_t)D->pkts + (uint64_t)D->lost;
            double qlt = (exp_total>0) ? (100.0 * (double)D->pkts / (double)exp_total) : 0.0;
            /* Best chain avg on this iface */
            int best_chain_avg_if = -127; int best_chain_id = -1; int best_valid=0;
            for (int c=0;c<RX_ANT_MAX;c++) {
              struct ant_stats* AS = &D->ant[c];
              if (AS->rssi_samples>0) {
                int avgc = (int)((AS->rssi_sum + (AS->rssi_samples>0? (AS->rssi_samples/2):0)) / (AS->rssi_samples?AS->rssi_samples:1));
                if (!best_valid || avgc > best_chain_avg_if) { best_chain_avg_if = avgc; best_chain_id = AS->ant_id; best_valid=1; }
              }
            }
            fprintf(stderr, "    [IF %d] pkts=%llu lost=%u qlt=%.1f%% | bestChain=%s%d(avg %d dBm)\n",
                    i2,(unsigned long long)D->pkts,(unsigned)D->lost,qlt,
                    (best_valid?"ANT":"n/a "), best_valid?(int)best_chain_id:0, best_valid?best_chain_avg_if:0);
            /* Per-antenna stats */
            for (int c=0;c<RX_ANT_MAX;c++) {
              struct ant_stats* AS = &D->ant[c]; if (AS->rssi_samples==0) continue;
              double av = (double)AS->rssi_sum / (double)AS->rssi_samples;
              fprintf(stderr, "      ANTa%02d: rssi min=%d avg=%.1f max=%d | lost=%u\n",
                      (int)AS->ant_id,(int)AS->rssi_min,av,(int)AS->rssi_max,(unsigned)AS->lost);
            }
            /* Per-IF timing stats (exclude absolute epoch) */
            struct epoch_stats* EI = &D->es;
            double ar  = (EI->real_delta_samples>0)?((double)EI->real_delta_sum/(double)EI->real_delta_samples):0.0;
            double ad  = (EI->e_delta_samples>0)?((double)EI->e_delta_sum/(double)EI->e_delta_samples):0.0;
            double ae  = (EI->e_epoch_samples>0)?((double)EI->e_epoch_sum/(double)EI->e_epoch_samples):0.0;
            fprintf(stderr, "      real_delta avg=%.1f min=%lld max=%lld n=%llu\n      e_delta avg=%.1f min=%lld max=%lld n=%llu\n      e_epoch avg=%.1f min=%lld max=%lld n=%llu\n",
                    ar,(long long)EI->real_delta_min,(long long)EI->real_delta_max,(unsigned long long)EI->real_delta_samples,
                    ad,(long long)EI->e_delta_min,(long long)EI->e_delta_max,(unsigned long long)EI->e_delta_samples,
                    ae,(long long)EI->e_epoch_min,(long long)EI->e_epoch_max,(unsigned long long)EI->e_epoch_samples);
          }
        }
        fprintf(stderr, "      real_delta_us: avg=%.1f min=%lld max=%lld n=%llu\n",
                avg_real_du, (long long)real_delta_min, (long long)real_delta_max,
                (unsigned long long)real_delta_samples);
        fprintf(stderr, "      e_us:    avg=%.1f min=%lld max=%lld n=%llu\n      e_delta: avg=%.1f min=%lld max=%lld n=%llu\n",
                avg_e_us, (long long)e_us_min, (long long)e_us_max, (unsigned long long)e_us_samples,
                avg_e_delta, (long long)e_delta_min, (long long)e_delta_max, (unsigned long long)e_delta_samples);
        if (e_epoch_inst_samples > 0 || e_epoch_hat_samples > 0) {
          double avg_e_epoch_inst = (e_epoch_inst_samples > 0) ? ((double)e_epoch_inst_sum / (double)e_epoch_inst_samples) : 0.0;
          double avg_e_epoch_hat  = (e_epoch_hat_samples > 0)  ? ((double)e_epoch_hat_sum  / (double)e_epoch_hat_samples)  : 0.0;
          fprintf(stderr, "      e_epoch_instant: avg=%.1f min=%lld max=%lld n=%llu\n      e_epoch_hat:     avg=%.1f min=%lld max=%lld n=%llu\n",
                  avg_e_epoch_inst, (long long)e_epoch_inst_min, (long long)e_epoch_inst_max, (unsigned long long)e_epoch_inst_samples,
                  avg_e_epoch_hat,  (long long)e_epoch_hat_min,  (long long)e_epoch_hat_max,  (unsigned long long)e_epoch_hat_samples);
        }
        t0 = t1; pkts = 0;
        /* Reset per-period iface/tx stats */
        stats_reset_period(n_open);
        real_delta_sum = 0; real_delta_samples = 0;
        e_us_sum = 0; e_us_samples = 0;
        e_delta_sum = 0; e_delta_samples = 0;
        e_epoch_inst_sum = 0; e_epoch_inst_samples = 0;
        e_epoch_hat_sum = 0;  e_epoch_hat_samples = 0;

        /* Publish EPOCH to subscribers (smoothed); send only T_epoch for now */
        if (cs >= 0 && have_epoch) {
          struct wfbx_ctrl_epoch m; memset(&m, 0, sizeof(m));
          m.h.magic = WFBX_CTRL_MAGIC; m.h.ver = WFBX_CTRL_VER; m.h.type = WFBX_CTRL_EPOCH; m.h.seq = ++epoch_seq;
          m.epoch_us = epoch_hat_us; m.epoch_len_us = 0; m.epoch_gi_us = 0; m.issued_us = mono_us_raw();
          for (int k=0;k<64;k++) if (subs[k].active) (void)sendto(cs, &m, sizeof(m), 0, (struct sockaddr*)&subs[k].sa, subs[k].sl);
        }
      }
    }
  }

  for (int i=0;i<n_open;i++) if (ph[i]) pcap_close(ph[i]);
  close(us);
  return 0;
}
