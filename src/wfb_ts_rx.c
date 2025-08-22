// wfb_rx.c — multi-interface 802.11 capture (monitor mode) -> UDP (configurable)
// - Supports multiple WLAN interfaces (positional args): receive diversity
// - A frame is accepted if received on at least one interface (dedup by 12-bit seq)
// - Per-antenna stats labeled ANTabc: a=iface index, bc=antenna index (00..99)
// - CLI: --ip, --port, --tx_id, --link_id, --radio_port, --stat_period, --help
// - TX filter supports: "any"/-1 (accept all), include-list "1,2,5,10-12", exclude-list "!3,7,20-25"
// - Periodic stats (default 1000 ms or --stat_period):
//     Global: packets, bytes, kbps, lost, quality, RSSI(best-chain) min/avg/max
//     Per-antenna (per interface): pkts, lost, quality, RSSI min/avg/max

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
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

#ifndef TS_TAIL_BYTES
#define TS_TAIL_BYTES 8u  /* t0_ns tail size in bytes */
#endif

#include "wfb_defs.h"

/* ---- Defaults ---- */
#ifndef STATS_PERIOD_MS_DEFAULT
#define STATS_PERIOD_MS_DEFAULT 1000
#endif
#define MAX_IFS 8

static const char* g_dest_ip_default   = "127.0.0.1";
static const int   g_dest_port_default = 5600;

/* Monotonic milliseconds */
static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

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
  int radio_port;
  int stat_period_ms;
};

static void print_help(const char* prog)
{
  printf(
    "Usage: sudo %s [options] <wlan_iface1> [<wlan_iface2> ...]\n"
    "Options:\n"
    "  --ip <addr>         UDP destination IP (default: %s)\n"
    "  --port <num>        UDP destination port (default: %d)\n"
    "  --tx_id <spec>      Filter by transmitter IDs:\n"
    "                     'any' or '-1'               → accept all\n"
    "                      include list '1,2,5,10-12' → accept only listed IDs\n"
    "                      exclude list '!3,7,20-25   → accept all except listed IDs'\n"
    "                      (NOTE: use quotes or escape '!' in bash: --tx_id '!0,7' or --tx_id '\'!0,7)\n" 
    "                      (default: 0 — only tx_id=0)\n"
    "  --link_id <id>      Filter by Link ID (addr3[4]); -1 disables filter (default: 0)\n"
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
  cfg->link_id = 0;
  cfg->radio_port = 0;
  cfg->n_if = 0;
  cfg->stat_period_ms = STATS_PERIOD_MS_DEFAULT;

  static struct option longopts[] = {
    {"ip",           required_argument, 0, 0},
    {"port",         required_argument, 0, 0},
    {"tx_id",        required_argument, 0, 0},
    {"link_id",      required_argument, 0, 0},
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
      else if (strcmp(name,"tx_id")==0)        txf_parse(&cfg->txf, val);
      else if (strcmp(name,"link_id")==0)      cfg->link_id = atoi(val);
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

  /* Open PCAP for each interface */
  pcap_t* ph[MAX_IFS] = {0};
  int fds[MAX_IFS]; for (int i=0;i<MAX_IFS;i++) fds[i] = -1;
  int n_open = 0;
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  for (int i=0;i<cli.n_if; ++i) {
    pcap_t* p = pcap_create(cli.ifname[i], errbuf);
    if (!p) { fprintf(stderr, "pcap_create(%s): %s\n", cli.ifname[i], errbuf); continue; }
    (void)pcap_set_immediate_mode(p, 1);
    (void)pcap_setnonblock(p, 1, errbuf);
    if (pcap_activate(p) != 0) {
      fprintf(stderr, "pcap_activate(%s): %s\n", cli.ifname[i], pcap_geterr(p));
      pcap_close(p); continue;
    }
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
  fprintf(stderr, " -> UDP %s:%d | stats %d ms | filters: TX=%s LINK=%d PORT=%d\n",
          cli.ip, cli.port, cli.stat_period_ms,
          (cli.txf.mode==TXF_ANY?"any":(cli.txf.mode==TXF_INCLUDE?"include":"exclude")),
          cli.link_id, cli.radio_port);

  /* Global period accumulators */
  uint64_t t0 = now_ms();
  uint64_t bytes_period = 0;
  uint32_t rx_pkts_period = 0;
  int rssi_min =  127;
  int rssi_max = -127;
  int64_t rssi_sum = 0;
  uint32_t rssi_samples = 0;
  int have_seq = 0;
  uint16_t expect_seq = 0;
  uint32_t lost_period = 0;

  /* Per-antenna per-interface accumulators */
  struct ant_stats A[MAX_IFS][RX_ANT_MAX];
  ant_stats_reset(A, n_open);

  /* Global dedup window */
  struct seq_window W; seqwin_init(&W);

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
        // rx time_stamp
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        uint64_t rx_ns_host = (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;

        struct rt_stats rs;
        if (parse_radiotap_rx(pkt, hdr->caplen, &rs) != 0) continue;

        struct wfb_pkt_view v;
        if (extract_dot11(pkt, hdr->caplen, &rs, &v) != 0) continue;

        /* filters */
        uint8_t tx_id      = v.h->addr2[5];
        uint8_t link_id    = v.h->addr3[4];
        uint8_t radio_port = v.h->addr3[5];
        if (!txf_match(&cli.txf, tx_id)) continue;
        if (cli.link_id    >= 0 && link_id    != (uint8_t)cli.link_id)    continue;
        if (cli.radio_port >= 0 && radio_port != (uint8_t)cli.radio_port) continue;

        /* --- Extract t0 tail (8 bytes ns) from the END of payload --- */
        uint64_t t0_ns = 0;
        int has_t0 = 0;
        if (v.payload_len >= TS_TAIL_BYTES) {
        uint64_t t0_le;
        memcpy(&t0_le, v.payload + (v.payload_len - TS_TAIL_BYTES), TS_TAIL_BYTES);
        t0_ns = le64toh(t0_le);
        has_t0 = 1;
        }

        /* --- Per-packet Δt print (per interface) --- */
        if (rs.has_tsft && has_t0) {
            int64_t dt_us = (int64_t)rs.tsft_us - (int64_t)(t0_ns / 1000ull);
            /* iface_index = i ph[i]) */
            fprintf(stderr, "[DT] iface=%d seq=%u dt_us=%" PRId64 " tsft_us=%" PRIu64 " t0_ns=%" PRIu64 "\n",
            i, v.seq12, dt_us, (uint64_t)rs.tsft_us, (uint64_t)t0_ns);
        }
        else
        {   
           int64_t dt_us_host = (int64_t)(rx_ns_host/1000ull) - (int64_t)(t0_ns/1000ull);
           fprintf(stderr, "[DT] iface=%d seq=%u dt_us=%" PRId64 " (HOST)\n", i, v.seq12, dt_us_host);
        }
        

        /* dedup by seq */
        int dup = seqwin_check_set(&W, v.seq12);
        if (!dup) {
          if (!have_seq) { have_seq = 1; expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF); }
          else {
            if (v.seq12 != expect_seq) {
              uint16_t gap = (uint16_t)((v.seq12 - expect_seq) & 0x0FFF);
              lost_period += gap;
              expect_seq = (uint16_t)((v.seq12 + 1) & 0x0FFF);
            } else {
              expect_seq = (uint16_t)((expect_seq + 1) & 0x0FFF);
            }
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
          /* forward once */
          size_t out_len = v.payload_len;
          if (has_t0 && out_len >= TS_TAIL_BYTES) out_len -= TS_TAIL_BYTES;

          if (out_len > 0) {
          (void)sendto(us, v.payload, out_len, 0, (struct sockaddr*)&dst, sizeof(dst));
          }


          //(void)sendto(us, v.payload, v.payload_len, 0, (struct sockaddr*)&dst, sizeof(dst));
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
      double kbps = seconds > 0.0 ? (bytes_period * 8.0 / 1000.0) / seconds : 0.0;
      uint32_t expected = rx_pkts_period + lost_period;
      int quality = expected ? (int)((rx_pkts_period * 100.0) / expected + 0.5) : 100;
      double rssi_avg = (rssi_samples > 0) ? ((double)rssi_sum / (double)rssi_samples) : 0.0;
      if (rssi_samples == 0) { rssi_min = 0; rssi_max = 0; }

      fprintf(stderr,
        "[STATS] dt=%llu ms | pkts=%u lost=%u quality=%d%% | bytes=%llu rate=%.1f kbps | RSSI best-chain min/avg/max = %d/%.1f/%d dBm\n",
        (unsigned long long)(t1 - t0), rx_pkts_period, lost_period, quality,
        (unsigned long long)bytes_period, kbps,
        rssi_min, rssi_avg, rssi_max);

      for (int a=0; a<n_open; ++a) {
        for (int c=0; c<RX_ANT_MAX; ++c) {
          const struct ant_stats* S = &A[a][c];
          if (S->rssi_samples == 0 && S->lost == 0) continue;
          uint32_t exp_i = S->rssi_samples + S->lost;
          int qual_i = exp_i ? (int)((S->rssi_samples * 100.0) / exp_i + 0.5) : 100;
          double avg_i = (S->rssi_samples > 0) ? ((double)S->rssi_sum / (double)S->rssi_samples) : 0.0;
          int min_i = (S->rssi_samples > 0) ? S->rssi_min : 0;
          int max_i = (S->rssi_samples > 0) ? S->rssi_max : 0;
          fprintf(stderr, "   [ANT%1d%02d] pkts=%u lost=%u quality=%d%% | rssi min/avg/max = %d/%.1f/%d dBm\n",
                  a, c, S->rssi_samples, S->lost, qual_i, min_i, avg_i, max_i);
        }
      }

      /* reset period */
      t0 = t1;
      bytes_period = 0;
      rx_pkts_period = 0;
      lost_period = 0;
      rssi_min = 127; rssi_max = -127; rssi_sum = 0; rssi_samples = 0;
      ant_stats_reset(A, n_open);
    }
  }

  for (int i=0;i<n_open;i++) if (ph[i]) pcap_close(ph[i]);
  close(us);
  return 0;
}