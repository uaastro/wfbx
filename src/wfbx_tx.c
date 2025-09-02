// wfbx_tx.c — UDP -> 802.11 injection ....
// Preserves CLI and behavior of udp2wfb.c; uses shared defs from wfb_defs.h.
// Build: gcc -O2 -Wall -o wfbx_tx wfbx_tx.c -lpcap

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/types.h>
#include <pthread.h>
#include <math.h>

#ifdef __linux__
  #include <endian.h>
#else
  #include <sys/endian.h>
#endif

#ifndef htole16
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define htole16(x) (x)
    #define htole32(x) (x)
  #else
    #define htole16(x) __builtin_bswap16(x)
    #define htole32(x) __builtin_bswap32(x)
  #endif
#endif

// Fallback for htole64 on systems where it's missing.
// Converts a 64-bit host-order value to little-endian representation.
#ifndef htole64
  #if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define htole64(x) (x)
  #else
    #define htole64(x) __builtin_bswap64((uint64_t)(x))
  #endif
#endif

#include "wfb_defs.h"

#define MAX_FRAME        4096
#define MAX_UDP_PAYLOAD  2000

/* ---- Radiotap TX header (packed) ---- */
#pragma pack(push,1)
struct rt_tx_hdr {
  uint8_t  it_version;
  uint8_t  it_pad;
  uint16_t it_len;
  uint32_t it_present;
  uint16_t tx_flags;   /* WFB_TXF_* */
  uint8_t  mcs_known;  /* WFB_MCS_KNOWN_* */
  uint8_t  mcs_flags;  /* WFB_MCS_FLAGS_* */
  uint8_t  mcs_index;  /* 0..31 */
};
#pragma pack(pop)

/* ---- helpers ---- */
static volatile sig_atomic_t g_run = 1;
static void on_sigint(int){ g_run = 0; }

static void mac_set(uint8_t m[6], uint8_t a0,uint8_t a1,uint8_t a2,uint8_t a3,uint8_t a4,uint8_t a5){
  m[0]=a0; m[1]=a1; m[2]=a2; m[3]=a3; m[4]=a4; m[5]=a5;
}
static void build_addr1_group(uint8_t a[6], uint8_t group_id){
  /* addr1 → group_id (who in broadcast scheme) */
  mac_set(a, 0x02,0x11,0x22, 0x10, 0x00, group_id);
}
static void build_addr2_tx(uint8_t a[6], uint8_t tx_id){
  /* addr2 → transmitter_id (who sent) */
  mac_set(a, 0x02,0x11,0x22, 0x20, 0x00, tx_id);
}
static void build_addr3_link_port(uint8_t a[6], uint8_t link_id, uint8_t radio_port){
  /* addr3 → link_id / radio_port (logical stream) */
  mac_set(a, 0x02,0x11,0x22, 0x30, link_id, radio_port);
}

static uint8_t mcs_flags_from_args(int gi_short, int bw40, int ldpc, int stbc) {
  uint8_t f = 0;
  if (bw40)      f |= WFB_MCS_FLAGS_BW40;   /* 0=20,1=40 */
  if (gi_short)  f |= WFB_MCS_FLAGS_SGI;
  if (ldpc)      f |= WFB_MCS_FLAGS_LDPC;
  if (stbc < 0) stbc = 0;
  if (stbc > 3) stbc = 3;
  f |= (uint8_t)(stbc << WFB_MCS_FLAGS_STBC_SHIFT);
  return f;
}

/* Build radiotap TX header */
static size_t build_radiotap(uint8_t *out, uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc)
{
  struct rt_tx_hdr rt;
  memset(&rt, 0, sizeof(rt));
  rt.it_version = 0;
  rt.it_len     = htole16((uint16_t)sizeof(rt));
  rt.it_present = htole32((1u<<IEEE80211_RADIOTAP_TX_FLAGS) | (1u<<IEEE80211_RADIOTAP_MCS));

  /* Always set: NOACK + NOSEQ + NOAGG + FIXED RATE */
  rt.tx_flags   = htole16(WFB_TXF_NOACK | WFB_TXF_NOSEQ | WFB_TXF_NOAGG | WFB_TXF_FIXED_RATE);

  rt.mcs_known  = (uint8_t)(WFB_MCS_KNOWN_BW | WFB_MCS_KNOWN_MCS | WFB_MCS_KNOWN_GI |
                            WFB_MCS_KNOWN_FEC | WFB_MCS_KNOWN_STBC);
  rt.mcs_flags  = mcs_flags_from_args(gi_short, bw40, ldpc, stbc);
  rt.mcs_index  = mcs_idx;

  memcpy(out, &rt, sizeof(rt));
  return sizeof(rt);
}

/* Build 802.11 Data header */
static size_t build_dot11(uint8_t* out, uint16_t seq, uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port)
{
  struct wfb_dot11_hdr h;
  memset(&h, 0, sizeof(h));
  h.frame_control = htole16(0x0008); /* Data, ToDS/FromDS=0 */
  h.duration      = 0;
  build_addr1_group(h.addr1, group_id);
  build_addr2_tx(h.addr2, tx_id);
  build_addr3_link_port(h.addr3, link_id, radio_port);
  h.seq_ctrl = htole16((uint16_t)((seq & 0x0fff) << 4));
  memcpy(out, &h, sizeof(h));
  return sizeof(h);
}

/* Forward declaration for send_packet used by scheduler */
static int send_packet(pcap_t* ph,
                       const uint8_t* payload, size_t payload_len, uint16_t seq_num,
                       uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc,
                       uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port);

static uint64_t mono_ns_raw(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}


static inline uint64_t mono_us_raw(void) { return mono_ns_raw() / 1000ull; }

static uint64_t g_epoch_start_us = 0; /* T_epoch start since process start (mono raw, us) */

/* Mesh timing params (TX side) */
static uint32_t g_epoch_len_us = 50000;
static uint32_t g_epoch_gi_us  = 400;
static uint32_t g_slot_start_us = 0;
static uint32_t g_slot_len_us   = 50000;
static uint32_t g_gi_tx_us      = 400;
static uint32_t g_delta_us      = 1500;
static uint32_t g_tau_max_us    = 0;
static uint32_t g_eps_us        = 250;
static double   g_d_max_km      = 0.0; /* CLI: max distance; drives g_tau_max_us */

/* Control socket (UDS DGRAM) */
static int g_cs = -1;
static struct sockaddr_un g_tx_addr; static socklen_t g_tx_addr_len;
static struct sockaddr_un g_mx_addr; static socklen_t g_mx_addr_len;
static char g_tx_name[108] = {0};
static char g_mx_name[108] = {0};
static uint32_t g_ctrl_seq = 0;
static int g_ctrl_enabled = 0; /* control sync disabled by default */

static void uds_build_addr(const char* name_in, struct sockaddr_un* sa, socklen_t* sl_out, char* out_norm, size_t out_sz)
{
  if (!sa || !sl_out) return;
  memset(sa, 0, sizeof(*sa)); sa->sun_family = AF_UNIX;
  const char* nm = name_in ? name_in : "@wfbx.mx";
  if (nm[0] == '@') nm++;
  if (out_norm && out_sz) { snprintf(out_norm, out_sz, "%s", (nm && *nm)?nm:"wfbx"); }
  sa->sun_path[0] = '\0';
  if (nm && *nm) strncpy(sa->sun_path+1, nm, sizeof(sa->sun_path)-2);
  *sl_out = (socklen_t)offsetof(struct sockaddr_un, sun_path) + 1 + (socklen_t)strlen(nm?nm:"");
}

static int ctrl_init(const char* mx_name, uint8_t tx_id)
{
  if (!g_ctrl_enabled) return 0;
  g_cs = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (g_cs < 0) return -1;
  pid_t pid = getpid();
  char local[96]; snprintf(local, sizeof(local), "@wfbx.tx.%u.%d", (unsigned)tx_id, (int)pid);
  uds_build_addr(local, &g_tx_addr, &g_tx_addr_len, g_tx_name, sizeof(g_tx_name));
  if (bind(g_cs, (struct sockaddr*)&g_tx_addr, g_tx_addr_len) != 0) { perror("ctrl bind"); close(g_cs); g_cs=-1; return -1; }
  int fl = fcntl(g_cs, F_GETFL, 0); if (fl >= 0) fcntl(g_cs, F_SETFL, fl | O_NONBLOCK);
  uds_build_addr(mx_name?mx_name:"@wfbx.mx", &g_mx_addr, &g_mx_addr_len, g_mx_name, sizeof(g_mx_name));
  /* Send SUB */
  struct wfbx_ctrl_sub sub; memset(&sub, 0, sizeof(sub));
  sub.h.magic = WFBX_CTRL_MAGIC; sub.h.ver = WFBX_CTRL_VER; sub.h.type = WFBX_CTRL_SUB; sub.h.seq = ++g_ctrl_seq;
  sub.tx_id = tx_id;
  /* Safely prefix '@' and cap length to avoid truncation warnings */
  size_t maxcopy = sizeof(sub.name) - 2; /* '@' + up to maxcopy chars + NUL */
  snprintf(sub.name, sizeof(sub.name), "@%.*s", (int)maxcopy, g_tx_name);
  (void)sendto(g_cs, &sub, sizeof(sub), 0, (struct sockaddr*)&g_mx_addr, g_mx_addr_len);
  return 0;
}

static __attribute__((unused)) void ctrl_drain(void)
{
  if (!g_ctrl_enabled) return;
  if (g_cs < 0) return;
  uint8_t buf[256];
  ssize_t n;
  while ((n = recv(g_cs, buf, sizeof(buf), 0)) > 0) {
    if ((size_t)n >= sizeof(struct wfbx_ctrl_hdr)) {
      const struct wfbx_ctrl_hdr* h = (const struct wfbx_ctrl_hdr*)buf;
      if (h->magic == WFBX_CTRL_MAGIC && h->ver == WFBX_CTRL_VER && h->type == WFBX_CTRL_EPOCH && (size_t)n >= sizeof(struct wfbx_ctrl_epoch)) {
        const struct wfbx_ctrl_epoch* m = (const struct wfbx_ctrl_epoch*)buf;
        (void)m; /* ctrl_drain unused in threaded mode */
      }
    }
  }
}

/* ---- Simple ring buffer for UDP packets ---- */
typedef struct {
  size_t len;
  uint8_t data[MAX_UDP_PAYLOAD];
} pkt_t;

#define RING_SIZE 1024
static pkt_t g_ring[RING_SIZE];
static size_t g_rhead = 0, g_rtail = 0, g_rcount = 0;
static pthread_mutex_t g_rmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_rcond_nonempty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_rcond_nonfull  = PTHREAD_COND_INITIALIZER;

static void ring_push(const uint8_t* data, size_t len)
{
  pthread_mutex_lock(&g_rmtx);
  while (g_rcount == RING_SIZE && g_run) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 50 * 1000 * 1000; if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    (void)pthread_cond_timedwait(&g_rcond_nonfull, &g_rmtx, &ts);
  }
  if (!g_run) { pthread_mutex_unlock(&g_rmtx); return; }
  g_ring[g_rtail].len = len > MAX_UDP_PAYLOAD ? MAX_UDP_PAYLOAD : len;
  memcpy(g_ring[g_rtail].data, data, g_ring[g_rtail].len);
  g_rtail = (g_rtail + 1) % RING_SIZE;
  g_rcount++;
  pthread_cond_signal(&g_rcond_nonempty);
  pthread_mutex_unlock(&g_rmtx);
}

static int ring_pop(pkt_t* out)
{
  pthread_mutex_lock(&g_rmtx);
  while (g_rcount == 0 && g_run) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 50 * 1000 * 1000; if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    (void)pthread_cond_timedwait(&g_rcond_nonempty, &g_rmtx, &ts);
  }
  if (!g_run) { pthread_mutex_unlock(&g_rmtx); return 0; }
  *out = g_ring[g_rhead];
  g_rhead = (g_rhead + 1) % RING_SIZE;
  g_rcount--;
  pthread_cond_signal(&g_rcond_nonfull);
  pthread_mutex_unlock(&g_rmtx);
  return 1;
}

/* Push a packet back to the head (front) of the ring. Assumes there is space. */
static void ring_push_front(const pkt_t* in)
{
  if (!in) return;
  pthread_mutex_lock(&g_rmtx);
  /* If full (shouldn't be right after a pop), wait just in case */
  while (g_rcount == RING_SIZE && g_run) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 50 * 1000 * 1000; if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    (void)pthread_cond_timedwait(&g_rcond_nonfull, &g_rmtx, &ts);
  }
  if (!g_run) { pthread_mutex_unlock(&g_rmtx); return; }
  /* Move head backwards and place packet */
  g_rhead = (g_rhead == 0) ? (RING_SIZE - 1) : (g_rhead - 1);
  g_ring[g_rhead] = *in;
  g_rcount++;
  pthread_cond_signal(&g_rcond_nonempty);
  pthread_mutex_unlock(&g_rmtx);
}

/* ---- Epoch triple with mutex ---- */
typedef struct {
  uint64_t prev_us, cur_us, next_us;
  uint32_t len_us, gi_us; /* superframe params */
  pthread_mutex_t mtx;
} epoch_state_t;

static epoch_state_t g_epoch = {0,0,0,50000,0,PTHREAD_MUTEX_INITIALIZER};

static inline uint64_t sf_total(const epoch_state_t* e){ return (uint64_t)e->len_us + (uint64_t)e->gi_us; }

static void epoch_init_from_start(uint64_t epoch_start_us)
{
  pthread_mutex_lock(&g_epoch.mtx);
  g_epoch.cur_us = epoch_start_us;
  g_epoch.prev_us = epoch_start_us - sf_total(&g_epoch);
  g_epoch.next_us = epoch_start_us + sf_total(&g_epoch);
  pthread_mutex_unlock(&g_epoch.mtx);
}

static int epoch_switch_if_needed(uint64_t now_us)
{
  pthread_mutex_lock(&g_epoch.mtx);
  uint64_t T = sf_total(&g_epoch);
  int advanced = 0;
  while (now_us >= g_epoch.next_us) {
    g_epoch.prev_us = g_epoch.cur_us;
    g_epoch.cur_us = g_epoch.next_us;
    g_epoch.next_us = g_epoch.cur_us + T;
    advanced = 1;
  }
  g_epoch_start_us = g_epoch.cur_us;
  pthread_mutex_unlock(&g_epoch.mtx);
  return advanced;
}

static void epoch_adjust_from_mx(uint64_t epoch_mx_us)
{
  pthread_mutex_lock(&g_epoch.mtx);
  uint64_t T = sf_total(&g_epoch);
  if (T == 0) { pthread_mutex_unlock(&g_epoch.mtx); return; }
  int64_t diff = (int64_t)g_epoch.cur_us - (int64_t)epoch_mx_us;
  int64_t k = llround((double)diff / (double)T);
  uint64_t near = (uint64_t)((int64_t)epoch_mx_us + k*(int64_t)T);
  uint64_t dprev = (g_epoch.prev_us > near) ? (g_epoch.prev_us - near) : (near - g_epoch.prev_us);
  uint64_t dcur  = (g_epoch.cur_us  > near) ? (g_epoch.cur_us  - near) : (near - g_epoch.cur_us);
  uint64_t dnext = (g_epoch.next_us > near) ? (g_epoch.next_us - near) : (near - g_epoch.next_us);
  if (dprev <= dcur && dprev <= dnext) {
    g_epoch.prev_us = near;
    g_epoch.cur_us  = g_epoch.prev_us + T;
    g_epoch.next_us = g_epoch.cur_us + T;
  } else if (dcur <= dnext) {
    g_epoch.cur_us  = near;
    g_epoch.prev_us = g_epoch.cur_us - T;
    g_epoch.next_us = g_epoch.cur_us + T;
  } else {
    g_epoch.next_us = near;
    g_epoch.cur_us  = g_epoch.next_us - T;
    g_epoch.prev_us = g_epoch.cur_us - T;
  }
  g_epoch_start_us = g_epoch.cur_us;
  pthread_mutex_unlock(&g_epoch.mtx);
}

/* ---- TX airtime estimation (HT only) ---- */
static const double ht_mbps_tx[2][2][8] = {
  { {6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0}, {7.2, 14.4, 21.7, 28.9, 43.3, 57.8, 65.0, 72.2} },
  { {13.5,27.0, 40.5, 54.0, 81.0,108.0,121.5,135.0}, {15.0, 30.0, 45.0, 60.0, 90.0,120.0,135.0,150.0} }
};

static uint32_t airtime_us_tx(size_t mpdu_len, int mcs_idx, int gi_short, int bw40, int stbc)
{
  if (mcs_idx < 0) mcs_idx = 0;
  if (mcs_idx > 31) mcs_idx = 31;
  int nss = (mcs_idx / 8) + 1; if (nss < 1) nss = 1; if (nss > 4) nss = 4;
  int mod = mcs_idx % 8;
  int sgi = gi_short ? 1 : 0; int b40 = bw40 ? 1 : 0;
  double base = ht_mbps_tx[b40][sgi][mod];
  double rate = base * nss;
  if (rate <= 0.0) return 0;
  double bits = 8.0 * (double)mpdu_len + 22.0;
  double t_sym = sgi ? 3.6 : 4.0;
  double t_data = bits / rate;
  uint64_t nsym = (uint64_t)((t_data + t_sym - 1e-9) / t_sym);
  if (nsym * t_sym < t_data) nsym += 1;
  double t_data_rounded = (double)nsym * t_sym;
  double t_preamble = 36.0 + 4.0 * (double)(nss - 1);
  double total = t_preamble + t_data_rounded;
  if (total < 0.0) total = 0.0;
  if (total > (double)UINT32_MAX) total = (double)UINT32_MAX;
  return (uint32_t)(total + 0.5);
}

/* ---- Threads ---- */
static int g_usock = -1; /* UDP socket */
static pcap_t* g_ph = NULL;
static uint16_t g_seq = 0;
static int g_mcs_idx = 0, g_gi_short = 1, g_bw40 = 0, g_ldpc = 1, g_stbc = 1;
static uint8_t g_group_id = 0, g_tx_id = 0, g_link_id = 0, g_radio_port = 0;
/* Pending epoch adjustment (apply at boundary if set during active slot) */
static uint64_t g_pending_epoch_us = 0;
static int g_pending_epoch_valid = 0;

/* Stats */
static int g_stat_period_ms = 1000;
static uint64_t g_rx_t0_ms = 0;
static uint64_t g_rx_count_period = 0;
static uint64_t g_sent_in_window = 0;
static uint64_t g_drop_in_window = 0;
static uint64_t g_tx_t0_ms = 0;
static uint64_t g_sent_period = 0;

static void* thr_udp_rx(void* arg)
{
  (void)arg;
  uint8_t buf[MAX_UDP_PAYLOAD];
  while (g_run) {
    ssize_t n = recv(g_usock, buf, sizeof(buf), 0);
    if (n < 0) { if (errno==EINTR) continue; if (errno==EAGAIN||errno==EWOULDBLOCK){ usleep(1000); continue; } perror("recv"); break; }
    if (n == 0) continue;
    ring_push(buf, (size_t)n);
    /* Count only successfully received UDP datagrams */
    g_rx_count_period++;
    /* RX stats per period */
    uint64_t now_ms_local = (uint64_t)(mono_us_raw() / 1000ull);
    if (g_rx_t0_ms == 0) {
      g_rx_t0_ms = now_ms_local;
    }
    if (now_ms_local - g_rx_t0_ms >= (uint64_t)g_stat_period_ms) {
      fprintf(stderr, "[UDP RX] dt=%d ms | pkts=%llu\n", g_stat_period_ms, (unsigned long long)g_rx_count_period);
      g_rx_t0_ms = now_ms_local;
      g_rx_count_period = 0;
    }
  }
  return NULL;
}

static void* thr_ctrl(void* arg)
{
  if (!g_ctrl_enabled) return NULL;
  (void)arg;
  uint8_t buf[256];
  while (g_run) {
    ssize_t n = recv(g_cs, buf, sizeof(buf), 0);
    if (n < 0) { if (errno==EINTR) continue; if (errno==EAGAIN||errno==EWOULDBLOCK){ usleep(1000); continue; } perror("ctrl recv"); break; }
    if ((size_t)n >= sizeof(struct wfbx_ctrl_hdr)) {
      const struct wfbx_ctrl_hdr* h = (const struct wfbx_ctrl_hdr*)buf;
      if (h->magic == WFBX_CTRL_MAGIC && h->ver == WFBX_CTRL_VER && h->type == WFBX_CTRL_EPOCH && (size_t)n >= sizeof(struct wfbx_ctrl_epoch)) {
        const struct wfbx_ctrl_epoch* m = (const struct wfbx_ctrl_epoch*)buf;
        /* Defer correction if inside our active TX slot */
        uint64_t now = mono_us_raw();
        int defer = 0;
        pthread_mutex_lock(&g_epoch.mtx);
        uint64_t T_open  = g_epoch.cur_us + (uint64_t)g_slot_start_us;
        uint64_t T_close = T_open + (uint64_t)g_slot_len_us - (uint64_t)g_gi_tx_us;
        if (now >= T_open && now < T_close) defer = 1;
        pthread_mutex_unlock(&g_epoch.mtx);
        if (defer) {
          /* Keep only the latest pending epoch */
          pthread_mutex_lock(&g_epoch.mtx);
          g_pending_epoch_us = m->epoch_us;
          g_pending_epoch_valid = 1;
          pthread_mutex_unlock(&g_epoch.mtx);
        } else {
          epoch_adjust_from_mx(m->epoch_us);
        }
      }
    }
  }
  return NULL;
}

static void* thr_sched(void* arg)
{
  (void)arg;
  while (g_run) {
    uint64_t now = mono_us_raw();
    /* Per-second TX stats tick (independent of sends) */
    uint64_t now_ms_tick = now / 1000ull;
    if (g_tx_t0_ms == 0) g_tx_t0_ms = now_ms_tick;
    if (now_ms_tick - g_tx_t0_ms >= (uint64_t)g_stat_period_ms) {
      fprintf(stderr, "[TX OUT] dt=%d ms | pkts=%llu\n", g_stat_period_ms, (unsigned long long)g_sent_period);
      g_tx_t0_ms = now_ms_tick;
      g_sent_period = 0;
    }
    int advanced = epoch_switch_if_needed(now);
    if (advanced) {
      /* window boundary: report and reset per-window stats */
      fprintf(stderr, "[SCHED] window sent=%llu drop=%llu\n",
              (unsigned long long)g_sent_in_window,
              (unsigned long long)g_drop_in_window);
      g_sent_in_window = 0;
      g_drop_in_window = 0;
      /* Apply pending epoch correction (if any) exactly at boundary */
      if (g_ctrl_enabled) {
        uint64_t pending = 0; int have = 0;
        pthread_mutex_lock(&g_epoch.mtx);
        if (g_pending_epoch_valid) { pending = g_pending_epoch_us; have = 1; g_pending_epoch_valid = 0; }
        pthread_mutex_unlock(&g_epoch.mtx);
        if (have) {
          epoch_adjust_from_mx(pending);
        }
      }
    }

    pthread_mutex_lock(&g_epoch.mtx);
    uint64_t T_open  = g_epoch.cur_us + (uint64_t)g_slot_start_us;
    uint64_t T_close = T_open + (uint64_t)g_slot_len_us - (uint64_t)g_gi_tx_us;
    uint64_t T_next  = g_epoch.next_us;
    pthread_mutex_unlock(&g_epoch.mtx);

    now = mono_us_raw();
    static uint64_t t_next_send = 0;
    if (now < T_open) {
      uint64_t dt = T_open - now; struct timespec ts={ dt/1000000ull, (long)((dt%1000000ull)*1000ull)}; nanosleep(&ts, NULL);
      t_next_send = T_open;
      continue;
    }
    if (now > T_close) {
      uint64_t dt = (T_next > now) ? (T_next - now) : 1000; struct timespec ts={ dt/1000000ull, (long)((dt%1000000ull)*1000ull)}; nanosleep(&ts, NULL);
      t_next_send = 0;
      continue;
    }

    pkt_t p; if (!ring_pop(&p)) continue;

    /* Recompute slot window after potential wait in ring_pop to avoid using stale boundaries */
    pthread_mutex_lock(&g_epoch.mtx);
    T_open  = g_epoch.cur_us + (uint64_t)g_slot_start_us;
    T_close = T_open + (uint64_t)g_slot_len_us - (uint64_t)g_gi_tx_us;
    T_next  = g_epoch.next_us;
    pthread_mutex_unlock(&g_epoch.mtx);

    uint32_t A_us = airtime_us_tx(p.len + (size_t)WFBX_TRAILER_BYTES, g_mcs_idx, g_gi_short, g_bw40, g_stbc);
    now = mono_us_raw();
    if (t_next_send == 0) t_next_send = (now > T_open) ? now : T_open;
    if (now < t_next_send) {
      uint64_t dtp = t_next_send - now; struct timespec ts={ dtp/1000000ull, (long)((dtp%1000000ull)*1000ull)}; nanosleep(&ts, NULL);
      now = mono_us_raw();
    }
    if (now > T_close) {
      ring_push_front(&p);
      uint64_t dt = (T_next > now) ? (T_next - now) : 1000; struct timespec ts={ dt/1000000ull, (long)((dt%1000000ull)*1000ull)}; nanosleep(&ts, NULL);
      t_next_send = 0;
      continue;
    }
    if (now + g_delta_us + A_us + g_tau_max_us + g_eps_us > T_close) {
      /* Put the packet back to the front so it goes first in the next window */
      ring_push_front(&p);
      g_drop_in_window++;
      /* Sleep until next superframe to avoid busy loop */
      uint64_t dt = (T_next > now) ? (T_next - now) : 1000;
      struct timespec ts={ dt/1000000ull, (long)((dt%1000000ull)*1000ull)};
      nanosleep(&ts, NULL);
      t_next_send = 0;
      continue;
    }

    /* Diagnostics for this send */
    int64_t delta_to_close = (int64_t)T_close - (int64_t)now;
    uint64_t delta_slot_us = (uint64_t)(T_close - T_open);
    fprintf(stderr, "[TX SEND] airtime_us=%u delta_to_close_us=%" PRId64 " delta_slot_us=%" PRIu64 "\n",
            (unsigned)A_us, (int64_t)delta_to_close, (uint64_t)delta_slot_us);

    int ret = send_packet(g_ph, p.data, p.len, g_seq,
                          (uint8_t)g_mcs_idx, g_gi_short, g_bw40, g_ldpc, g_stbc,
                          g_group_id, g_tx_id, g_link_id, g_radio_port);
    if (ret >= 0) {
      g_seq = (uint16_t)((g_seq + 1) & 0x0fff);
      g_sent_in_window++;
      g_sent_period++;
      /* delta_us/tau_max_us are already reflected in guards and T_close; pace by airtime only */
      t_next_send = now + (uint64_t)A_us;
    }
  }
  return NULL;
}

/* Send one packet (payload) via pcap_inject with given TX params */
static int send_packet(pcap_t* ph,
                       const uint8_t* payload, size_t payload_len, uint16_t seq_num,
                       uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc,
                       uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port)
{
  uint8_t frame[MAX_FRAME];
  size_t pos = 0;

  pos += build_radiotap(frame + pos, mcs_idx, gi_short, bw40, ldpc, stbc);
  pos += build_dot11  (frame + pos, seq_num, group_id, tx_id, link_id, radio_port);

  if (payload_len > 0) {
    if (pos + payload_len > sizeof(frame)) return -1;
    memcpy(frame + pos, payload, payload_len);
    pos += payload_len;
  }
  /* Append mesh trailer: 4B TS_tx (us, LE) + 8B t0_ns (LE) */
  {
    struct wfbx_mesh_trailer tr;
    uint64_t now_us = mono_us_raw();
    uint32_t ts_tx = (uint32_t)(now_us - g_epoch_start_us);
    tr.ts_tx_us_le = htole32(ts_tx);
    tr.t0_ns_le    = htole64(mono_ns_raw());
    tr.epoch_us_le = htole64(g_epoch_start_us);
    if (pos + sizeof(tr) > sizeof(frame)) return -1;
    memcpy(frame + pos, &tr, sizeof(tr));
    pos += sizeof(tr);
  }

  int ret = pcap_inject(ph, frame, (int)pos);
  return ret;
}

int main(int argc, char** argv) {
  /* defaults (preserved from udp2wfb.c) */
  const char* ip = "0.0.0.0";
  int port = 5600;
  int mcs_idx = 0;
  int gi_short = 1;     /* default short GI */
  int bw40 = 0;         /* default 20 MHz */
  int ldpc = 1;
  int stbc = 1;
  int group_id = 0, tx_id = 0, link_id = 0, radio_port = 0;
  const char* mx_addr_cli = "@wfbx.mx";

  static struct option longopts[] = {
    {"ip",         required_argument, 0, 0},
    {"port",       required_argument, 0, 0},
    {"mcs_idx",    required_argument, 0, 0},
    {"gi",         required_argument, 0, 0}, /* "short" / "long" */
    {"bw",         required_argument, 0, 0}, /* 20 / 40 */
    {"ldpc",       required_argument, 0, 0}, /* 0 / 1 */
    {"stbc",       required_argument, 0, 0}, /* 0..3 */
    {"group_id",   required_argument, 0, 0},
    {"tx_id",      required_argument, 0, 0},
    {"link_id",    required_argument, 0, 0},
    {"radio_port", required_argument, 0, 0},
    {"mx",         required_argument, 0, 0}, /* MX UDS abstract address */
    {"epoch_len",  required_argument, 0, 0},
    {"epoch_gi",   required_argument, 0, 0},
    {"slot_start", required_argument, 0, 0},
    {"slot_len",   required_argument, 0, 0},
    {"gi_tx",      required_argument, 0, 0},
    {"delta_us",   required_argument, 0, 0},
    {"d_max",      required_argument, 0, 0},
    {"eps_us",     required_argument, 0, 0},
    {0,0,0,0}
  };

  int optidx = 0;
  while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx);
    if (c == -1) break;
    if (c == 0) {
      const char* name = longopts[optidx].name;
      const char* val  = optarg ? optarg : "";
      if      (strcmp(name,"ip")==0) ip = val;
      else if (strcmp(name,"port")==0) port = atoi(val);
      else if (strcmp(name,"mcs_idx")==0) mcs_idx = atoi(val);
      else if (strcmp(name,"gi")==0) {
        if (strcmp(val,"short")==0 || strcmp(val,"sgi")==0) gi_short = 1;
        else if (strcmp(val,"long")==0) gi_short = 0;
        else fprintf(stderr,"Unknown --gi value '%s' (use short|long)\n", val);
      }
      else if (strcmp(name,"bw")==0) {
        if (strcmp(val,"40")==0) bw40 = 1;
        else if (strcmp(val,"20")==0) bw40 = 0;
        else fprintf(stderr,"Unknown --bw value '%s' (use 20|40)\n", val);
      }
      else if (strcmp(name,"ldpc")==0) ldpc = atoi(val)!=0;
      else if (strcmp(name,"stbc")==0) stbc = atoi(val);
      else if (strcmp(name,"group_id")==0) group_id = atoi(val);
      else if (strcmp(name,"tx_id")==0)    tx_id    = atoi(val);
      else if (strcmp(name,"link_id")==0)  link_id  = atoi(val);
      else if (strcmp(name,"radio_port")==0) radio_port = atoi(val);
      else if (strcmp(name,"mx")==0)       mx_addr_cli = val;
      else if (strcmp(name,"epoch_len")==0)  g_epoch_len_us = (uint32_t)atoi(val);
      else if (strcmp(name,"epoch_gi")==0)   g_epoch_gi_us  = (uint32_t)atoi(val);
      else if (strcmp(name,"slot_start")==0)  g_slot_start_us= (uint32_t)atoi(val);
      else if (strcmp(name,"slot_len")==0)    g_slot_len_us  = (uint32_t)atoi(val);
      else if (strcmp(name,"gi_tx")==0)       g_gi_tx_us     = (uint32_t)atoi(val);
      else if (strcmp(name,"delta_us")==0)    g_delta_us     = (uint32_t)atoi(val);
      else if (strcmp(name,"d_max")==0)       g_d_max_km     = atof(val);
      else if (strcmp(name,"eps_us")==0)      g_eps_us       = (uint32_t)atoi(val);
    }
  }

  /* Optional env to enable control sync: WFBX_CTRL=1 */
  const char* ctrl_env = getenv("WFBX_CTRL");
  if (ctrl_env && atoi(ctrl_env) != 0) g_ctrl_enabled = 1;

  /* Stats period (env) */
  const char* sp = getenv("WFBX_STAT_MS");
  if (sp) { int v = atoi(sp); if (v > 0 && v <= 60000) g_stat_period_ms = v; }

  if (optind >= argc) {
    fprintf(stderr, "Usage: sudo %s [--ip 0.0.0.0] [--port 5600] [--mcs_idx N] [--gi short|long] [--bw 20|40]\n"
                    "                [--ldpc 0|1] [--stbc 0..3] [--group_id G] [--tx_id T] [--link_id L] [--radio_port P] <wlan_iface>\n",
            argv[0]);
    return 1;
  }
  const char* iface = argv[optind];

  /* open UDP socket and bind */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = htons(port);
  if (!inet_aton(ip, &sa.sin_addr)) { fprintf(stderr, "inet_aton failed for %s\n", ip); return 1; }
  if (bind(us, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

  /* open pcap on iface (monitor mode expected) */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(iface, errbuf);
  if (!ph) { fprintf(stderr, "pcap_create(%s): %s\n", iface, errbuf); return 1; }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", iface, pcap_geterr(ph));
    return 1;
  }

  signal(SIGINT, on_sigint);
  signal(SIGTERM, on_sigint);
  signal(SIGHUP, on_sigint);
  signal(SIGPIPE, SIG_IGN);
  /* Define local T_epoch as process start time; may be overridden by MX */
  g_epoch_start_us = mono_us_raw();
  /* Control sync disabled by default */
  if (g_ctrl_enabled) (void)ctrl_init(mx_addr_cli, (uint8_t)tx_id);
  /* Derive tau_max_us from d_max (km): c≈299792.458 km/s ⇒ 3.335641 µs/km */
  if (g_d_max_km > 0.0) {
    double tau = g_d_max_km * 3.335641; /* us */
    if (tau < 0.0) tau = 0.0;
    if (tau > (double)UINT32_MAX) tau = (double)UINT32_MAX;
    g_tau_max_us = (uint32_t)(tau + 0.5);
  }
  /* Apply propagation guard to epoch_gi and gi_tx */
  g_epoch_gi_us += g_tau_max_us;
  g_gi_tx_us    += g_tau_max_us;
  /* initialize epoch triple with adjusted guards */
  pthread_mutex_lock(&g_epoch.mtx);
  g_epoch.len_us = g_epoch_len_us; g_epoch.gi_us = g_epoch_gi_us;
  pthread_mutex_unlock(&g_epoch.mtx);
  epoch_init_from_start(g_epoch_start_us);

  fprintf(stderr, "UDP %s:%d -> WLAN %s | MCS=%d GI=%s BW=%s LDPC=%d STBC=%d | G=%d TX=%d L=%d P=%d | mx=%s\n",
          ip, port, iface, mcs_idx, gi_short?"short":"long", bw40?"40":"20",
          ldpc, stbc, group_id, tx_id, link_id, radio_port, mx_addr_cli);

  /* Make UDP socket non-blocking */
  int nfl = fcntl(us, F_GETFL, 0); if (nfl >= 0) fcntl(us, F_SETFL, nfl | O_NONBLOCK);

  /* Publish globals for threads */
  g_usock = us; g_ph = ph; g_seq = 0;
  g_mcs_idx = mcs_idx; g_gi_short = gi_short; g_bw40 = bw40; g_ldpc = ldpc; g_stbc = stbc;
  g_group_id = (uint8_t)group_id; g_tx_id = (uint8_t)tx_id; g_link_id = (uint8_t)link_id; g_radio_port = (uint8_t)radio_port;

  pthread_t th_rx, th_ctrl, th_sched;
  pthread_create(&th_rx, NULL, thr_udp_rx, NULL);
  if (g_ctrl_enabled) pthread_create(&th_ctrl, NULL, thr_ctrl, NULL);
  pthread_create(&th_sched, NULL, thr_sched, NULL);

  /* Join until SIGINT */
  pthread_join(th_rx, NULL);
  if (g_ctrl_enabled) pthread_join(th_ctrl, NULL);
  pthread_join(th_sched, NULL);

  if (g_ph) pcap_close(g_ph);
  close(g_usock);
  return 0;
}
