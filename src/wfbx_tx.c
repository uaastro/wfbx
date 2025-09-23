// wfbx_tx.c — UDP -> 802.11 injection ....
// Preserves CLI and behavior of udp2wfb.c; uses shared defs from wfb_defs.h.
// Build: gcc -O2 -Wall -o wfbx_tx wfbx_tx.c -lpcap

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

/* Ensure BSD typedefs are defined before pcap includes */
#include <sys/types.h>
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
#include <pthread.h>
#include <math.h>
#include <limits.h>

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
#include "wfbx_stats_core.h"
#include "wfbx_stats_tx.h"

#define MAX_FRAME        4096
#define MAX_UDP_PAYLOAD  2000

#define WFBX_TX_STATS_MAX_PACKET 512

static int            g_stat_sock = -1;
static struct sockaddr_in g_stat_addr;
static int            g_stat_enabled = 0;
static uint8_t        g_stat_packet[WFBX_TX_STATS_MAX_PACKET];
static size_t         g_stat_packet_len = 0;
static uint32_t       g_stat_tick_id = 0;
static char           g_stat_module_id[24] = "tx";

static int stats_append_section(uint8_t* dst, size_t* offset, size_t cap,
                                uint16_t type, const uint8_t* data, uint16_t length);
static void stats_send_packet(size_t len);

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

static int stats_append_section(uint8_t* dst, size_t* offset, size_t cap,
                                uint16_t type, const uint8_t* data, uint16_t length)
{
  if (!dst || !offset) return -1;
  if (*offset + 4u + (size_t)length > cap) return -1;
  dst[*offset + 0] = (uint8_t)(type >> 8);
  dst[*offset + 1] = (uint8_t)(type & 0xFF);
  dst[*offset + 2] = (uint8_t)(length >> 8);
  dst[*offset + 3] = (uint8_t)(length & 0xFF);
  if (length > 0 && data) memcpy(dst + *offset + 4, data, length);
  *offset += 4u + (size_t)length;
  return 0;
}

static void stats_send_packet(size_t len)
{
  if (!g_stat_enabled || g_stat_sock < 0) return;
  if (len == 0 || len > sizeof(g_stat_packet)) return;
  char ipbuf[INET_ADDRSTRLEN];
  const char* ip = inet_ntop(AF_INET, &g_stat_addr.sin_addr, ipbuf, sizeof(ipbuf));
  if (!ip) ip = "?";
  ssize_t sent = sendto(g_stat_sock, g_stat_packet, len, 0,
                        (const struct sockaddr*)&g_stat_addr, sizeof(g_stat_addr));
  if (sent < 0) {
    perror("stats sendto");
    fprintf(stderr, "[STATS] TX sendto failed len=%zu dest=%s:%d\n",
            len, ip, ntohs(g_stat_addr.sin_port));
  } else {
    fprintf(stderr, "[STATS] TX sendto ok sent=%zd len=%zu dest=%s:%d\n",
            sent, len, ip, ntohs(g_stat_addr.sin_port));
  }
}

/* Forward declaration for send_packet used by scheduler */
static int send_packet(pcap_t* ph,
                       const uint8_t* payload, size_t payload_len, uint16_t seq_num,
                       uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc,
                       uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port);

static void print_help(const char* prog)
{
  printf(
    "Usage: sudo %s [options] <wlan_iface>\n"
    "\nOptions (defaults in brackets):\n"
    "  --ip <addr>           UDP bind IP [%s]\n"
    "  --port <num>          UDP bind port [%d]\n"
    "  --stat_ip <addr>      Stats server IP [127.0.0.1]\n"
    "  --stat_port <num>     Stats server port [9601]\n"
    "  --stat_id <name>      Stats module identifier [tx]\n"
    "  --mcs_idx <n>         HT MCS index (0..31) [%d]\n"
    "  --gi <short|long>     Guard interval [%s]\n"
    "  --bw <20|40>          Channel bandwidth (MHz) [%s]\n"
    "  --ldpc <0|1>          Use LDPC FEC [%d]\n"
    "  --stbc <0..3>         STBC streams [%d]\n"
    "  --group_id <id>       Group ID (addr1[5]) [%d]\n"
    "  --tx_id <id>          Transmitter ID (addr2[5]) [%d]\n"
    "  --link_id <id>        Link ID (addr3[4]) [%d]\n"
    "  --radio_port <id>     Radio Port (addr3[5]) [%d]\n"
    "  --mx <@name>          Control UDS abstract addr [%s]\n"
    "  --epoch_len <us>      Superframe length [%u]\n"
    "  --epoch_gi <us>       Inter-superframe guard (pre-prop) [%u]\n"
    "  --slot_start <us>     TX slot start offset [%u]\n"
    "  --slot_len <us>       TX slot length [%u]\n"
    "  --gi_tx <us>          TX slot tail guard (pre-prop) [%u]\n"
    "  --delta_us <us>       Stack latency delta [%u]\n"
    "  --d_max <km>          Max distance; adds tau guard [%.1f]\n"
    "  --eps_us <us>         Scheduler margin epsilon [%u]\n"
    "  --send_gi <us>        Inter-send pacing guard [%u]\n"
    "  --prewake_q <n>       Divide long sleeps into n slices [%d]\n"
    "  --prewake_min <us>    Minimum slice length (us) [%u]\n"
    "  --stat_period <ms>    Stats period in ms [%d]\n"
    "  --epoch_sync <on|off> Enable/disable MX epoch sync [%s]\n"
    "  --help                Show this help and exit\n"
    "\nEnvironment:\n"
    "  WFBX_CTRL=1           Enable control channel (default off)\n"
    "  WFBX_STAT_MS=<ms>     Stats period in ms [1000]\n",
    prog,
    "0.0.0.0", 5600,
    0,
    "short",
    "20",
    1,
    1,
    0, 0, 0, 0,
    "@wfbx.mx",
    50000u,
    400u,
    0u,
    50000u,
    400u,
    1500u,
    0.0,
    250u,
    200u,
    1,
    1000u,
    1000,
    "on"
  );
}

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
static uint32_t g_send_guard_us = 200; /* pacing guard between packets (us) */
/* Pre-wake slicing to refine epoch boundaries during long sleeps */
static int      g_prewake_quanta  = 1;     /* number of slices for long sleeps (>=1) */
static uint32_t g_prewake_min_us  = 1000;  /* minimum sleep slice (us) */

/* Control socket (UDS DGRAM) */
static int g_cs = -1;
static struct sockaddr_un g_tx_addr; static socklen_t g_tx_addr_len;
static struct sockaddr_un g_mx_addr; static socklen_t g_mx_addr_len;
static char g_tx_name[108] = {0};
static char g_mx_name[108] = {0};
static uint32_t g_ctrl_seq = 0;
static int g_ctrl_enabled = 1; /* control sync enabled by default (can be toggled by CLI) */
/* Pending epoch adjustment (applied at epoch boundary) */
static uint64_t g_pending_epoch_us = 0;
static int g_pending_epoch_valid = 0;
/* MX epoch messages received (per reporting period) */
static uint64_t g_mx_epoch_msgs_period = 0;
/* Base-epoch advancement stats (per reporting period) */
static uint64_t g_base_adv_period = 0;
static uint64_t g_base_step_sum = 0;
static uint64_t g_base_step_min = UINT64_MAX;
static uint64_t g_base_step_max = 0;
static uint64_t g_base_step_samples = 0;
/* Control re-subscribe support */
static uint8_t  g_tx_id_ctrl = 0;
static uint64_t g_last_sub_us = 0;
static uint64_t g_last_epoch_rx_us = 0;
/* Applied epoch adjustments (per reporting period) */
static uint64_t g_epoch_adj_count_period = 0;
static uint64_t g_epoch_adj_abs_sum = 0;
static uint64_t g_epoch_adj_abs_min = UINT64_MAX;
static uint64_t g_epoch_adj_abs_max = 0;

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
  /* Remember tx_id for periodic re-subscribe */
  g_tx_id_ctrl = tx_id;
  /* Initial SUB */
  struct wfbx_ctrl_sub sub; memset(&sub, 0, sizeof(sub));
  sub.h.magic = WFBX_CTRL_MAGIC; sub.h.ver = WFBX_CTRL_VER; sub.h.type = WFBX_CTRL_SUB; sub.h.seq = ++g_ctrl_seq;
  sub.tx_id = g_tx_id_ctrl;
  size_t maxcopy = sizeof(sub.name) - 2; /* '@' + up to maxcopy chars + NUL */
  snprintf(sub.name, sizeof(sub.name), "@%.*s", (int)maxcopy, g_tx_name);
  (void)sendto(g_cs, &sub, sizeof(sub), 0, (struct sockaddr*)&g_mx_addr, g_mx_addr_len);
  g_last_sub_us = mono_us_raw();
  fprintf(stderr, "[CTRL] SUB sent (seq=%u) to %s | tx_id=%u\n",
          (unsigned)sub.h.seq, g_mx_name, (unsigned)g_tx_id_ctrl);
  return 0;
}

static void ctrl_send_sub(void)
{
  if (!g_ctrl_enabled || g_cs < 0) return;
  struct wfbx_ctrl_sub sub; memset(&sub, 0, sizeof(sub));
  sub.h.magic = WFBX_CTRL_MAGIC; sub.h.ver = WFBX_CTRL_VER; sub.h.type = WFBX_CTRL_SUB; sub.h.seq = ++g_ctrl_seq;
  sub.tx_id = g_tx_id_ctrl;
  size_t maxcopy = sizeof(sub.name) - 2;
  snprintf(sub.name, sizeof(sub.name), "@%.*s", (int)maxcopy, g_tx_name);
  (void)sendto(g_cs, &sub, sizeof(sub), 0, (struct sockaddr*)&g_mx_addr, g_mx_addr_len);
  g_last_sub_us = mono_us_raw();
  uint64_t since_epoch = (g_last_epoch_rx_us>0 && g_last_sub_us>g_last_epoch_rx_us) ? (g_last_sub_us - g_last_epoch_rx_us) : 0;
  fprintf(stderr, "[CTRL] re-SUB sent (seq=%u) to %s | tx_id=%u | since_last_epoch=%llu ms\n",
          (unsigned)sub.h.seq, g_mx_name, (unsigned)g_tx_id_ctrl,
          (unsigned long long)(since_epoch/1000ull));
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

/* ---- Double-linked list buffer with node pool (no malloc in hot path) ---- */
typedef struct {
  size_t len;
  uint8_t data[MAX_UDP_PAYLOAD];
} pkt_t;

#define BUF_CAPACITY 1024

typedef struct pkt_node {
  struct pkt_node* prev;
  struct pkt_node* next;
  struct pkt_node* pool_next; /* singly-linked free list */
  pkt_t pkt;
} pkt_node;

typedef struct {
  /* list */
  pkt_node* head;
  pkt_node* tail;
  size_t size;
  /* pool */
  pkt_node* pool_head;
  size_t    pool_count;
  pkt_node  storage[BUF_CAPACITY];
  /* sync */
  pthread_mutex_t mtx;
  pthread_cond_t  not_empty;
} dl_list;

static dl_list g_buf;
static uint64_t g_buf_drop_period = 0; /* dropped oldest on overflow in producer */

static void dl_init(dl_list* L)
{
  memset(L, 0, sizeof(*L));
  pthread_mutex_init(&L->mtx, NULL);
  pthread_cond_init(&L->not_empty, NULL);
  /* build pool */
  L->pool_head = &L->storage[0];
  L->pool_count = BUF_CAPACITY;
  for (size_t i=0;i<BUF_CAPACITY-1;i++) L->storage[i].pool_next = &L->storage[i+1];
  L->storage[BUF_CAPACITY-1].pool_next = NULL;
}

static inline pkt_node* pool_get(dl_list* L){ pkt_node* n=L->pool_head; if (n){ L->pool_head=n->pool_next; L->pool_count--; n->prev=n->next=NULL; } return n; }
static inline void pool_put(dl_list* L, pkt_node* n){ n->prev=n->next=NULL; n->pool_next=L->pool_head; L->pool_head=n; L->pool_count++; }

/* producer push_back with overflow policy: drop oldest */
static void dl_push_back_drop_oldest(dl_list* L, const uint8_t* data, size_t len)
{
  pthread_mutex_lock(&L->mtx);
  if (L->pool_count == 0) {
    /* drop oldest (head) */
    if (L->head) {
      pkt_node* h = L->head;
      L->head = h->next; if (L->head) L->head->prev = NULL; else L->tail = NULL;
      L->size--;
      pool_put(L, h);
      g_buf_drop_period++;
    }
  }
  pkt_node* n = pool_get(L);
  if (n) {
    n->pkt.len = len > MAX_UDP_PAYLOAD ? MAX_UDP_PAYLOAD : len;
    memcpy(n->pkt.data, data, n->pkt.len);
    /* append */
    if (!L->tail) { L->head = L->tail = n; }
    else { n->prev = L->tail; L->tail->next = n; L->tail = n; }
    L->size++;
    pthread_cond_signal(&L->not_empty);
  }
  pthread_mutex_unlock(&L->mtx);
}

/* consumer pop_front; blocks (timed) until not empty or g_run false */
static int dl_pop_front(dl_list* L, pkt_t* out)
{
  int ok = 0;
  pthread_mutex_lock(&L->mtx);
  while (L->size == 0 && g_run) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 50 * 1000 * 1000; if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    (void)pthread_cond_timedwait(&L->not_empty, &L->mtx, &ts);
  }
  if (!g_run) { pthread_mutex_unlock(&L->mtx); return 0; }
  pkt_node* h = L->head;
  if (h) {
    *out = h->pkt;
    L->head = h->next; if (L->head) L->head->prev = NULL; else L->tail = NULL;
    L->size--;
    pool_put(L, h);
    ok = 1;
  }
  pthread_mutex_unlock(&L->mtx);
  return ok;
}

/* consumer push_front (used when deferring to next slot) */
static int dl_push_front(dl_list* L, const pkt_t* in)
{
  int ok = 0;
  pthread_mutex_lock(&L->mtx);
  pkt_node* n = pool_get(L);
  if (n) {
    n->pkt = *in;
    if (!L->head) { L->head = L->tail = n; }
    else { n->next = L->head; L->head->prev = n; L->head = n; }
    L->size++;
    pthread_cond_signal(&L->not_empty);
    ok = 1;
  }
  pthread_mutex_unlock(&L->mtx);
  return ok;
}

static inline size_t dl_size(dl_list* L){ size_t s; pthread_mutex_lock(&L->mtx); s=L->size; pthread_mutex_unlock(&L->mtx); return s; }

/* ---- Epoch triple with mutex ---- */
typedef struct {
  uint64_t prev_us, cur_us, next_us;
  uint32_t len_us, gi_us; /* superframe params */
  pthread_mutex_t mtx;
} epoch_state_t;

static epoch_state_t g_epoch = {0,0,0,50000,0,PTHREAD_MUTEX_INITIALIZER};
/* Base epoch follows initial startup schedule (no MX adjustments). */
static epoch_state_t g_epoch_base = {0,0,0,50000,0,PTHREAD_MUTEX_INITIALIZER};

static inline uint64_t sf_total(const epoch_state_t* e){ return (uint64_t)e->len_us + (uint64_t)e->gi_us; }

static void epoch_init_from_start(uint64_t epoch_start_us)
{
  pthread_mutex_lock(&g_epoch.mtx);
  g_epoch.cur_us = epoch_start_us;
  g_epoch.prev_us = epoch_start_us - sf_total(&g_epoch);
  g_epoch.next_us = epoch_start_us + sf_total(&g_epoch);
  pthread_mutex_unlock(&g_epoch.mtx);
}

/* Initialize base epoch (no adjustments). */
static void epoch_base_init_from_start(uint64_t epoch_start_us)
{
  pthread_mutex_lock(&g_epoch_base.mtx);
  g_epoch_base.cur_us  = epoch_start_us;
  g_epoch_base.prev_us = epoch_start_us - sf_total(&g_epoch_base);
  g_epoch_base.next_us = epoch_start_us + sf_total(&g_epoch_base);
  pthread_mutex_unlock(&g_epoch_base.mtx);
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

/* Advance base epoch when time passes (no adjustments). */
static int epoch_base_switch_if_needed(uint64_t now_us)
{
  pthread_mutex_lock(&g_epoch_base.mtx);
  uint64_t T = sf_total(&g_epoch_base);
  int advanced = 0;
  while (now_us >= g_epoch_base.next_us) {
    g_epoch_base.prev_us = g_epoch_base.cur_us;
    g_epoch_base.cur_us  = g_epoch_base.next_us;
    g_epoch_base.next_us = g_epoch_base.cur_us + T;
    advanced = 1;
  }
  pthread_mutex_unlock(&g_epoch_base.mtx);
  return advanced;
}

static void epoch_adjust_from_mx(uint64_t epoch_mx_us)
{
  pthread_mutex_lock(&g_epoch.mtx);
  uint64_t T = sf_total(&g_epoch);
  if (T == 0) { pthread_mutex_unlock(&g_epoch.mtx); return; }
  uint64_t old_cur = g_epoch.cur_us;
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

  /* Count applied correction magnitude (absolute change of current epoch) */
  uint64_t new_cur = g_epoch_start_us;
  uint64_t abs_step = (new_cur > old_cur) ? (new_cur - old_cur) : (old_cur - new_cur);
  if (abs_step > 0) {
    g_epoch_adj_count_period++;
    g_epoch_adj_abs_sum += abs_step;
    if (g_epoch_adj_abs_min == UINT64_MAX || abs_step < g_epoch_adj_abs_min) g_epoch_adj_abs_min = abs_step;
    if (abs_step > g_epoch_adj_abs_max) g_epoch_adj_abs_max = abs_step;
  }
}

/* ---- Helpers for pre-wake sliced sleep to boundary ---- */
/* Forward declaration: used from sliced sleep helper */
static inline void epoch_rollover_if_needed(void);
static inline void epoch_base_rollover_if_needed(void);
static inline uint64_t epoch_get_T_open(void)
{
  uint64_t T_open;
  pthread_mutex_lock(&g_epoch.mtx);
  T_open = g_epoch.cur_us + (uint64_t)g_slot_start_us;
  pthread_mutex_unlock(&g_epoch.mtx);
  return T_open;
}
static inline uint64_t epoch_get_T_next(void)
{
  uint64_t T_next;
  pthread_mutex_lock(&g_epoch.mtx);
  T_next = g_epoch.next_us;
  pthread_mutex_unlock(&g_epoch.mtx);
  return T_next;
}
static inline void apply_pending_epoch_if_any(void)
{
  if (!g_ctrl_enabled) return;
  uint64_t pending = 0; int have = 0;
  /* Apply only when we are NOT inside the active TX slot. */
  uint64_t now = mono_us_raw();
  pthread_mutex_lock(&g_epoch.mtx);
  uint64_t T_open  = g_epoch.cur_us + (uint64_t)g_slot_start_us;
  uint64_t T_close = T_open + (uint64_t)g_slot_len_us - (uint64_t)g_gi_tx_us;
  int in_slot = (now >= T_open) && (now < T_close);
  if (!in_slot && g_pending_epoch_valid) { pending = g_pending_epoch_us; have = 1; g_pending_epoch_valid = 0; }
  pthread_mutex_unlock(&g_epoch.mtx);
  if (have) epoch_adjust_from_mx(pending);
}
/* target_kind: 0 → T_open, 1 → T_next */
static void sleep_until_boundary_sliced(int target_kind)
{
  int qs = (g_prewake_quanta < 1) ? 1 : g_prewake_quanta;
  for (int i=0; i<qs && g_run; ++i) {
    uint64_t target = (target_kind == 0) ? epoch_get_T_open() : epoch_get_T_next();
    uint64_t now = mono_us_raw();
    if (now >= target) break;
    int slices_left = qs - i;
    uint64_t remain = target - now;
    uint64_t slice = remain / (uint64_t)slices_left;
    if (slice < (uint64_t)g_prewake_min_us) slice = (uint64_t)g_prewake_min_us;
    if (slice > remain) slice = remain;
    struct timespec ts = { slice/1000000ull, (long)((slice%1000000ull)*1000ull) };
    nanosleep(&ts, NULL);
    /* Maintain epoch continuity and roll over per-slot stats on boundary */
    epoch_rollover_if_needed();
    /* If we had a pending epoch update from MX (arrived during active slot),
       and we are now outside the slot, apply it immediately (don't wait boundary). */
    apply_pending_epoch_if_any();
  }
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

/* Stats */
static int g_stat_period_ms = 1000;
static uint64_t g_rx_count_period = 0;
static uint64_t g_sent_in_window = 0;
static uint64_t g_drop_in_window = 0;
static uint64_t g_tx_t0_ms = 0;
static uint64_t g_sent_period = 0;
static uint64_t g_rx_bytes_period = 0;
static uint64_t g_sent_bytes_period = 0;
static uint64_t g_slot_sent_sum = 0;
static uint64_t g_slot_sent_min = UINT64_MAX;
static uint64_t g_slot_sent_max = 0;
static uint64_t g_slot_count    = 0;
static pthread_mutex_t g_stat_mtx = PTHREAD_MUTEX_INITIALIZER;
/* Buffer-left-at-slot-end statistics over the reporting period */
static uint64_t g_buf_left_sum = 0;
static uint64_t g_buf_left_min = UINT64_MAX;
static uint64_t g_buf_left_max = 0;
static uint64_t g_buf_left_cnt = 0;
/* Whether we've already sampled buffer-left for the current slot */
static int g_buf_left_sampled_this_slot = 0;

static void* thr_udp_rx(void* arg)
{
  (void)arg;
  uint8_t buf[MAX_UDP_PAYLOAD];
  while (g_run) {
    ssize_t n = recv(g_usock, buf, sizeof(buf), 0);
    if (n < 0) { if (errno==EINTR) continue; if (errno==EAGAIN||errno==EWOULDBLOCK){ usleep(1000); continue; } perror("recv"); break; }
    if (n == 0) continue;
    dl_push_back_drop_oldest(&g_buf, buf, (size_t)n);
    /* Count only successfully received UDP datagrams */
    pthread_mutex_lock(&g_stat_mtx);
    g_rx_count_period++;
    g_rx_bytes_period += (uint64_t)n;
    pthread_mutex_unlock(&g_stat_mtx);
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
        /* Count received MX epoch messages for diagnostics */
        g_mx_epoch_msgs_period++;
        const struct wfbx_ctrl_epoch* m = (const struct wfbx_ctrl_epoch*)buf;
        g_last_epoch_rx_us = mono_us_raw();
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

static inline void epoch_rollover_if_needed(void)
{
  uint64_t now = mono_us_raw();
  int advanced = epoch_switch_if_needed(now);
  if (advanced) {
    /* At epoch boundary: record buffer-left once per slot if not yet sampled */
    if (!g_buf_left_sampled_this_slot) {
      uint64_t buf_left = dl_size(&g_buf);
      g_buf_left_sum += buf_left;
      if (g_buf_left_min == UINT64_MAX || buf_left < g_buf_left_min) g_buf_left_min = buf_left;
      if (buf_left > g_buf_left_max) g_buf_left_max = buf_left;
      g_buf_left_cnt++;
    }
    g_buf_left_sampled_this_slot = 0; /* new slot begins */
    /* window boundary: fold per-window sent into period slot stats and reset window counters */
    g_slot_sent_sum += g_sent_in_window;
    if (g_slot_sent_min == UINT64_MAX || g_sent_in_window < g_slot_sent_min) g_slot_sent_min = g_sent_in_window;
    if (g_sent_in_window > g_slot_sent_max) g_slot_sent_max = g_sent_in_window;
    g_slot_count++;
    g_sent_in_window = 0;
    g_drop_in_window = 0;
    /* Apply pending epoch correction (if any) exactly at boundary */
    apply_pending_epoch_if_any();
  }
}

static inline void epoch_base_rollover_if_needed(void)
{
  uint64_t now = mono_us_raw();
  int advanced = epoch_base_switch_if_needed(now);
  if (advanced) {
    /* Gather base step stats: step = cur - prev */
    uint64_t cur=0, prev=0;
    pthread_mutex_lock(&g_epoch_base.mtx);
    cur  = g_epoch_base.cur_us;
    prev = g_epoch_base.prev_us;
    pthread_mutex_unlock(&g_epoch_base.mtx);
    if (cur > prev) {
      uint64_t step = cur - prev;
      g_base_step_sum += step;
      if (g_base_step_min == UINT64_MAX || step < g_base_step_min) g_base_step_min = step;
      if (step > g_base_step_max) g_base_step_max = step;
      g_base_step_samples++;
    }
    g_base_adv_period++;
  }
}

static void* thr_sched(void* arg)
{
  (void)arg;
  while (g_run) {
    uint64_t now = mono_us_raw();
    /* Re-subscribe if MX likely started after us or link lost: */
    if (g_ctrl_enabled) {
      int need_resub = 0;
      /* If we haven't received any epoch yet, or долгое молчание — шлем SUB раз в ~1s */
      if (g_last_sub_us == 0) need_resub = 1;
      else if (now - g_last_sub_us >= 1000000ull) {
        if (g_last_epoch_rx_us == 0 || now - g_last_epoch_rx_us > 1500000ull) need_resub = 1;
      }
      if (need_resub) ctrl_send_sub();
    }
    /* Per-second TX stats tick (independent of sends) */
    uint64_t now_ms_tick = now / 1000ull;
    if (g_tx_t0_ms == 0) g_tx_t0_ms = now_ms_tick;
    if (now_ms_tick - g_tx_t0_ms >= (uint64_t)g_stat_period_ms) {
      /* Summary once per period */
      uint64_t udp_rx = 0;
      uint64_t udp_rx_bytes = 0;
      uint64_t sent_bytes = 0;
      pthread_mutex_lock(&g_stat_mtx);
      udp_rx = g_rx_count_period;
      g_rx_count_period = 0;
      udp_rx_bytes = g_rx_bytes_period;
      g_rx_bytes_period = 0;
      sent_bytes = g_sent_bytes_period;
      g_sent_bytes_period = 0;
      pthread_mutex_unlock(&g_stat_mtx);
      uint64_t slot_avg = (g_slot_count > 0) ? (g_slot_sent_sum / g_slot_count) : 0;
      uint64_t slot_min = (g_slot_count > 0) ? g_slot_sent_min : 0;
      uint64_t slot_max = (g_slot_count > 0) ? g_slot_sent_max : 0;
      uint64_t buf_avg  = (g_buf_left_cnt > 0) ? (g_buf_left_sum / g_buf_left_cnt) : 0;
      uint64_t buf_min  = (g_buf_left_cnt > 0) ? g_buf_left_min : 0;
      uint64_t buf_max  = (g_buf_left_cnt > 0) ? g_buf_left_max : 0;
      /* Line 1: period udp_rx and sent (+ buffer overflow drops) */
      double rx_rate_kbps = (double)udp_rx_bytes * 8.0 / (double)g_stat_period_ms;
      double tx_rate_kbps = (double)sent_bytes * 8.0 / (double)g_stat_period_ms;
      fprintf(stderr, "[TX STAT] dt=%d ms | udp_rx=%llu (%.1f kbps) | sent=%llu (%.1f kbps) | drop_overflow=%llu |\n",
              g_stat_period_ms,
              (unsigned long long)udp_rx,
              rx_rate_kbps,
              (unsigned long long)g_sent_period,
              tx_rate_kbps,
              (unsigned long long)g_buf_drop_period);
      /* Line 2: buffer-left and per-slot send stats */
      fprintf(stderr, "[TX STAT] buf_left avg=%llu min=%llu max=%llu | slot_sent avg=%llu min=%llu max=%llu\n",
              (unsigned long long)buf_avg,
              (unsigned long long)buf_min,
              (unsigned long long)buf_max,
              (unsigned long long)slot_avg,
              (unsigned long long)slot_min,
              (unsigned long long)slot_max);
      /* Epoch drift vs base + MX counters */
      uint64_t cur_epoch_us = 0, cur_base_us = 0;
      pthread_mutex_lock(&g_epoch.mtx);
      cur_epoch_us = g_epoch.cur_us;
      pthread_mutex_unlock(&g_epoch.mtx);
      pthread_mutex_lock(&g_epoch_base.mtx);
      cur_base_us = g_epoch_base.cur_us;
      pthread_mutex_unlock(&g_epoch_base.mtx);
      long long e_epoch_base = (long long)((int64_t)cur_epoch_us - (int64_t)cur_base_us);
      fprintf(stderr, "[TX STAT] e_epoch_base=%lld us | mx_epoch_msgs=%llu | base_adv=%llu\n",
              e_epoch_base,
              (unsigned long long)g_mx_epoch_msgs_period,
              (unsigned long long)g_base_adv_period);
      if (g_base_step_samples > 0) {
        unsigned long long avg = (unsigned long long)(g_base_step_sum / g_base_step_samples);
        fprintf(stderr, "[TX STAT] base_step_us avg=%llu min=%llu max=%llu n=%llu\n",
                avg,
                (unsigned long long)g_base_step_min,
                (unsigned long long)g_base_step_max,
                (unsigned long long)g_base_step_samples);
      }
      if (g_epoch_adj_count_period > 0) {
        unsigned long long avg_adj = (unsigned long long)(g_epoch_adj_abs_sum / g_epoch_adj_count_period);
        fprintf(stderr, "[TX STAT] epoch_adj abs_us avg=%llu min=%llu max=%llu n=%llu\n",
                avg_adj,
                (unsigned long long)g_epoch_adj_abs_min,
                (unsigned long long)g_epoch_adj_abs_max,
                (unsigned long long)g_epoch_adj_count_period);
      }
      wfbx_tx_summary_t tx_summary = {
        .dt_ms = (uint32_t)g_stat_period_ms,
        .udp_rx_packets = (uint32_t)udp_rx,
        .udp_rx_kbps_x10 = (uint32_t)(rx_rate_kbps * 10.0),
        .sent_packets = (uint32_t)g_sent_period,
        .sent_kbps_x10 = (uint32_t)(tx_rate_kbps * 10.0),
        .drop_overflow = (uint32_t)g_buf_drop_period,
        .reserved0 = 0,
        .reserved1 = 0,
      };
      wfbx_tx_queue_stats_t tx_queue = {
        .avg = (uint32_t)buf_avg,
        .min = (uint32_t)buf_min,
        .max = (uint32_t)buf_max,
        .samples = (uint32_t)g_buf_left_cnt,
      };
      wfbx_tx_slot_stats_t tx_slot = {
        .avg = (uint32_t)slot_avg,
        .min = (uint32_t)slot_min,
        .max = (uint32_t)slot_max,
        .slots = (uint32_t)g_slot_count,
      };
      wfbx_tx_epoch_stats_t tx_epoch = {
        .e_epoch_base_us = (int32_t)e_epoch_base,
        .mx_epoch_msgs = (uint32_t)g_mx_epoch_msgs_period,
        .base_adv = (uint32_t)g_base_adv_period,
        .base_step_avg_us = (uint32_t)(g_base_step_samples ? (g_base_step_sum / g_base_step_samples) : 0),
        .base_step_min_us = (uint32_t)((g_base_step_samples > 0 && g_base_step_min != UINT64_MAX) ? g_base_step_min : 0),
        .base_step_max_us = (uint32_t)(g_base_step_samples ? g_base_step_max : 0),
        .base_step_samples = (uint32_t)g_base_step_samples,
        .epoch_adj_count = (uint32_t)g_epoch_adj_count_period,
        .epoch_adj_avg_us = (uint32_t)(g_epoch_adj_count_period ? (g_epoch_adj_abs_sum / g_epoch_adj_count_period) : 0),
        .epoch_adj_min_us = (uint32_t)((g_epoch_adj_count_period > 0 && g_epoch_adj_abs_min != UINT64_MAX) ? g_epoch_adj_abs_min : 0),
        .epoch_adj_max_us = (uint32_t)(g_epoch_adj_count_period ? g_epoch_adj_abs_max : 0),
      };
      uint8_t tx_summary_buf[sizeof(wfbx_tx_summary_t)];
      int tx_summary_sz = wfbx_tx_summary_pack(tx_summary_buf, sizeof(tx_summary_buf), &tx_summary);
      uint8_t tx_queue_buf[sizeof(wfbx_tx_queue_stats_t)];
      int tx_queue_sz = wfbx_tx_queue_stats_pack(tx_queue_buf, sizeof(tx_queue_buf), &tx_queue);
      uint8_t tx_slot_buf[sizeof(wfbx_tx_slot_stats_t)];
      int tx_slot_sz = wfbx_tx_slot_stats_pack(tx_slot_buf, sizeof(tx_slot_buf), &tx_slot);
      uint8_t tx_epoch_buf[sizeof(wfbx_tx_epoch_stats_t)];
      int tx_epoch_sz = wfbx_tx_epoch_stats_pack(tx_epoch_buf, sizeof(tx_epoch_buf), &tx_epoch);

      if (g_stat_enabled &&
          tx_summary_sz > 0 && tx_queue_sz > 0 && tx_slot_sz > 0 && tx_epoch_sz > 0) {
        uint8_t payload_buf[WFBX_TX_STATS_MAX_PACKET - WFBX_STATS_HEADER_SIZE];
        size_t payload_off = 0;
        uint16_t section_count = 0;
        int build_failed = 0;
        g_stat_packet_len = 0;

        if (stats_append_section(payload_buf, &payload_off, sizeof(payload_buf),
                                 WFBX_TX_SECTION_SUMMARY,
                                 tx_summary_buf, (uint16_t)tx_summary_sz) != 0) {
          fprintf(stderr, "[STATS] TX summary append failed\n");
          build_failed = 1;
        } else {
          section_count++;
        }
        if (!build_failed &&
            stats_append_section(payload_buf, &payload_off, sizeof(payload_buf),
                                 WFBX_TX_SECTION_QUEUE,
                                 tx_queue_buf, (uint16_t)tx_queue_sz) != 0) {
          fprintf(stderr, "[STATS] TX queue append failed\n");
          build_failed = 1;
        } else if (!build_failed) {
          section_count++;
        }
        if (!build_failed &&
            stats_append_section(payload_buf, &payload_off, sizeof(payload_buf),
                                 WFBX_TX_SECTION_SLOT,
                                 tx_slot_buf, (uint16_t)tx_slot_sz) != 0) {
          fprintf(stderr, "[STATS] TX slot append failed\n");
          build_failed = 1;
        } else if (!build_failed) {
          section_count++;
        }
        if (!build_failed &&
            stats_append_section(payload_buf, &payload_off, sizeof(payload_buf),
                                 WFBX_TX_SECTION_EPOCH,
                                 tx_epoch_buf, (uint16_t)tx_epoch_sz) != 0) {
          fprintf(stderr, "[STATS] TX epoch append failed\n");
          build_failed = 1;
        } else if (!build_failed) {
          section_count++;
        }

        if (!build_failed) {
          if (payload_off + WFBX_STATS_HEADER_SIZE <= WFBX_TX_STATS_MAX_PACKET) {
            wfbx_stats_header_t hdr;
            uint64_t ts_us = mono_us_raw();
            uint32_t tick = g_stat_tick_id++;
            if (wfbx_stats_header_init(&hdr,
                                       1,
                                       WFBX_MODULE_TX,
                                       g_stat_module_id,
                                       NULL,
                                       tick,
                                       ts_us,
                                       0,
                                       section_count,
                                       (uint32_t)payload_off) == 0) {
              uint8_t header_buf[WFBX_STATS_HEADER_SIZE];
              if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &hdr) == 0) {
                memcpy(g_stat_packet, header_buf, WFBX_STATS_HEADER_SIZE);
                memcpy(g_stat_packet + WFBX_STATS_HEADER_SIZE, payload_buf, payload_off);
                size_t total_len = WFBX_STATS_HEADER_SIZE + payload_off;
                hdr.crc32 = wfbx_stats_crc32(g_stat_packet, total_len);
                if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &hdr) == 0) {
                  memcpy(g_stat_packet, header_buf, WFBX_STATS_HEADER_SIZE);
                  g_stat_packet_len = total_len;
                  stats_send_packet(total_len);
                } else {
                  fprintf(stderr, "[STATS] TX header pack (crc) failed\n");
                }
              } else {
                fprintf(stderr, "[STATS] TX header pack failed\n");
              }
            } else {
              fprintf(stderr, "[STATS] TX header init failed\n");
            }
          } else {
            fprintf(stderr, "[STATS] TX packet too large (%zu)\n",
                    payload_off + WFBX_STATS_HEADER_SIZE);
          }
        }
      }

      /* reset period counters */
      g_tx_t0_ms    = now_ms_tick;
      g_sent_period = 0;
      g_slot_sent_sum = 0;
      g_slot_sent_min = UINT64_MAX;
      g_slot_sent_max = 0;
      g_slot_count    = 0;
      g_buf_left_sum = 0;
      g_buf_left_min = UINT64_MAX;
      g_buf_left_max = 0;
      g_buf_left_cnt = 0;
      /* reset period-scoped overflow counter */
      g_buf_drop_period = 0;
      /* reset MX/base counters */
      g_mx_epoch_msgs_period = 0;
      g_base_adv_period = 0;
      g_base_step_sum = 0;
      g_base_step_min = UINT64_MAX;
      g_base_step_max = 0;
      g_base_step_samples = 0;
      /* reset epoch adjustment counters */
      g_epoch_adj_count_period = 0;
      g_epoch_adj_abs_sum = 0;
      g_epoch_adj_abs_min = UINT64_MAX;
      g_epoch_adj_abs_max = 0;
    }
    epoch_rollover_if_needed();
    epoch_base_rollover_if_needed();

    pthread_mutex_lock(&g_epoch.mtx);
    uint64_t T_open  = g_epoch.cur_us + (uint64_t)g_slot_start_us;
    uint64_t T_close = T_open + (uint64_t)g_slot_len_us - (uint64_t)g_gi_tx_us;
    uint64_t T_next  = g_epoch.next_us;
    pthread_mutex_unlock(&g_epoch.mtx);

    now = mono_us_raw();
    static uint64_t t_next_send = 0;
    if (now < T_open) {
      /* Pre-wake sliced sleep until T_open to refine epoch */
      sleep_until_boundary_sliced(0);
      t_next_send = epoch_get_T_open();
      continue;
    }
    if (now > T_close) {
      /* Capture buffer occupancy at slot end (once per slot) */
      if (!g_buf_left_sampled_this_slot) {
        uint64_t buf_left = dl_size(&g_buf);
        g_buf_left_sum += buf_left;
        if (g_buf_left_min == UINT64_MAX || buf_left < g_buf_left_min) g_buf_left_min = buf_left;
        if (buf_left > g_buf_left_max) g_buf_left_max = buf_left;
        g_buf_left_cnt++;
        g_buf_left_sampled_this_slot = 1;
      }
      /* Pre-wake sliced sleep until next superframe */
      sleep_until_boundary_sliced(1);
      t_next_send = 0;
      continue;
    }

    pkt_t p; if (!dl_pop_front(&g_buf, &p)) continue;

    /* Recompute slot window after potential wait in ring_pop to avoid using stale boundaries */
    pthread_mutex_lock(&g_epoch.mtx);
    T_open  = g_epoch.cur_us + (uint64_t)g_slot_start_us;
    T_close = T_open + (uint64_t)g_slot_len_us - (uint64_t)g_gi_tx_us;
    T_next  = g_epoch.next_us;
    pthread_mutex_unlock(&g_epoch.mtx);

    /* Compute airtime using TX payload + mesh trailer (legacy behavior) */
    uint32_t A_us = airtime_us_tx((size_t)p.len + (size_t)WFBX_TRAILER_BYTES, g_mcs_idx, g_gi_short, g_bw40, g_stbc);
    now = mono_us_raw();
    if (t_next_send == 0) t_next_send = (now > T_open) ? now : T_open;
    if (now < t_next_send) {
      uint64_t dtp = t_next_send - now; struct timespec ts={ dtp/1000000ull, (long)((dtp%1000000ull)*1000ull)}; nanosleep(&ts, NULL);
      now = mono_us_raw();
    }
    if (now > T_close) {
      /* We already popped one packet (p); account buffer-left including it (once) */
      if (!g_buf_left_sampled_this_slot) {
        uint64_t buf_left2 = dl_size(&g_buf) + 1;
        g_buf_left_sum += buf_left2;
        if (g_buf_left_min == UINT64_MAX || buf_left2 < g_buf_left_min) g_buf_left_min = buf_left2;
        if (buf_left2 > g_buf_left_max) g_buf_left_max = buf_left2;
        g_buf_left_cnt++;
        g_buf_left_sampled_this_slot = 1;
      }
      /* return packet and wait next superframe */
      (void)dl_push_front(&g_buf, &p);
      /* Sleep sliced until next superframe to avoid busy loop and refine epoch */
      sleep_until_boundary_sliced(1);
      t_next_send = 0;
      continue;
    }
    if (now + g_delta_us + A_us + g_tau_max_us + g_eps_us > T_close) {
      /* Put the packet back to the front so it goes first in the next window */
      (void)dl_push_front(&g_buf, &p);
      g_drop_in_window++;
      /* Sleep until next superframe to avoid busy loop */
      uint64_t dt = (T_next > now) ? (T_next - now) : 1000;
      struct timespec ts={ dt/1000000ull, (long)((dt%1000000ull)*1000ull)};
      nanosleep(&ts, NULL);
      t_next_send = 0;
      continue;
    }

    /* Diagnostics for this send */
    //int64_t delta_to_close = (int64_t)T_close - (int64_t)now;
    //uint64_t delta_slot_us = (uint64_t)(T_close - T_open);
    //fprintf(stderr, "[TX SEND] airtime_us=%u delta_to_close_us=%" PRId64 " delta_slot_us=%" PRIu64 "\n",
    //        (unsigned)A_us, (int64_t)delta_to_close, (uint64_t)delta_slot_us);

    int ret = send_packet(g_ph, p.data, p.len, g_seq,
                          (uint8_t)g_mcs_idx, g_gi_short, g_bw40, g_ldpc, g_stbc,
                          g_group_id, g_tx_id, g_link_id, g_radio_port);
    if (ret >= 0) {
      g_seq = (uint16_t)((g_seq + 1) & 0x0fff);
      g_sent_in_window++;
      g_sent_period++;
      pthread_mutex_lock(&g_stat_mtx);
      g_sent_bytes_period += (uint64_t)ret;
      pthread_mutex_unlock(&g_stat_mtx);
      /* delta_us/tau_max_us are already reflected in guards and T_close; pace by airtime only */
      t_next_send = now + (uint64_t)A_us + (uint64_t)g_send_guard_us;
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
  /* Append mesh trailer: epoch (LE64) + ts_tx (LE64, 0) + ts_rx (LE64, 0).
     Driver will overwrite ts_tx/ts_rx in-place. */
  {
    struct wfbx_mesh_trailer tr;
    memset(&tr, 0, sizeof(tr));
    tr.epoch_us_le = htole64(g_epoch_start_us);
    /* ts_tx_us_le and ts_rx_us_le stay zero as placeholders */
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
  const char* stat_ip = "127.0.0.1";
  int stat_port = 9601;
  const char* stat_id = "tx";
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
    {"stat_ip",    required_argument, 0, 0},
    {"stat_port",  required_argument, 0, 0},
    {"stat_id",    required_argument, 0, 0},
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
    {"send_gi",    required_argument, 0, 0},
    {"prewake_q",  required_argument, 0, 0},
    {"prewake_min",required_argument, 0, 0},
    {"stat_period",required_argument, 0, 0},
    {"epoch_sync", required_argument, 0, 0},
    {"help",       no_argument,       0, 0},
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
      else if (strcmp(name,"stat_ip")==0) stat_ip = val;
      else if (strcmp(name,"stat_port")==0) stat_port = atoi(val);
      else if (strcmp(name,"stat_id")==0) stat_id = val;
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
      else if (strcmp(name,"send_gi")==0)     g_send_guard_us= (uint32_t)atoi(val);
      else if (strcmp(name,"prewake_q")==0)   { g_prewake_quanta = atoi(val); if (g_prewake_quanta < 1) g_prewake_quanta = 1; }
      else if (strcmp(name,"prewake_min")==0) { g_prewake_min_us = (uint32_t)atoi(val); if (g_prewake_min_us < 100) g_prewake_min_us = 100; }
      else if (strcmp(name,"stat_period")==0) { int v=atoi(val); if (v>0 && v<=60000) g_stat_period_ms = v; }
      else if (strcmp(name,"epoch_sync")==0)  { if (val && (*val=='0' || strcasecmp(val,"off")==0)) g_ctrl_enabled = 0; else g_ctrl_enabled = 1; }
      else if (strcmp(name,"help")==0)        { print_help(argv[0]); return 0; }
    }
  }

  /* Optional env to enable/disable control sync: WFBX_CTRL=0/1 (CLI has priority) */
  const char* ctrl_env = getenv("WFBX_CTRL");
  if (ctrl_env) {
    int v = atoi(ctrl_env);
    if (v == 0) g_ctrl_enabled = 0;
    else if (v != 0) g_ctrl_enabled = 1;
  }

  /* Stats period (env) if CLI not set; CLI already applied above */
  const char* sp = getenv("WFBX_STAT_MS");
  if (sp) { int v = atoi(sp); if (v > 0 && v <= 60000) g_stat_period_ms = v; }

  if (optind >= argc) {
    fprintf(stderr, "Usage: sudo %s [--ip 0.0.0.0] [--port 5600] [--mcs_idx N] [--gi short|long] [--bw 20|40]\n"
                    "                [--ldpc 0|1] [--stbc 0..3] [--group_id G] [--tx_id T] [--link_id L] [--radio_port P] <wlan_iface>\n",
            argv[0]);
    return 1;
  }
  const char* iface = argv[optind];

  /* Prepare stats module metadata */
  memset(g_stat_module_id, 0, sizeof(g_stat_module_id));
  strncpy(g_stat_module_id, stat_id ? stat_id : "tx", sizeof(g_stat_module_id) - 1);
  g_stat_module_id[sizeof(g_stat_module_id) - 1] = '\0';
  g_stat_enabled = 0;
  if (stat_port > 0 && stat_port <= 65535) {
    memset(&g_stat_addr, 0, sizeof(g_stat_addr));
    g_stat_addr.sin_family = AF_INET;
    g_stat_addr.sin_port = htons((uint16_t)stat_port);
    if (!inet_aton(stat_ip, &g_stat_addr.sin_addr)) {
      fprintf(stderr, "[STATS] invalid stat_ip '%s' — TX stats disabled\n", stat_ip);
    } else {
      g_stat_sock = socket(AF_INET, SOCK_DGRAM, 0);
      if (g_stat_sock < 0) {
        perror("[STATS] socket");
      } else {
        g_stat_enabled = 1;
        fprintf(stderr, "[STATS] TX stats -> %s:%d id=%s (host will be set by statd)\n",
                stat_ip,
                stat_port,
                g_stat_module_id);
      }
    }
  } else {
    fprintf(stderr, "[STATS] stat_port=%d out of range — TX stats disabled\n", stat_port);
  }

  /* open UDP socket and bind */
  int us = socket(AF_INET, SOCK_DGRAM, 0);
  if (us < 0) { perror("socket"); return 1; }
  {
    int one = 1;
    (void)setsockopt(us, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    (void)setsockopt(us, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
  }
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
  /* Init list buffer */
  dl_init(&g_buf);
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
  /* Initialize base epoch (no MX adjustments). */
  pthread_mutex_lock(&g_epoch_base.mtx);
  g_epoch_base.len_us = g_epoch_len_us; g_epoch_base.gi_us = g_epoch_gi_us;
  pthread_mutex_unlock(&g_epoch_base.mtx);
  epoch_base_init_from_start(g_epoch_start_us);

  fprintf(stderr, "UDP %s:%d -> WLAN %s | MCS=%d GI=%s BW=%s LDPC=%d STBC=%d | G=%d TX=%d L=%d P=%d | mx=%s | stats -> %s:%d id=%s\n",
          ip, port, iface, mcs_idx, gi_short?"short":"long", bw40?"40":"20",
          ldpc, stbc, group_id, tx_id, link_id, radio_port, mx_addr_cli,
          stat_ip, stat_port, stat_id);

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
  if (g_cs >= 0) {
    close(g_cs);
    g_cs = -1;
  }
  if (g_stat_sock >= 0) {
    close(g_stat_sock);
    g_stat_sock = -1;
  }
  close(g_usock);
  return 0;
}
