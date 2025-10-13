// wfbx_ptx.c — UDP pre-TX multiplexer feeding wfbx_tx

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <limits.h>
#include <getopt.h>

#include "wfb_defs.h"
#include "wfbx_stats_core.h"
#include "wfbx_stats_ptx.h"

#define PTX_MAX_PAYLOAD   4096
#define PTX_BUFFER_SIZE  (WFBX_PTX_HDR_BYTES + PTX_MAX_PAYLOAD)

static volatile sig_atomic_t g_run = 1;
static void on_signal(int signo){ (void)signo; g_run = 0; }

static const char* g_bind_ip = "0.0.0.0";
static int         g_bind_port = 5600;
static uint8_t     g_radio_port = 0;
static const char* g_xtx_ip = "127.0.0.1";
static int         g_xtx_port = 4600;

static uint32_t    g_stat_period_ms = 1000;
static const char* g_stat_ip = "127.0.0.1";
static int         g_stat_port = 9601;
static char        g_stat_module_id[24] = "ptx";

static int              g_stat_sock = -1;
static int              g_stat_enabled = 0;
static struct sockaddr_in g_stat_addr;
static uint32_t         g_stat_tick_id = 0;
static uint8_t          g_stat_packet[512];

static uint64_t g_period_start_ms = 0;
static uint64_t g_rx_packets_period = 0;
static uint64_t g_rx_bytes_period = 0;
static uint64_t g_fwd_packets_period = 0;
static uint64_t g_fwd_bytes_period = 0;
static uint64_t g_drop_packets_period = 0;
static uint64_t g_drop_bytes_period = 0;

static uint16_t g_seq12 = 0;

static uint64_t now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint64_t mono_us_raw(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

static uint32_t clamp_u32(uint64_t v)
{
  return (v > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (uint32_t)v;
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
  if (length && data) memcpy(dst + *offset + 4, data, length);
  *offset += 4u + (size_t)length;
  return 0;
}

static void stats_send_summary(uint32_t dt_ms)
{
  if (!g_stat_enabled || dt_ms == 0) return;

  uint8_t payload_buf[256];
  size_t payload_off = 0;
  uint16_t section_count = 0;

  wfbx_ptx_summary_t summary;
  summary.dt_ms        = dt_ms;
  summary.rx_packets   = clamp_u32(g_rx_packets_period);
  summary.rx_bytes     = clamp_u32(g_rx_bytes_period);
  summary.fwd_packets  = clamp_u32(g_fwd_packets_period);
  summary.fwd_bytes    = clamp_u32(g_fwd_bytes_period);
  summary.drop_packets = clamp_u32(g_drop_packets_period);
  summary.drop_bytes   = clamp_u32(g_drop_bytes_period);

  uint8_t section_buf[sizeof(wfbx_ptx_summary_t)];
  int packed = wfbx_ptx_summary_pack(section_buf, sizeof(section_buf), &summary);
  if (packed < 0) {
    fprintf(stderr, "[STATS] PTX summary pack failed\n");
    return;
  }

  if (stats_append_section(payload_buf, &payload_off, sizeof(payload_buf),
                           WFBX_PTX_SECTION_SUMMARY,
                           section_buf, (uint16_t)packed) != 0) {
    fprintf(stderr, "[STATS] PTX append summary failed\n");
    return;
  }
  section_count++;

  wfbx_stats_header_t hdr;
  if (wfbx_stats_header_init(&hdr,
                             1,
                             WFBX_MODULE_PTX,
                             g_stat_module_id,
                             NULL,
                             ++g_stat_tick_id,
                             mono_us_raw(),
                             0,
                             section_count,
                             (uint32_t)payload_off) != 0) {
    fprintf(stderr, "[STATS] PTX header init failed\n");
    return;
  }

  uint8_t header_buf[WFBX_STATS_HEADER_SIZE];
  if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &hdr) != 0) {
    fprintf(stderr, "[STATS] PTX header pack failed\n");
    return;
  }

  memcpy(g_stat_packet, header_buf, WFBX_STATS_HEADER_SIZE);
  memcpy(g_stat_packet + WFBX_STATS_HEADER_SIZE, payload_buf, payload_off);

  size_t total_len = WFBX_STATS_HEADER_SIZE + payload_off;
  hdr.crc32 = wfbx_stats_crc32(g_stat_packet, total_len);
  if (wfbx_stats_header_pack(header_buf, sizeof(header_buf), &hdr) != 0) {
    fprintf(stderr, "[STATS] PTX header pack (crc) failed\n");
    return;
  }
  memcpy(g_stat_packet, header_buf, WFBX_STATS_HEADER_SIZE);

  ssize_t sent = sendto(g_stat_sock, g_stat_packet, total_len, 0,
                        (const struct sockaddr*)&g_stat_addr, sizeof(g_stat_addr));
  if (sent < 0) {
    perror("ptx stats sendto");
  }
}

static void stats_reset_period(void)
{
  g_rx_packets_period = 0;
  g_rx_bytes_period = 0;
  g_fwd_packets_period = 0;
  g_fwd_bytes_period = 0;
  g_drop_packets_period = 0;
  g_drop_bytes_period = 0;
}

static void print_help(const char* prog)
{
  printf(
    "Usage: %s [options]\n"
    "\nOptions (defaults in brackets):\n"
    "  --ip <addr>           Bind IP for incoming UDP [%s]\n"
    "  --port <num>          Bind port for incoming UDP [%d]\n"
    "  --radio_port <id>     Radio port tag for forwarded traffic [%u]\n"
    "  --xtx_ip <addr>       Destination wfbx_tx IP [%s]\n"
    "  --xtx_port <num>      Destination wfbx_tx port [%d]\n"
    "  --stat_period <ms>    Statistics interval [%u]\n"
    "  --stat_ip <addr>      Stats collector IP [%s]\n"
    "  --stat_port <num>     Stats collector port [%d]\n"
    "  --stat_id <name>      Stats module identifier [%s]\n"
    "  --help                Show this help and exit\n",
    prog,
    g_bind_ip, g_bind_port,
    (unsigned)g_radio_port,
    g_xtx_ip, g_xtx_port,
    g_stat_period_ms,
    g_stat_ip, g_stat_port,
    g_stat_module_id
  );
}

static void parse_args(int argc, char** argv)
{
  static struct option longopts[] = {
    { "ip",           required_argument, 0, 0 },
    { "port",         required_argument, 0, 0 },
    { "radio_port",   required_argument, 0, 0 },
    { "xtx_ip",       required_argument, 0, 0 },
    { "xtx_port",     required_argument, 0, 0 },
    { "stat_period",  required_argument, 0, 0 },
    { "stat_ip",      required_argument, 0, 0 },
    { "stat_port",    required_argument, 0, 0 },
    { "stat_id",      required_argument, 0, 0 },
    { "help",         no_argument,       0, 0 },
    { 0,0,0,0 }
  };

  int optidx = 0;
  while (1) {
    int c = getopt_long(argc, argv, "", longopts, &optidx);
    if (c == -1) break;
    if (c != 0) {
      print_help(argv[0]);
      exit(1);
    }
    const char* name = longopts[optidx].name;
    const char* val  = optarg ? optarg : "";
    char* end = NULL;

    if (strcmp(name, "ip") == 0) {
      g_bind_ip = val;
    } else if (strcmp(name, "port") == 0) {
      long tmp = strtol(val, &end, 10);
      if (!end || *end != '\0' || tmp <= 0 || tmp > 65535) {
        fprintf(stderr, "Invalid --port value '%s'\n", val);
        exit(1);
      }
      g_bind_port = (int)tmp;
    } else if (strcmp(name, "radio_port") == 0) {
      long tmp = strtol(val, &end, 10);
      if (!end || *end != '\0' || tmp < 0 || tmp > 255) {
        fprintf(stderr, "Invalid --radio_port value '%s'\n", val);
        exit(1);
      }
      g_radio_port = (uint8_t)tmp;
    } else if (strcmp(name, "xtx_ip") == 0) {
      g_xtx_ip = val;
    } else if (strcmp(name, "xtx_port") == 0) {
      long tmp = strtol(val, &end, 10);
      if (!end || *end != '\0' || tmp <= 0 || tmp > 65535) {
        fprintf(stderr, "Invalid --xtx_port value '%s'\n", val);
        exit(1);
      }
      g_xtx_port = (int)tmp;
    } else if (strcmp(name, "stat_period") == 0) {
      long tmp = strtol(val, &end, 10);
      if (!end || *end != '\0' || tmp < 0) {
        fprintf(stderr, "Invalid --stat_period value '%s'\n", val);
        exit(1);
      }
      g_stat_period_ms = (uint32_t)tmp;
    } else if (strcmp(name, "stat_ip") == 0) {
      g_stat_ip = val;
    } else if (strcmp(name, "stat_port") == 0) {
      long tmp = strtol(val, &end, 10);
      if (!end || *end != '\0' || tmp < 0 || tmp > 65535) {
        fprintf(stderr, "Invalid --stat_port value '%s'\n", val);
        exit(1);
      }
      g_stat_port = (int)tmp;
    } else if (strcmp(name, "stat_id") == 0) {
      snprintf(g_stat_module_id, sizeof(g_stat_module_id), "%s", val);
    } else if (strcmp(name, "help") == 0) {
      print_help(argv[0]);
      exit(0);
    }
  }

  if (optind != argc) {
    print_help(argv[0]);
    exit(1);
  }
}

int main(int argc, char** argv)
{
  parse_args(argc, argv);

  int rx_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (rx_sock < 0) {
    perror("socket");
    return 1;
  }
  int one = 1;
  (void)setsockopt(rx_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port   = htons((uint16_t)g_bind_port);
  if (!inet_aton(g_bind_ip, &bind_addr.sin_addr)) {
    fprintf(stderr, "Invalid bind IP %s\n", g_bind_ip);
    close(rx_sock);
    return 1;
  }
  if (bind(rx_sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
    perror("bind");
    close(rx_sock);
    return 1;
  }

  int tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (tx_sock < 0) {
    perror("socket tx");
    close(rx_sock);
    return 1;
  }

  struct sockaddr_in tx_addr;
  memset(&tx_addr, 0, sizeof(tx_addr));
  tx_addr.sin_family = AF_INET;
  tx_addr.sin_port   = htons((uint16_t)g_xtx_port);
  if (!inet_aton(g_xtx_ip, &tx_addr.sin_addr)) {
    fprintf(stderr, "Invalid xtx IP %s\n", g_xtx_ip);
    close(tx_sock);
    close(rx_sock);
    return 1;
  }

  g_stat_enabled = (g_stat_period_ms > 0 && g_stat_port > 0);
  if (g_stat_enabled) {
    g_stat_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_stat_sock < 0) {
      perror("stats socket");
      g_stat_enabled = 0;
    } else {
      memset(&g_stat_addr, 0, sizeof(g_stat_addr));
      g_stat_addr.sin_family = AF_INET;
      g_stat_addr.sin_port   = htons((uint16_t)g_stat_port);
      if (!inet_aton(g_stat_ip, &g_stat_addr.sin_addr)) {
        fprintf(stderr, "Invalid stat IP %s\n", g_stat_ip);
        close(g_stat_sock);
        g_stat_sock = -1;
        g_stat_enabled = 0;
      }
    }
  }

  signal(SIGINT,  on_signal);
  signal(SIGTERM, on_signal);

  g_period_start_ms = now_ms();
  stats_reset_period();

  struct pollfd pfd;
  pfd.fd = rx_sock;
  pfd.events = POLLIN;
  pfd.revents = 0;

  uint8_t rx_buf[PTX_MAX_PAYLOAD];
  uint8_t tx_buf[PTX_BUFFER_SIZE];

  while (g_run) {
    uint64_t loop_start_ms = now_ms();
    int timeout_ms = -1;
    if (g_stat_enabled && g_stat_period_ms > 0) {
      uint64_t elapsed = loop_start_ms - g_period_start_ms;
      if (elapsed >= g_stat_period_ms) {
        timeout_ms = 0;
      } else {
        uint64_t remain = g_stat_period_ms - elapsed;
        timeout_ms = (remain > (uint64_t)INT_MAX) ? INT_MAX : (int)remain;
      }
    }

    int pret = poll(&pfd, 1, timeout_ms);
    if (pret < 0) {
      if (errno == EINTR) continue;
      perror("poll");
      break;
    }
    if (pret == 0) {
      uint64_t now_tick = now_ms();
      uint64_t dt64 = (now_tick > g_period_start_ms) ? (now_tick - g_period_start_ms) : g_stat_period_ms;
      uint32_t dt = clamp_u32(dt64);
      stats_send_summary(dt);
      stats_reset_period();
      g_period_start_ms = now_tick;
      continue;
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      fprintf(stderr, "poll: socket error\n");
      break;
    }
    if (!(pfd.revents & POLLIN)) continue;

    ssize_t n = recvfrom(rx_sock, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
    if (n < 0) {
      if (errno == EINTR) continue;
      perror("recvfrom");
      break;
    }

    g_rx_packets_period++;
    g_rx_bytes_period += (uint64_t)n;

    struct wfbx_ptx_hdr hdr;
    hdr.radio_port = g_radio_port;
    uint16_t seq = (uint16_t)(g_seq12 & WFBX_SEQ12_MASK);
    hdr.seq_be = htons(seq);
    g_seq12 = (uint16_t)((seq + 1u) & WFBX_SEQ12_MASK);

    memcpy(tx_buf, &hdr, WFBX_PTX_HDR_BYTES);
    memcpy(tx_buf + WFBX_PTX_HDR_BYTES, rx_buf, (size_t)n);

    size_t frame_len = WFBX_PTX_HDR_BYTES + (size_t)n;
    ssize_t sent = sendto(tx_sock, tx_buf, frame_len, 0,
                          (struct sockaddr*)&tx_addr, sizeof(tx_addr));
    if (sent != (ssize_t)frame_len) {
      if (sent < 0) perror("sendto");
      g_drop_packets_period++;
      g_drop_bytes_period += (uint64_t)n;
    } else {
      g_fwd_packets_period++;
      g_fwd_bytes_period += (uint64_t)n;
    }

    if (g_stat_enabled && g_stat_period_ms > 0) {
      uint64_t now_tick = now_ms();
      if (now_tick - g_period_start_ms >= g_stat_period_ms) {
        uint64_t dt64 = now_tick - g_period_start_ms;
        uint32_t dt = clamp_u32(dt64);
        stats_send_summary(dt);
        stats_reset_period();
        g_period_start_ms = now_tick;
      }
    }
  }

  if (g_stat_enabled && g_stat_period_ms > 0) {
    uint64_t now_tick = now_ms();
    uint64_t dt64 = (now_tick > g_period_start_ms) ? (now_tick - g_period_start_ms) : 0;
    if (dt64 > 0 && (g_rx_packets_period || g_fwd_packets_period || g_drop_packets_period)) {
      stats_send_summary(clamp_u32(dt64));
    }
  }

  if (g_stat_sock >= 0) close(g_stat_sock);
  close(tx_sock);
  close(rx_sock);
  return 0;
}
