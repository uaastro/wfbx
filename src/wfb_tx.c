// wfb_tx.c — UDP -> 802.11 injection (monitor mode) via Radiotap
// Preserves CLI and behavior of udp2wfb.c; uses shared defs from wfb_defs.h.
// Build: gcc -O2 -Wall -o wfb_tx wfb_tx.c -lpcap

#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif

#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <getopt.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

#ifdef __linux__
  #include <endian.h>
#elif defined(__APPLE__)
  #include <libkern/OSByteOrder.h>
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

#include "wfb_defs.h"
#include "wfbx_stats_core.h"
#include "wfb_stats_tx_legacy.h"

#define MAX_FRAME        4096
#define MAX_UDP_PAYLOAD  2000
#define WFB_TX_STATS_MAX_PACKET 512

typedef enum {
  DRIVER_WFB = 0,
  DRIVER_WFBX = 1
} driver_mode_t;

static inline uint32_t clamp_u32(uint64_t v) {
  return (v > UINT32_MAX) ? UINT32_MAX : (uint32_t)v;
}

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

static inline uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static inline uint64_t mono_us_raw(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

static int append_section(uint8_t* dst, size_t* offset, size_t cap,
                          uint16_t type, const uint8_t* data, uint16_t length)
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
static volatile int g_run = 1;
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

/* Send one packet (payload) via pcap_inject with given TX params */
static int send_packet(pcap_t* ph,
                       const uint8_t* payload, size_t payload_len, uint16_t seq_num,
                       uint8_t mcs_idx, int gi_short, int bw40, int ldpc, int stbc,
                       uint8_t group_id, uint8_t tx_id, uint8_t link_id, uint8_t radio_port,
                       driver_mode_t driver_mode)
{
  uint8_t frame[MAX_FRAME];
  size_t pos = 0;

  pos += build_radiotap(frame + pos, mcs_idx, gi_short, bw40, ldpc, stbc);
  pos += build_dot11  (frame + pos, seq_num, group_id, tx_id, link_id, radio_port);

  const size_t trailer_len = (driver_mode == DRIVER_WFBX) ? (size_t)WFBX_TRAILER_BYTES : 0u;
  if (pos + payload_len + trailer_len > sizeof(frame)) return -1;

  if (payload_len > 0) {
    memcpy(frame + pos, payload, payload_len);
    pos += payload_len;
  }

  if (trailer_len > 0) {
    struct wfbx_mesh_trailer tr;
    memset(&tr, 0, sizeof(tr));
    memcpy(frame + pos, &tr, trailer_len);
    pos += trailer_len;
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
  int stat_period_ms = 1000;
  driver_mode_t driver_mode = DRIVER_WFBX;

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
    {"stat_ip",    required_argument, 0, 0},
    {"stat_port",  required_argument, 0, 0},
    {"stat_id",    required_argument, 0, 0},
    {"stat_period",required_argument, 0, 0},
    {"driver",     required_argument, 0, 0},
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
      else if (strcmp(name,"stat_ip")==0)  stat_ip = val;
      else if (strcmp(name,"stat_port")==0) stat_port = atoi(val);
      else if (strcmp(name,"stat_id")==0)  stat_id = val;
      else if (strcmp(name,"stat_period")==0) stat_period_ms = atoi(val);
      else if (strcmp(name,"driver")==0) {
        if (strcasecmp(val, "wfbx") == 0) driver_mode = DRIVER_WFBX;
        else if (strcasecmp(val, "wfb") == 0) driver_mode = DRIVER_WFB;
        else {
          fprintf(stderr, "Unknown --driver value '%s' (use wfb|wfbx)\n", val);
          return 1;
        }
      }
    }
  }

  if (optind >= argc) {
    fprintf(stderr,
            "Usage: sudo %s [--ip 0.0.0.0] [--port 5600] [--mcs_idx N] [--gi short|long] [--bw 20|40]\n"
            "                [--ldpc 0|1] [--stbc 0..3] [--group_id G] [--tx_id T] [--link_id L] [--radio_port P]\n"
            "                [--stat_ip 127.0.0.1] [--stat_port 9601] [--stat_id tx] [--stat_period 1000]\n"
            "                [--driver wfb|wfbx]\n"
            "                <wlan_iface>\n",
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

  if (stat_period_ms <= 0) stat_period_ms = 1000;

  int stats_enabled = (stat_period_ms > 0 && stat_port > 0);
  int stat_sock = -1;
  struct sockaddr_in stat_addr;
  memset(&stat_addr, 0, sizeof(stat_addr));
  uint32_t stat_tick_id = 0;
  if (stats_enabled) {
    stat_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (stat_sock < 0) {
      perror("stat socket");
      stats_enabled = 0;
    } else {
      stat_addr.sin_family = AF_INET;
      stat_addr.sin_port = htons((uint16_t)stat_port);
      if (inet_pton(AF_INET, stat_ip, &stat_addr.sin_addr) != 1) {
        fprintf(stderr, "[STATS] invalid stat_ip '%s' — TX stats disabled\n", stat_ip);
        close(stat_sock);
        stat_sock = -1;
        stats_enabled = 0;
      }
    }
  }

  /* open pcap on iface (monitor mode expected) */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* ph = pcap_create(iface, errbuf);
  if (!ph) {
    fprintf(stderr, "pcap_create(%s): %s\n", iface, errbuf);
    close(us);
    return 0;
  }
  (void)pcap_set_immediate_mode(ph, 1);
  if (pcap_activate(ph) != 0) {
    fprintf(stderr, "pcap_activate(%s): %s\n", iface, pcap_geterr(ph));
    pcap_close(ph);
    close(us);
    return 0;
  }

  signal(SIGINT, on_sigint);

  fprintf(stderr, "UDP %s:%d -> WLAN %s | MCS=%d GI=%s BW=%s LDPC=%d STBC=%d | G=%d TX=%d L=%d P=%d | driver=%s | stats -> %s:%d id=%s period=%d ms%s\n",
          ip, port, iface, mcs_idx, gi_short?"short":"long", bw40?"40":"20",
          ldpc, stbc, group_id, tx_id, link_id, radio_port,
          (driver_mode == DRIVER_WFBX) ? "wfbx" : "wfb",
          stat_ip, stat_port, stat_id, stat_period_ms,
          stats_enabled ? "" : " (disabled)");

  uint8_t buf[MAX_UDP_PAYLOAD];
  uint16_t seq = 0;
  uint64_t rx_pkts_period = 0;
  uint64_t rx_bytes_period = 0;
  uint64_t tx_pkts_period = 0;
  uint64_t tx_bytes_period = 0;
  uint64_t t_stats = now_ms();

  while (g_run) {
    ssize_t n = recv(us, buf, sizeof(buf), 0);
    if (n < 0) { if (errno==EINTR) continue; perror("recv"); break; }
    if (n == 0) continue;

    rx_pkts_period += 1;
    rx_bytes_period += (uint64_t)n;

    int ret = send_packet(ph, buf, (size_t)n, seq,
                          (uint8_t)mcs_idx, gi_short, bw40, ldpc, stbc,
                          (uint8_t)group_id, (uint8_t)tx_id, (uint8_t)link_id, (uint8_t)radio_port,
                          driver_mode);
    if (ret < 0) {
      const char* perr = pcap_geterr(ph);
      fprintf(stderr, "pcap_inject(%s) failed: %s\n", iface, perr ? perr : "unknown error");
      break;
    }
    if (ret > 0) {
      tx_pkts_period += 1;
      tx_bytes_period += (uint64_t)ret;
    }
    seq = (uint16_t)((seq + 1) & 0x0fff);

    if (stats_enabled) {
      uint64_t t_now = now_ms();
      if (t_now - t_stats >= (uint64_t)stat_period_ms) {
        uint64_t dt_ms64 = t_now - t_stats;
        if (dt_ms64 == 0) dt_ms64 = (uint64_t)stat_period_ms;

        double rx_rate_kbps = (dt_ms64 > 0) ? ((double)rx_bytes_period * 8.0) / (double)dt_ms64 : 0.0;
        double tx_rate_kbps = (dt_ms64 > 0) ? ((double)tx_bytes_period * 8.0) / (double)dt_ms64 : 0.0;

        unsigned __int128 rx_num = (unsigned __int128)rx_bytes_period * 80u;
        unsigned __int128 tx_num = (unsigned __int128)tx_bytes_period * 80u;
        uint64_t rx_rate_x10 = (dt_ms64 > 0) ? (uint64_t)(rx_num / dt_ms64) : 0;
        uint64_t tx_rate_x10 = (dt_ms64 > 0) ? (uint64_t)(tx_num / dt_ms64) : 0;
        if (rx_rate_x10 > UINT32_MAX) rx_rate_x10 = UINT32_MAX;
        if (tx_rate_x10 > UINT32_MAX) tx_rate_x10 = UINT32_MAX;

        fprintf(stderr,
                "[STATS] dt=%llu ms | rx_pkts=%llu rate=%.1f kbps | tx_pkts=%llu rate=%.1f kbps\n",
                (unsigned long long)dt_ms64,
                (unsigned long long)rx_pkts_period, rx_rate_kbps,
                (unsigned long long)tx_pkts_period, tx_rate_kbps);

        wfb_stats_tx_summary_t summary = {
          .dt_ms = clamp_u32(dt_ms64),
          .udp_rx_packets = clamp_u32(rx_pkts_period),
          .udp_rx_kbps_x10 = (uint32_t)rx_rate_x10,
          .sent_packets = clamp_u32(tx_pkts_period),
          .sent_kbps_x10 = (uint32_t)tx_rate_x10,
          .drop_overflow = 0,
          .reserved0 = 0,
          .reserved1 = 0,
        };

        uint8_t summary_buf[sizeof(wfb_stats_tx_summary_t)];
        int summary_len = wfb_stats_tx_summary_pack(summary_buf, sizeof(summary_buf), &summary);

        if (summary_len > 0) {
          uint8_t payload[WFB_TX_STATS_MAX_PACKET - WFBX_STATS_HEADER_SIZE];
          size_t payload_off = 0;
          uint16_t section_count = 0;
          if (append_section(payload, &payload_off, sizeof(payload),
                             WFB_STATS_TX_SECTION_SUMMARY,
                             summary_buf, (uint16_t)summary_len) == 0) {
            section_count++;

            char preview_buf[128];
            int preview_len = snprintf(preview_buf, sizeof(preview_buf),
                                       "pks_rx=%llu rate_rx=%.1f pks_tx=%llu rate_tx=%.1f",
                                       (unsigned long long)rx_pkts_period,
                                       rx_rate_kbps,
                                       (unsigned long long)tx_pkts_period,
                                       tx_rate_kbps);
            if (preview_len > 0 && preview_len < (int)sizeof(preview_buf)) {
              if (append_section(payload, &payload_off, sizeof(payload),
                                 WFBX_SECTION_TEXT_PREVIEW,
                                 (const uint8_t*)preview_buf,
                                 (uint16_t)preview_len) == 0) {
                section_count++;
              }
            }

            uint8_t packet[WFB_TX_STATS_MAX_PACKET];
            wfbx_stats_header_t hdr;
            if (wfbx_stats_header_init(&hdr,
                                       1,
                                       WFBX_MODULE_TX,
                                       stat_id,
                                       NULL,
                                       stat_tick_id++,
                                       mono_us_raw(),
                                       0,
                                       section_count,
                                       (uint32_t)payload_off) == 0) {
              if (wfbx_stats_header_pack(packet, sizeof(packet), &hdr) == 0) {
                memcpy(packet + WFBX_STATS_HEADER_SIZE, payload, payload_off);
                size_t total_len = WFBX_STATS_HEADER_SIZE + payload_off;
                hdr.crc32 = wfbx_stats_crc32(packet, total_len);
                if (wfbx_stats_header_pack(packet, sizeof(packet), &hdr) == 0) {
                  (void)sendto(stat_sock, packet, total_len, 0,
                               (struct sockaddr*)&stat_addr, sizeof(stat_addr));
                }
              }
            }
          }
        }

        t_stats = t_now;
        rx_pkts_period = 0;
        rx_bytes_period = 0;
        tx_pkts_period = 0;
        tx_bytes_period = 0;
      }
    }
  }

  if (ph) pcap_close(ph);
  close(us);
  if (stat_sock >= 0) close(stat_sock);
  return 0;
}
