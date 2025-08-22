// wfb_tx.c — UDP -> 802.11 injection (monitor mode) via Radiotap
// Preserves CLI and behavior of udp2wfb.c; uses shared defs from wfb_defs.h.
// Build: gcc -O2 -Wall -o wfb_tx wfb_tx.c -lpcap

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
    }
  }

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

  fprintf(stderr, "UDP %s:%d -> WLAN %s | MCS=%d GI=%s BW=%s LDPC=%d STBC=%d | G=%d TX=%d L=%d P=%d\n",
          ip, port, iface, mcs_idx, gi_short?"short":"long", bw40?"40":"20",
          ldpc, stbc, group_id, tx_id, link_id, radio_port);

  uint8_t buf[MAX_UDP_PAYLOAD];
  uint16_t seq = 0;

  while (g_run) {
    ssize_t n = recv(us, buf, sizeof(buf), 0);
    if (n < 0) { if (errno==EINTR) continue; perror("recv"); break; }
    if (n == 0) continue;

    int ret = send_packet(ph, buf, (size_t)n, seq,
                          (uint8_t)mcs_idx, gi_short, bw40, ldpc, stbc,
                          (uint8_t)group_id, (uint8_t)tx_id, (uint8_t)link_id, (uint8_t)radio_port);
    if (ret < 0) {
      fprintf(stderr, "send_packet failed\n");
      break;
    }
    seq = (uint16_t)((seq + 1) & 0x0fff);
  }

  if (ph) pcap_close(ph);
  close(us);
  return 0;
}