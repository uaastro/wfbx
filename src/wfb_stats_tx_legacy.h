#ifndef WFB_STATS_TX_LEGACY_H
#define WFB_STATS_TX_LEGACY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WFB_STATS_TX_SECTION_SUMMARY = 0x0100
};

typedef struct {
    uint32_t dt_ms;
    uint32_t udp_rx_packets;
    uint32_t udp_rx_kbps_x10;
    uint32_t sent_packets;
    uint32_t sent_kbps_x10;
    uint32_t drop_overflow;
    uint32_t reserved0;
    uint32_t reserved1;
} wfb_stats_tx_summary_t;

int wfb_stats_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfb_stats_tx_summary_t* summary);

#ifdef __cplusplus
}
#endif

#endif /* WFB_STATS_TX_LEGACY_H */
