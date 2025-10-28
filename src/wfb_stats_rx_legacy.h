#ifndef WFB_STATS_RX_LEGACY_H
#define WFB_STATS_RX_LEGACY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WFB_STATS_RX_SECTION_SUMMARY     = 0x1200,
    WFB_STATS_RX_SECTION_TX_SUMMARY  = 0x1201,
    WFB_STATS_RX_SECTION_FILTERS     = 0x1230,
};

typedef struct {
    uint32_t dt_ms;
    uint32_t packets_total;
    uint32_t bytes_total;
    uint16_t iface_count;
    uint16_t tx_count;
    uint16_t filter_flags;
    uint16_t reserved;
} wfb_stats_rx_summary_t;

typedef struct {
    uint8_t  tx_id;
    uint8_t  iface_count;
    uint16_t state_flags;
    uint32_t packets;
    uint32_t lost;
    uint16_t quality_permille;
    int16_t  rssi_q8;
    int32_t  rate_kbps;
} wfb_stats_rx_tx_summary_t;

typedef struct {
    uint8_t  group_id;
    uint8_t  txf_mode;
    uint8_t  has_link_id;
    uint8_t  has_radio_port;
    int16_t  link_id;
    int16_t  radio_port;
    const char* txf_spec;   /* optional, may be NULL */
} wfb_stats_rx_filter_info_t;

int wfb_stats_rx_summary_pack(uint8_t* dst, size_t dst_len, const wfb_stats_rx_summary_t* summary);
int wfb_stats_rx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfb_stats_rx_tx_summary_t* src);
int wfb_stats_rx_filter_info_pack(uint8_t* dst, size_t dst_len, const wfb_stats_rx_filter_info_t* filters);

#ifdef __cplusplus
}
#endif

#endif /* WFB_STATS_RX_LEGACY_H */
