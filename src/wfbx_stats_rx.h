#ifndef WFBX_STATS_RX_H
#define WFBX_STATS_RX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WFBX_RX_SECTION_SUMMARY      = 0x0200,
    WFBX_RX_SECTION_TX_SUMMARY   = 0x0201,
    WFBX_RX_SECTION_IF_DETAIL    = 0x0210,
    WFBX_RX_SECTION_CHAIN_DETAIL = 0x0220,
    WFBX_RX_SECTION_FILTERS      = 0x0230
};

/* Global RX summary for the reporting interval. */
typedef struct {
    uint32_t dt_ms;
    uint32_t packets_total;
    uint32_t bytes_total;
    uint16_t iface_count;
    uint16_t tx_count;
    uint16_t filter_flags;   /* bit0: tx filter active, bit1: link filter active, bit2: radio filter active */
    uint16_t reserved;
} wfbx_rx_summary_t;

/* Per-TX aggregates (matching the RX view). */
typedef struct {
    uint8_t  tx_id;
    uint8_t  iface_count;
    uint16_t state_flags;
    uint32_t packets;
    uint32_t lost;
    uint16_t quality_permille;
    int16_t  rssi_q8;
    int32_t  rate_kbps;
} wfbx_rx_tx_summary_t;

/* Per-interface aggregates for a TX. */
typedef struct {
    uint8_t tx_id;
    uint8_t iface_id;
    uint8_t chain_count;
    uint8_t reserved0;
    uint32_t packets;
    uint32_t lost;
    uint16_t quality_permille;
    int16_t  best_chain_rssi_q8;
    uint16_t freq_mhz;
    uint16_t reserved1;
    /* Followed by chain_count entries of wfbx_rx_chain_detail_t */
} wfbx_rx_if_detail_t;

/* Per-chain (antenna) metrics within an interface. */
typedef struct {
    uint8_t  chain_id;
    uint8_t  ant_id;
    uint16_t quality_permille;
    int16_t  rssi_min_q8;
    int16_t  rssi_avg_q8;
    int16_t  rssi_max_q8;
    uint16_t packets;
    uint16_t lost;
} wfbx_rx_chain_detail_t;

/* Snapshot of active RX filters. */
typedef struct {
    uint8_t  group_id;       /* 0xFF if unused */
    uint8_t  txf_mode;       /* enum semantics match wfbx_rx CLI: 0=any,1=include,2=exclude */
    uint8_t  has_link_id;
    uint8_t  has_radio_port;
    int16_t  link_id;        /* valid when has_link_id != 0 */
    int16_t  radio_port;     /* valid when has_radio_port != 0 */
    const char* txf_spec;    /* textual representation of tx_id filter (may be NULL) */
} wfbx_rx_filter_info_t;

int wfbx_rx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_summary_t* summary);
int wfbx_rx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_tx_summary_t* src);
int wfbx_rx_if_detail_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_if_detail_t* hdr, const wfbx_rx_chain_detail_t* chains);
int wfbx_rx_chain_detail_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_chain_detail_t* src);
int wfbx_rx_filter_info_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_filter_info_t* filters);

#ifdef __cplusplus
}
#endif

#endif /* WFBX_STATS_RX_H */
