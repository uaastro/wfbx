#ifndef WFBX_STATS_MX_H
#define WFBX_STATS_MX_H

#include "wfbx_stats_core.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WFBX_MX_SECTION_TX_SUMMARY   = 0x0002,
    WFBX_MX_SECTION_GLOBAL_DEBUG = 0x0003,
    WFBX_MX_SECTION_FILTER_INFO  = 0x0004,
    WFBX_MX_SECTION_IF_DETAIL    = 0x0010,
    WFBX_MX_SECTION_ANT_DETAIL   = 0x0020
};

enum {
    WFBX_MX_TX_FLAG_DEBUG = 0x0001
};

typedef struct {
    uint8_t  tx_id;
    uint8_t  if_count;
    uint16_t state_flags;
    uint32_t packets;
    uint32_t lost;
    int16_t  rssi_q8;
    uint16_t quality_permille;
    int32_t  rate_kbps;
    int32_t  debug_real_delta_q4;
    int32_t  debug_e_delta_q4;
} wfbx_mx_tx_summary_t;

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
    /* Followed by chain_count entries of wfbx_mx_chain_detail_t */
} wfbx_mx_if_detail_t;

typedef struct {
    uint8_t  chain_id;
    uint8_t  ant_id;
    uint16_t quality_permille;
    int16_t  rssi_min_q8;
    int16_t  rssi_avg_q8;
    int16_t  rssi_max_q8;
    uint16_t packets;
    uint16_t lost;
} wfbx_mx_chain_detail_t;

typedef struct {
    int32_t real_delta_avg_q4;
    int32_t real_delta_min_q4;
    int32_t real_delta_max_q4;
    uint32_t real_delta_samples;
    int32_t e_delta_avg_q4;
    int32_t e_delta_min_q4;
    int32_t e_delta_max_q4;
    uint32_t e_delta_samples;
    int32_t e_epoch_avg_q4;
    int32_t e_epoch_min_q4;
    int32_t e_epoch_max_q4;
    uint32_t e_epoch_samples;
    int32_t e_epoch_last_avg_q4;
    int32_t e_epoch_last_min_q4;
    int32_t e_epoch_last_max_q4;
    uint32_t e_epoch_last_samples;
} wfbx_mx_global_debug_t;

typedef struct {
    uint8_t version;
    uint8_t tx_filter_mode;
    int16_t group_id;
    char    tx_filter_spec[64];
} wfbx_mx_filter_info_t;

typedef struct {
    uint32_t dt_ms;
    uint32_t packets_total;
    uint32_t bytes_total;
    uint32_t ctrl_epoch_sent;
    uint16_t iface_count;
    uint16_t tx_count;
    uint16_t flags;
    uint16_t reserved;
} wfbx_mx_summary_t;

int wfbx_mx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_tx_summary_t* src);
int wfbx_mx_if_detail_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_if_detail_t* hdr, const wfbx_mx_chain_detail_t* chains);
int wfbx_mx_global_debug_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_global_debug_t* src);
int wfbx_mx_filter_info_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_filter_info_t* src);
int wfbx_mx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_summary_t* summary);


#ifdef __cplusplus
}
#endif

#endif /* WFBX_STATS_MX_H */
