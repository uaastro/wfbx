#ifndef WFBX_STATS_TX_H
#define WFBX_STATS_TX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WFBX_TX_SECTION_SUMMARY = 0x0100,
    WFBX_TX_SECTION_QUEUE   = 0x0101,
    WFBX_TX_SECTION_SLOT    = 0x0102,
    WFBX_TX_SECTION_EPOCH   = 0x0103,
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
} wfbx_tx_summary_t;

int wfbx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_summary_t* src);

typedef struct {
    uint32_t avg;
    uint32_t min;
    uint32_t max;
    uint32_t samples;
} wfbx_tx_queue_stats_t;

int wfbx_tx_queue_stats_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_queue_stats_t* src);

typedef struct {
    uint32_t avg;
    uint32_t min;
    uint32_t max;
    uint32_t slots;
} wfbx_tx_slot_stats_t;

int wfbx_tx_slot_stats_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_slot_stats_t* src);

typedef struct {
    int32_t  e_epoch_base_us;
    uint32_t mx_epoch_msgs;
    uint32_t base_adv;
    uint32_t base_step_avg_us;
    uint32_t base_step_min_us;
    uint32_t base_step_max_us;
    uint32_t base_step_samples;
    uint32_t epoch_adj_count;
    uint32_t epoch_adj_avg_us;
    uint32_t epoch_adj_min_us;
    uint32_t epoch_adj_max_us;
} wfbx_tx_epoch_stats_t;

int wfbx_tx_epoch_stats_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_epoch_stats_t* src);

#ifdef __cplusplus
}
#endif

#endif /* WFBX_STATS_TX_H */
