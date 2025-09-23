#include "wfbx_stats_tx.h"

#include <string.h>
#include <arpa/inet.h>

static void store_u32(uint8_t* dst, uint32_t v)
{
    uint32_t be = htonl(v);
    memcpy(dst, &be, sizeof(be));
}

static void store_i32(uint8_t* dst, int32_t v)
{
    uint32_t be = htonl((uint32_t)v);
    memcpy(dst, &be, sizeof(be));
}

int wfbx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_summary_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_tx_summary_t)) return -1;
    store_u32(dst + 0, src->dt_ms);
    store_u32(dst + 4, src->udp_rx_packets);
    store_u32(dst + 8, src->udp_rx_kbps_x10);
    store_u32(dst + 12, src->sent_packets);
    store_u32(dst + 16, src->sent_kbps_x10);
    store_u32(dst + 20, src->drop_overflow);
    store_u32(dst + 24, src->reserved0);
    store_u32(dst + 28, src->reserved1);
    return (int)sizeof(wfbx_tx_summary_t);
}

int wfbx_tx_queue_stats_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_queue_stats_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_tx_queue_stats_t)) return -1;
    store_u32(dst + 0, src->avg);
    store_u32(dst + 4, src->min);
    store_u32(dst + 8, src->max);
    store_u32(dst + 12, src->samples);
    return (int)sizeof(wfbx_tx_queue_stats_t);
}

int wfbx_tx_slot_stats_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_slot_stats_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_tx_slot_stats_t)) return -1;
    store_u32(dst + 0, src->avg);
    store_u32(dst + 4, src->min);
    store_u32(dst + 8, src->max);
    store_u32(dst + 12, src->slots);
    return (int)sizeof(wfbx_tx_slot_stats_t);
}

int wfbx_tx_epoch_stats_pack(uint8_t* dst, size_t dst_len, const wfbx_tx_epoch_stats_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_tx_epoch_stats_t)) return -1;
    store_i32(dst + 0, src->e_epoch_base_us);
    store_u32(dst + 4, src->mx_epoch_msgs);
    store_u32(dst + 8, src->base_adv);
    store_u32(dst + 12, src->base_step_avg_us);
    store_u32(dst + 16, src->base_step_min_us);
    store_u32(dst + 20, src->base_step_max_us);
    store_u32(dst + 24, src->base_step_samples);
    store_u32(dst + 28, src->epoch_adj_count);
    store_u32(dst + 32, src->epoch_adj_avg_us);
    store_u32(dst + 36, src->epoch_adj_min_us);
    store_u32(dst + 40, src->epoch_adj_max_us);
    return (int)sizeof(wfbx_tx_epoch_stats_t);
}
