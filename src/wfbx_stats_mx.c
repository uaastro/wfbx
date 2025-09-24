#include "wfbx_stats_mx.h"

#include <string.h>
#include <arpa/inet.h>

static void store_u16(uint8_t* dst, uint16_t v)
{
    uint16_t be = htons(v);
    memcpy(dst, &be, sizeof(be));
}

static void store_u32(uint8_t* dst, uint32_t v)
{
    uint32_t be = htonl(v);
    memcpy(dst, &be, sizeof(be));
}

static void store_i16(uint8_t* dst, int16_t v)
{
    uint16_t be = htons((uint16_t)v);
    memcpy(dst, &be, sizeof(be));
}

static void store_i32(uint8_t* dst, int32_t v)
{
    uint32_t be = htonl((uint32_t)v);
    memcpy(dst, &be, sizeof(be));
}

static size_t bounded_strnlen(const char* s, size_t max_len)
{
    size_t len = 0;
    if (!s) return 0;
    while (len < max_len && s[len] != '\0') ++len;
    return len;
}

int wfbx_mx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_summary_t* summary)
{
    if (!dst || !summary || dst_len < sizeof(wfbx_mx_summary_t)) return -1;
    store_u32(dst + 0, summary->dt_ms);
    store_u32(dst + 4, summary->packets_total);
    store_u32(dst + 8, summary->bytes_total);
    store_u32(dst + 12, summary->ctrl_epoch_sent);
    store_u16(dst + 16, summary->iface_count);
    store_u16(dst + 18, summary->tx_count);
    store_u16(dst + 20, summary->flags);
    store_u16(dst + 22, summary->reserved);
    return (int)sizeof(wfbx_mx_summary_t);
}

int wfbx_mx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_tx_summary_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_mx_tx_summary_t)) return -1;
    dst[0] = src->tx_id;
    dst[1] = src->if_count;
    store_u16(dst + 2, src->state_flags);
    store_u32(dst + 4, src->packets);
    store_u32(dst + 8, src->lost);
    store_i16(dst + 12, src->rssi_q8);
    store_u16(dst + 14, src->quality_permille);
    store_i32(dst + 16, src->rate_kbps);
    store_i32(dst + 20, src->debug_real_delta_q4);
    store_i32(dst + 24, src->debug_e_delta_q4);
    return (int)sizeof(wfbx_mx_tx_summary_t);
}

static int pack_chain(uint8_t* dst, size_t dst_len, const wfbx_mx_chain_detail_t* src)
{
    if (dst_len < sizeof(wfbx_mx_chain_detail_t)) return -1;
    dst[0] = src->chain_id;
    dst[1] = src->ant_id;
    store_u16(dst + 2, src->quality_permille);
    store_i16(dst + 4, src->rssi_min_q8);
    store_i16(dst + 6, src->rssi_avg_q8);
    store_i16(dst + 8, src->rssi_max_q8);
    store_u16(dst + 10, src->packets);
    store_u16(dst + 12, src->lost);
    return (int)sizeof(wfbx_mx_chain_detail_t);
}

int wfbx_mx_if_detail_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_if_detail_t* hdr, const wfbx_mx_chain_detail_t* chains)
{
    if (!dst || !hdr || (hdr->chain_count > 0 && !chains)) return -1;
    size_t needed = sizeof(wfbx_mx_if_detail_t) + (size_t)hdr->chain_count * sizeof(wfbx_mx_chain_detail_t);
    if (dst_len < needed) return -1;
    dst[0] = hdr->tx_id;
    dst[1] = hdr->iface_id;
    dst[2] = hdr->chain_count;
    dst[3] = hdr->reserved0;
    store_u32(dst + 4, hdr->packets);
    store_u32(dst + 8, hdr->lost);
    store_u16(dst + 12, hdr->quality_permille);
    store_i16(dst + 14, hdr->best_chain_rssi_q8);
    store_u16(dst + 16, hdr->freq_mhz);
    store_u16(dst + 18, hdr->reserved1);
    uint8_t* p = dst + sizeof(wfbx_mx_if_detail_t);
    for (uint8_t i = 0; i < hdr->chain_count; ++i) {
        if (pack_chain(p, dst + needed - p, &chains[i]) < 0) return -1;
        p += sizeof(wfbx_mx_chain_detail_t);
    }
    return (int)needed;
}

int wfbx_mx_global_debug_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_global_debug_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_mx_global_debug_t)) return -1;
    store_i32(dst + 0, src->real_delta_avg_q4);
    store_i32(dst + 4, src->real_delta_min_q4);
    store_i32(dst + 8, src->real_delta_max_q4);
    store_u32(dst + 12, src->real_delta_samples);
    store_i32(dst + 16, src->e_delta_avg_q4);
    store_i32(dst + 20, src->e_delta_min_q4);
    store_i32(dst + 24, src->e_delta_max_q4);
    store_u32(dst + 28, src->e_delta_samples);
    store_i32(dst + 32, src->e_epoch_avg_q4);
    store_i32(dst + 36, src->e_epoch_min_q4);
    store_i32(dst + 40, src->e_epoch_max_q4);
    store_u32(dst + 44, src->e_epoch_samples);
    store_i32(dst + 48, src->e_epoch_last_avg_q4);
    store_i32(dst + 52, src->e_epoch_last_min_q4);
    store_i32(dst + 56, src->e_epoch_last_max_q4);
    store_u32(dst + 60, src->e_epoch_last_samples);
    return (int)sizeof(wfbx_mx_global_debug_t);
}

int wfbx_mx_filter_info_pack(uint8_t* dst, size_t dst_len, const wfbx_mx_filter_info_t* src)
{
    if (!dst || !src) return -1;
    size_t spec_cap = sizeof(src->tx_filter_spec);
    size_t spec_len = bounded_strnlen(src->tx_filter_spec, spec_cap);
    if (spec_len > 255) spec_len = 255;
    size_t needed = 5u + spec_len;
    if (dst_len < needed) return -1;
    dst[0] = src->version;
    dst[1] = src->tx_filter_mode;
    store_i16(dst + 2, src->group_id);
    dst[4] = (uint8_t)spec_len;
    if (spec_len > 0) memcpy(dst + 5, src->tx_filter_spec, spec_len);
    return (int)needed;
}
