#include "wfbx_stats_rx.h"

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

int wfbx_rx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_summary_t* summary)
{
    if (!dst || !summary || dst_len < sizeof(wfbx_rx_summary_t)) return -1;
    store_u32(dst + 0, summary->dt_ms);
    store_u32(dst + 4, summary->packets_total);
    store_u32(dst + 8, summary->bytes_total);
    store_u16(dst + 12, summary->iface_count);
    store_u16(dst + 14, summary->tx_count);
    store_u16(dst + 16, summary->filter_flags);
    store_u16(dst + 18, summary->reserved);
    return (int)sizeof(wfbx_rx_summary_t);
}

int wfbx_rx_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_tx_summary_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_rx_tx_summary_t)) return -1;
    dst[0] = src->tx_id;
    dst[1] = src->iface_count;
    store_u16(dst + 2, src->state_flags);
    store_u32(dst + 4, src->packets);
    store_u32(dst + 8, src->lost);
    store_u16(dst + 12, src->quality_permille);
    store_i16(dst + 14, src->rssi_q8);
    store_i32(dst + 16, src->rate_kbps);
    return (int)sizeof(wfbx_rx_tx_summary_t);
}

int wfbx_rx_chain_detail_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_chain_detail_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_rx_chain_detail_t)) return -1;
    dst[0] = src->chain_id;
    dst[1] = src->ant_id;
    store_u16(dst + 2, src->quality_permille);
    store_i16(dst + 4, src->rssi_min_q8);
    store_i16(dst + 6, src->rssi_avg_q8);
    store_i16(dst + 8, src->rssi_max_q8);
    store_u16(dst + 10, src->packets);
    store_u16(dst + 12, src->lost);
    return (int)sizeof(wfbx_rx_chain_detail_t);
}

int wfbx_rx_if_detail_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_if_detail_t* hdr, const wfbx_rx_chain_detail_t* chains)
{
    if (!dst || !hdr || (hdr->chain_count > 0 && !chains)) return -1;
    size_t needed = sizeof(wfbx_rx_if_detail_t) + (size_t)hdr->chain_count * sizeof(wfbx_rx_chain_detail_t);
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
    uint8_t* p = dst + sizeof(wfbx_rx_if_detail_t);
    for (uint8_t i = 0; i < hdr->chain_count; ++i) {
        if (wfbx_rx_chain_detail_pack(p, dst + needed - p, &chains[i]) < 0) return -1;
        p += sizeof(wfbx_rx_chain_detail_t);
    }
    return (int)needed;
}

int wfbx_rx_filter_info_pack(uint8_t* dst, size_t dst_len, const wfbx_rx_filter_info_t* filters)
{
    if (!dst || !filters || dst_len < 10u) return -1;
    const char* spec = filters->txf_spec;
    size_t spec_len = spec ? strlen(spec) : 0;
    if (spec_len > 0xFFFF) spec_len = 0xFFFF;
    size_t needed = 10u + spec_len;
    if (dst_len < needed) return -1;
    dst[0] = filters->group_id;
    dst[1] = filters->txf_mode;
    dst[2] = filters->has_link_id;
    dst[3] = filters->has_radio_port;
    store_i16(dst + 4, filters->link_id);
    store_i16(dst + 6, filters->radio_port);
    store_u16(dst + 8, (uint16_t)spec_len);
    if (spec_len > 0) memcpy(dst + 10, spec, spec_len);
    return (int)needed;
}
