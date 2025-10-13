#include "wfbx_stats_ptx.h"

#include <string.h>
#include <arpa/inet.h>

static void store_u32(uint8_t* dst, uint32_t v)
{
    uint32_t be = htonl(v);
    memcpy(dst, &be, sizeof(be));
}

int wfbx_ptx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_ptx_summary_t* src)
{
    if (!dst || !src || dst_len < sizeof(wfbx_ptx_summary_t)) return -1;
    store_u32(dst + 0, src->dt_ms);
    store_u32(dst + 4, src->rx_packets);
    store_u32(dst + 8, src->rx_bytes);
    store_u32(dst + 12, src->fwd_packets);
    store_u32(dst + 16, src->fwd_bytes);
    store_u32(dst + 20, src->drop_packets);
    store_u32(dst + 24, src->drop_bytes);
    return (int)sizeof(wfbx_ptx_summary_t);
}
