#ifndef WFBX_STATS_PTX_H
#define WFBX_STATS_PTX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    WFBX_PTX_SECTION_SUMMARY = 0x0300
};

typedef struct {
    uint32_t dt_ms;
    uint32_t rx_packets;
    uint32_t rx_bytes;
    uint32_t fwd_packets;
    uint32_t fwd_bytes;
    uint32_t drop_packets;
    uint32_t drop_bytes;
} wfbx_ptx_summary_t;

int wfbx_ptx_summary_pack(uint8_t* dst, size_t dst_len, const wfbx_ptx_summary_t* src);

#ifdef __cplusplus
}
#endif

#endif /* WFBX_STATS_PTX_H */
