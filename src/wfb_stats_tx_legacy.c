#include "wfb_stats_tx_legacy.h"

#include <string.h>
#include <arpa/inet.h>

int wfb_stats_tx_summary_pack(uint8_t* dst, size_t dst_len, const wfb_stats_tx_summary_t* summary)
{
    if (!dst || !summary || dst_len < sizeof(wfb_stats_tx_summary_t)) return -1;

    uint32_t fields[8] = {
        summary->dt_ms,
        summary->udp_rx_packets,
        summary->udp_rx_kbps_x10,
        summary->sent_packets,
        summary->sent_kbps_x10,
        summary->drop_overflow,
        summary->reserved0,
        summary->reserved1
    };

    for (size_t i = 0; i < 8; ++i) {
        uint32_t be = htonl(fields[i]);
        memcpy(dst + i * sizeof(uint32_t), &be, sizeof(uint32_t));
    }

    return (int)sizeof(wfb_stats_tx_summary_t);
}
