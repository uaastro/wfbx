#include "wfbx_stats_core.h"

#include <string.h>
#include <arpa/inet.h>

static void copy_fixed_string(char dest[], size_t dest_len, const char* src)
{
    size_t n = 0;
    if (src) {
        n = strnlen(src, dest_len);
        memcpy(dest, src, n);
    }
    if (n < dest_len) {
        memset(dest + n, 0, dest_len - n);
    }
}

int wfbx_stats_header_init(wfbx_stats_header_t* hdr,
                           uint8_t version,
                           uint8_t module_type,
                           const char* module_id,
                           const char* host_id,
                           uint32_t tick_id,
                           uint64_t timestamp_us,
                           uint16_t flags,
                           uint16_t section_count,
                           uint32_t payload_len)
{
    if (!hdr) return -1;
    memcpy(hdr->magic, WFBX_STATS_MAGIC, WFBX_STATS_MAGIC_LEN);
    hdr->version = version;
    hdr->module_type = module_type;
    copy_fixed_string(hdr->module_id, sizeof(hdr->module_id), module_id);
    copy_fixed_string(hdr->host_id, sizeof(hdr->host_id), host_id);
    hdr->tick_id = tick_id;
    hdr->timestamp_us = timestamp_us;
    hdr->flags = flags;
    hdr->section_count = section_count;
    hdr->payload_len = payload_len;
    hdr->reserved = 0;
    hdr->crc32 = 0;
    return 0;
}

int wfbx_stats_header_validate(const wfbx_stats_header_t* hdr)
{
    if (!hdr) return -1;
    if (memcmp(hdr->magic, WFBX_STATS_MAGIC, WFBX_STATS_MAGIC_LEN) != 0) return -1;
    if (hdr->version == 0) return -1;
    return 0;
}

uint32_t wfbx_stats_crc32(const uint8_t* data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        uint32_t byte = data[i];
        crc ^= byte;
        for (int j = 0; j < 8; ++j) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

int wfbx_stats_sections_parse(const uint8_t* payload,
                              uint32_t payload_len,
                              wfbx_stats_section_t* sections,
                              uint16_t section_capacity)
{
    if (!payload || !sections) return -1;
    uint32_t offset = 0;
    uint16_t count = 0;
    while (offset + 4 <= payload_len && count < section_capacity) {
        const uint8_t* p = payload + offset;
        uint16_t type = (uint16_t)((p[0] << 8) | p[1]);
        uint16_t length = (uint16_t)((p[2] << 8) | p[3]);
        offset += 4;
        if (offset + length > payload_len) {
            return -1;
        }
        sections[count].type = type;
        sections[count].length = length;
        sections[count].data = payload + offset;
        offset += length;
        count++;
    }
    return count;
}

static uint64_t wfbx_htonll(uint64_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(v >> 32))) | ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFF)) << 32);
#else
    return v;
#endif
}

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

static void store_u64(uint8_t* dst, uint64_t v)
{
    uint64_t be = wfbx_htonll(v);
    memcpy(dst, &be, sizeof(be));
}

int wfbx_stats_header_pack(uint8_t* dst, size_t dst_len, const wfbx_stats_header_t* hdr)
{
    if (!dst || !hdr || dst_len < WFBX_STATS_HEADER_SIZE) return -1;
    memcpy(dst, hdr->magic, 4);
    dst[4] = hdr->version;
    dst[5] = hdr->module_type;
    memcpy(dst + 6, hdr->module_id, sizeof hdr->module_id);
    memcpy(dst + 30, hdr->host_id, sizeof hdr->host_id);
    store_u32(dst + 46, hdr->tick_id);
    store_u64(dst + 50, hdr->timestamp_us);
    store_u16(dst + 58, hdr->flags);
    store_u16(dst + 60, hdr->section_count);
    store_u32(dst + 62, hdr->payload_len);
    store_u16(dst + 66, hdr->reserved);
    store_u32(dst + 68, hdr->crc32);
    return 0;
}
