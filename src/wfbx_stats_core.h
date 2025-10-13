#ifndef WFBX_STATS_CORE_H
#define WFBX_STATS_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WFBX_STATS_MAGIC "WFBX"
#define WFBX_STATS_MAGIC_LEN 4

typedef enum {
    WFBX_MODULE_TX = 1,
    WFBX_MODULE_RX = 2,
    WFBX_MODULE_MX = 3,
    WFBX_MODULE_PTX = 4,
    WFBX_MODULE_UNKNOWN = 255
} wfbx_module_type_t;

typedef struct {
    char     magic[4];
    uint8_t  version;
    uint8_t  module_type; /* wfbx_module_type_t */
    char     module_id[24];
    char     host_id[16];  /* Emitters leave this zeroed; statd populates on ingest */
    uint32_t tick_id;
    uint64_t timestamp_us;
    uint16_t flags;
    uint16_t section_count;
    uint32_t payload_len;
    uint16_t reserved;
    uint32_t crc32;
} wfbx_stats_header_t;

typedef struct {
    uint16_t type;
    uint16_t length;
    const uint8_t* data;
} wfbx_stats_section_t;

enum {
    WFBX_SECTION_SUMMARY      = 0x0001,
    WFBX_SECTION_TEXT_PREVIEW = 0x00F0
};

int wfbx_stats_header_init(wfbx_stats_header_t* hdr,
                           uint8_t version,
                           uint8_t module_type,
                           const char* module_id,
                           const char* host_id,
                           uint32_t tick_id,
                           uint64_t timestamp_us,
                           uint16_t flags,
                           uint16_t section_count,
                           uint32_t payload_len);

int wfbx_stats_header_validate(const wfbx_stats_header_t* hdr);

uint32_t wfbx_stats_crc32(const uint8_t* data, size_t len);

int wfbx_stats_sections_parse(const uint8_t* payload,
                              uint32_t payload_len,
                              wfbx_stats_section_t* sections,
                              uint16_t section_capacity);

int wfbx_stats_header_pack(uint8_t* dst, size_t dst_len, const wfbx_stats_header_t* hdr);
#define WFBX_STATS_HEADER_SIZE 72

#ifdef __cplusplus
}
#endif

#endif /* WFBX_STATS_CORE_H */
