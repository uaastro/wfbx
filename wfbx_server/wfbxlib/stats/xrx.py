"""XRX (mesh RX) stats packet helpers."""

from __future__ import annotations

import dataclasses
import enum
import struct
from typing import List, Tuple


class SectionType(enum.IntEnum):
    SUMMARY = 0x0200
    TX_SUMMARY = 0x0201
    IF_DETAIL = 0x0210
    CHAIN_DETAIL = 0x0220
    FILTERS = 0x0230


SUMMARY_STRUCT = struct.Struct(
    ">IIIHHHH"
)


@dataclasses.dataclass
class Summary:
    dt_ms: int
    packets_total: int
    bytes_total: int
    iface_count: int
    tx_count: int
    filter_flags: int

    @classmethod
    def unpack(cls, data: bytes) -> "Summary":
        if len(data) != SUMMARY_STRUCT.size:
            raise ValueError("rx summary size mismatch")
        dt_ms, packets_total, bytes_total, iface_count, tx_count, filter_flags, _reserved = SUMMARY_STRUCT.unpack(data)
        return cls(
            dt_ms=dt_ms,
            packets_total=packets_total,
            bytes_total=bytes_total,
            iface_count=iface_count,
            tx_count=tx_count,
            filter_flags=filter_flags,
        )


TX_SUMMARY_STRUCT = struct.Struct(
    ">BBHIIHhI"
)


@dataclasses.dataclass
class TxSummary:
    tx_id: int
    iface_count: int
    state_flags: int
    packets: int
    lost: int
    quality_permille: int
    rssi_q8: int
    rate_kbps: int

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> "TxSummary":
        chunk = data[offset:offset + TX_SUMMARY_STRUCT.size]
        return cls(*TX_SUMMARY_STRUCT.unpack(chunk))


CHAIN_DETAIL_STRUCT = struct.Struct(
    ">BBHhhhHH"
)


@dataclasses.dataclass
class ChainDetail:
    chain_id: int
    ant_id: int
    quality_permille: int
    rssi_min_q8: int
    rssi_avg_q8: int
    rssi_max_q8: int
    packets: int
    lost: int

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> "ChainDetail":
        chunk = data[offset:offset + CHAIN_DETAIL_STRUCT.size]
        return cls(*CHAIN_DETAIL_STRUCT.unpack(chunk))


IF_DETAIL_STRUCT = struct.Struct(
    ">BBBBIIHhHH"
)


@dataclasses.dataclass
class IfDetail:
    tx_id: int
    iface_id: int
    packets: int
    lost: int
    quality_permille: int
    best_chain_rssi_q8: int
    freq_mhz: int
    chains: List[ChainDetail]

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> Tuple["IfDetail", int]:
        if offset + IF_DETAIL_STRUCT.size > len(data):
            raise ValueError("if detail header truncated")
        tx_id, iface_id, chain_count, _reserved0, packets, lost, quality_permille, best_rssi, freq_mhz, _reserved1 = IF_DETAIL_STRUCT.unpack(
            data[offset: offset + IF_DETAIL_STRUCT.size]
        )
        chains: List[ChainDetail] = []
        cursor = offset + IF_DETAIL_STRUCT.size
        for _ in range(chain_count):
            if cursor + CHAIN_DETAIL_STRUCT.size > len(data):
                raise ValueError("chain detail truncated")
            chains.append(ChainDetail.unpack_from(data, cursor))
            cursor += CHAIN_DETAIL_STRUCT.size
        return cls(
            tx_id=tx_id,
            iface_id=iface_id,
            packets=packets,
            lost=lost,
            quality_permille=quality_permille,
            best_chain_rssi_q8=best_rssi,
            freq_mhz=freq_mhz,
            chains=chains,
        ), cursor


FILTER_STRUCT = struct.Struct(
    ">BBBBhhH"
)


@dataclasses.dataclass
class FilterInfo:
    group_id: int
    txf_mode: int
    has_link_id: bool
    has_radio_port: bool
    link_id: int
    radio_port: int
    txf_spec: str

    @classmethod
    def unpack(cls, data: bytes) -> "FilterInfo":
        if len(data) < FILTER_STRUCT.size:
            raise ValueError("filter info truncated")
        group_id, txf_mode, has_link, has_port, link_id, radio_port, spec_len = FILTER_STRUCT.unpack(
            data[:FILTER_STRUCT.size]
        )
        spec_bytes = data[FILTER_STRUCT.size : FILTER_STRUCT.size + spec_len]
        spec = spec_bytes.decode("utf-8", "ignore") if spec_bytes else ""
        return cls(
            group_id=group_id,
            txf_mode=txf_mode,
            has_link_id=bool(has_link),
            has_radio_port=bool(has_port),
            link_id=link_id,
            radio_port=radio_port,
            txf_spec=spec,
        )


def unpack_tx_summary_section(payload: bytes) -> List[TxSummary]:
    size = TX_SUMMARY_STRUCT.size
    if len(payload) % size != 0:
        raise ValueError("tx summary section misaligned")
    entries: List[TxSummary] = []
    for offset in range(0, len(payload), size):
        entries.append(TxSummary.unpack_from(payload, offset))
    return entries


def unpack_if_detail_section(payload: bytes) -> List[IfDetail]:
    details: List[IfDetail] = []
    cursor = 0
    while cursor < len(payload):
        info, cursor_next = IfDetail.unpack_from(payload, cursor)
        details.append(info)
        cursor = cursor_next
    return details


def unpack_filter_section(payload: bytes) -> FilterInfo:
    return FilterInfo.unpack(payload)
