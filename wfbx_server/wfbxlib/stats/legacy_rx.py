"""Legacy RX (wfb_rx) stats helpers."""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import List


class SectionType(enum.IntEnum):
    SUMMARY = 0x1200
    TX_SUMMARY = 0x1201
    FILTERS = 0x1230


@dataclass
class Summary:
    dt_ms: int
    packets_total: int
    bytes_total: int
    iface_count: int
    tx_count: int
    filter_flags: int

    @classmethod
    def unpack(cls, data: bytes) -> "Summary":
        if len(data) != 20:
            raise ValueError("legacy rx summary size mismatch")
        dt_ms, packets_total, bytes_total, iface_count, tx_count, filter_flags, _reserved = struct.unpack(
            ">IIIHHHH", data
        )
        return cls(
            dt_ms=dt_ms,
            packets_total=packets_total,
            bytes_total=bytes_total,
            iface_count=iface_count,
            tx_count=tx_count,
            filter_flags=filter_flags,
        )


@dataclass
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
    def unpack(cls, data: bytes) -> "TxSummary":
        if len(data) != 20:
            raise ValueError("legacy rx tx summary size mismatch")
        tx_id, iface_count, state_flags, packets, lost, quality, rssi_q8, rate_kbps = struct.unpack(
            ">BBHIIHhi", data
        )
        return cls(
            tx_id=tx_id,
            iface_count=iface_count,
            state_flags=state_flags,
            packets=packets,
            lost=lost,
            quality_permille=quality,
            rssi_q8=rssi_q8,
            rate_kbps=rate_kbps,
        )


def unpack_tx_summary_section(data: bytes) -> List[TxSummary]:
    if len(data) % 20 != 0:
        raise ValueError("legacy rx tx summary payload misaligned")
    entries: List[TxSummary] = []
    for offset in range(0, len(data), 20):
        entries.append(TxSummary.unpack(data[offset : offset + 20]))
    return entries


@dataclass
class FilterInfo:
    txf_mode: int
    has_link_id: bool
    has_radio_port: bool
    link_id: int
    radio_port: int
    txf_spec: str
    group_id: int = 0xFF

    @classmethod
    def unpack(cls, data: bytes) -> "FilterInfo":
        if len(data) < 10:
            raise ValueError("legacy rx filter section too short")
        group_id, txf_mode, has_link_id, has_radio_port, link_id, radio_port, spec_len = struct.unpack(
            ">BBBBhhH", data[:10]
        )
        if spec_len > len(data) - 10:
            raise ValueError("legacy rx filter spec truncated")
        spec_bytes = data[10 : 10 + spec_len]
        spec = spec_bytes.decode("ascii", "ignore") if spec_len > 0 else ""
        return cls(
            txf_mode=txf_mode,
            has_link_id=bool(has_link_id),
            has_radio_port=bool(has_radio_port),
            link_id=link_id,
            radio_port=radio_port,
            txf_spec=spec,
            group_id=group_id,
        )
