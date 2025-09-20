"""MX-specific stats packet helpers."""

from __future__ import annotations

import dataclasses
import enum
import struct
from typing import Iterable, List, Sequence

from . import core


class SectionType(enum.IntEnum):
    TX_SUMMARY = 0x0002
    GLOBAL_DEBUG = 0x0003
    IF_DETAIL = 0x0010
    ANT_DETAIL = 0x0020


TX_SUMMARY_STRUCT = struct.Struct(
    ">BBHIIhHiii"
)


@dataclasses.dataclass
class TxSummary:
    tx_id: int
    iface_count: int
    state_flags: int
    packets: int
    lost: int
    rssi_q8: int
    quality_permille: int
    rate_kbps: int
    debug_real_delta_q4: int = 0
    debug_e_delta_q4: int = 0

    def pack(self) -> bytes:
        return TX_SUMMARY_STRUCT.pack(
            self.tx_id,
            self.iface_count,
            self.state_flags,
            self.packets,
            self.lost,
            self.rssi_q8,
            self.quality_permille,
            self.rate_kbps,
            self.debug_real_delta_q4,
            self.debug_e_delta_q4,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "TxSummary":
        if len(data) != TX_SUMMARY_STRUCT.size:
            raise ValueError("tx summary size mismatch")
        return cls(*TX_SUMMARY_STRUCT.unpack(data))


IF_DETAIL_STRUCT = struct.Struct(
    ">BBBBIIHh"
)


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

    def pack(self) -> bytes:
        return CHAIN_DETAIL_STRUCT.pack(
            self.chain_id,
            self.ant_id,
            self.quality_permille,
            self.rssi_min_q8,
            self.rssi_avg_q8,
            self.rssi_max_q8,
            self.packets,
            self.lost,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "ChainDetail":
        if len(data) != CHAIN_DETAIL_STRUCT.size:
            raise ValueError("chain detail size mismatch")
        return cls(*CHAIN_DETAIL_STRUCT.unpack(data))


@dataclasses.dataclass
class IfDetail:
    tx_id: int
    iface_id: int
    chains: List[ChainDetail]
    packets: int
    lost: int
    quality_permille: int
    best_chain_rssi_q8: int

    def pack(self) -> bytes:
        header = IF_DETAIL_STRUCT.pack(
            self.tx_id,
            self.iface_id,
            len(self.chains),
            0,
            self.packets,
            self.lost,
            self.quality_permille,
            self.best_chain_rssi_q8,
        )
        chain_payload = b"".join(chain.pack() for chain in self.chains)
        return header + chain_payload

    @classmethod
    def unpack(cls, data: bytes) -> "IfDetail":
        if len(data) < IF_DETAIL_STRUCT.size:
            raise ValueError("if detail header truncated")
        tx_id, iface_id, chain_count, _reserved, packets, lost, quality_permille, best_rssi = IF_DETAIL_STRUCT.unpack(
            data[: IF_DETAIL_STRUCT.size]
        )
        chains: List[ChainDetail] = []
        offset = IF_DETAIL_STRUCT.size
        for _ in range(chain_count):
            chunk = data[offset : offset + CHAIN_DETAIL_STRUCT.size]
            chains.append(ChainDetail.unpack(chunk))
            offset += CHAIN_DETAIL_STRUCT.size
        return cls(
            tx_id=tx_id,
            iface_id=iface_id,
            chains=chains,
            packets=packets,
            lost=lost,
            quality_permille=quality_permille,
            best_chain_rssi_q8=best_rssi,
        )


GLOBAL_DEBUG_STRUCT = struct.Struct(
    ">iiiIiiiIiiiIiiiI"
)


@dataclasses.dataclass
class GlobalDebug:
    real_delta_avg_q4: int
    real_delta_min_q4: int
    real_delta_max_q4: int
    real_delta_samples: int
    e_delta_avg_q4: int
    e_delta_min_q4: int
    e_delta_max_q4: int
    e_delta_samples: int
    e_epoch_avg_q4: int
    e_epoch_min_q4: int
    e_epoch_max_q4: int
    e_epoch_samples: int
    e_epoch_last_avg_q4: int
    e_epoch_last_min_q4: int
    e_epoch_last_max_q4: int
    e_epoch_last_samples: int

    def pack(self) -> bytes:
        return GLOBAL_DEBUG_STRUCT.pack(
            self.real_delta_avg_q4,
            self.real_delta_min_q4,
            self.real_delta_max_q4,
            self.real_delta_samples,
            self.e_delta_avg_q4,
            self.e_delta_min_q4,
            self.e_delta_max_q4,
            self.e_delta_samples,
            self.e_epoch_avg_q4,
            self.e_epoch_min_q4,
            self.e_epoch_max_q4,
            self.e_epoch_samples,
            self.e_epoch_last_avg_q4,
            self.e_epoch_last_min_q4,
            self.e_epoch_last_max_q4,
            self.e_epoch_last_samples,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "GlobalDebug":
        if len(data) != GLOBAL_DEBUG_STRUCT.size:
            raise ValueError("global debug size mismatch")
        return cls(*GLOBAL_DEBUG_STRUCT.unpack(data))


def pack_tx_summary_section(entries: Sequence[TxSummary]) -> bytes:
    return b"".join(entry.pack() for entry in entries)


def unpack_tx_summary_section(data: bytes) -> List[TxSummary]:
    size = TX_SUMMARY_STRUCT.size
    if len(data) % size != 0:
        raise ValueError("tx summary section misaligned")
    return [TxSummary.unpack(data[i : i + size]) for i in range(0, len(data), size)]


def pack_if_detail_section(entries: Sequence[IfDetail]) -> bytes:
    return b"".join(entry.pack() for entry in entries)


def unpack_if_detail_section(data: bytes) -> List[IfDetail]:
    details: List[IfDetail] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < IF_DETAIL_STRUCT.size:
            raise ValueError("if detail section truncated")
        chain_count = data[offset + 2]
        entry_len = IF_DETAIL_STRUCT.size + chain_count * CHAIN_DETAIL_STRUCT.size
        chunk = data[offset : offset + entry_len]
        details.append(IfDetail.unpack(chunk))
        offset += entry_len
    return details


__all__ = [
    "SectionType",
    "TxSummary",
    "ChainDetail",
    "IfDetail",
    "GlobalDebug",
    "pack_tx_summary_section",
    "unpack_tx_summary_section",
    "pack_if_detail_section",
    "unpack_if_detail_section",
]
