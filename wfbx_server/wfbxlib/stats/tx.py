"""Legacy TX (wfb_tx) stats helpers."""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass


class SectionType(enum.IntEnum):
    SUMMARY = 0x0100


_SUMMARY_STRUCT = struct.Struct(">IIIIIIII")


@dataclass
class Summary:
    dt_ms: int
    udp_rx_packets: int
    udp_rx_kbps_x10: int
    sent_packets: int
    sent_kbps_x10: int
    drop_overflow: int
    reserved0: int = 0
    reserved1: int = 0

    @classmethod
    def unpack(cls, data: bytes) -> "Summary":
        if len(data) != _SUMMARY_STRUCT.size:
            raise ValueError("tx summary size mismatch")
        return cls(*_SUMMARY_STRUCT.unpack(data))

    def pack(self) -> bytes:
        return _SUMMARY_STRUCT.pack(
            self.dt_ms,
            self.udp_rx_packets,
            self.udp_rx_kbps_x10,
            self.sent_packets,
            self.sent_kbps_x10,
            self.drop_overflow,
            self.reserved0,
            self.reserved1,
        )


def unpack_summary_section(data: bytes) -> Summary:
    return Summary.unpack(data)


def pack_summary_section(summary: Summary) -> bytes:
    return summary.pack()


__all__ = [
    "SectionType",
    "Summary",
    "unpack_summary_section",
    "pack_summary_section",
]
