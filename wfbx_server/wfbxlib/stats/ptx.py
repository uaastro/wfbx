"""Helpers for PTX statistics sections."""

from __future__ import annotations

import struct
from dataclasses import dataclass

_PTX_SUMMARY_STRUCT = struct.Struct(
    ">IIIIIII"
)


@dataclass
class Summary:
    dt_ms: int
    rx_packets: int
    rx_bytes: int
    fwd_packets: int
    fwd_bytes: int
    drop_packets: int
    drop_bytes: int

    @classmethod
    def unpack(cls, data: bytes) -> "Summary":
        if len(data) != _PTX_SUMMARY_STRUCT.size:
            raise ValueError("ptx summary size mismatch")
        return cls(*_PTX_SUMMARY_STRUCT.unpack(data))


__all__ = ["Summary"]
