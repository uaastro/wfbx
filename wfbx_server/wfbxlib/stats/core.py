"""Core helpers for WFBX stats packets (module-agnostic)."""

from __future__ import annotations

import dataclasses
import enum
import struct
import zlib
from typing import Iterable, List, Sequence, Tuple


MAGIC = b"WFBX"
HEADER_STRUCT = struct.Struct(
    ">4sBB24s16sIQHHIHI"
)  # magic, version, module_type, module_id, host_id, tick_id, timestamp, flags, section_count, payload_len, reserved, crc32


class ModuleType(enum.IntEnum):
    TX = 1
    RX = 2
    MX = 3
    UNKNOWN = 255


class SectionType(enum.IntEnum):
    SUMMARY = 0x0001
    TEXT_PREVIEW = 0x00F0


@dataclasses.dataclass
class Header:
    version: int
    module_type: ModuleType
    module_id: str
    tick_id: int
    timestamp_us: int
    flags: int
    section_count: int
    payload_len: int
    host_id: str = ""
    crc32: int = 0

    def pack(self) -> bytes:
        module_bytes = self.module_id.encode("ascii", "ignore")[:24]
        module_bytes = module_bytes.ljust(24, b"\0")
        host_bytes = self.host_id.encode("ascii", "ignore")[:16]
        host_bytes = host_bytes.ljust(16, b"\0")
        reserved = 0
        return HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            int(self.module_type),
            module_bytes,
            host_bytes,
            self.tick_id,
            self.timestamp_us,
            self.flags,
            self.section_count,
            self.payload_len,
            reserved,
            self.crc32,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        if len(data) < HEADER_STRUCT.size:
            raise ValueError("header truncated")
        magic, version, module_type, module_id, host_id, tick_id, timestamp_us, flags, section_count, payload_len, reserved, crc32 = HEADER_STRUCT.unpack(
            data[: HEADER_STRUCT.size]
        )
        if magic != MAGIC:
            raise ValueError("invalid stats magic")
        module_id_str = module_id.rstrip(b"\0").decode("ascii", "ignore")
        host_id_str = host_id.rstrip(b"\0").decode("ascii", "ignore")
        return cls(
            version=version,
            module_type=ModuleType(module_type),
            module_id=module_id_str,
            host_id=host_id_str,
            tick_id=tick_id,
            timestamp_us=timestamp_us,
            flags=flags,
            section_count=section_count,
            payload_len=payload_len,
            crc32=crc32,
        )


def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _packet_for_crc(header: Header, payload: bytes) -> bytes:
    h = dataclasses.replace(header, crc32=0)
    return h.pack() + payload


def build_packet(header: Header, sections: Sequence[Tuple[int, bytes]], *, with_crc: bool = False) -> bytes:
    payload_parts: List[bytes] = []
    for section_type, body in sections:
        payload_parts.append(struct.pack(">HH", section_type, len(body)))
        payload_parts.append(body)
    payload = b"".join(payload_parts)
    header.section_count = len(sections)
    header.payload_len = len(payload)
    if with_crc:
        crc = compute_crc32(_packet_for_crc(header, payload))
        header.crc32 = crc
    else:
        header.crc32 = 0
    return header.pack() + payload


def decode_packet(packet: bytes, *, verify_crc: bool = False) -> Tuple[Header, List[Tuple[int, bytes]]]:
    if len(packet) < HEADER_STRUCT.size:
        raise ValueError("packet too short")
    header = Header.unpack(packet)
    expected_len = HEADER_STRUCT.size + header.payload_len
    if len(packet) < expected_len:
        raise ValueError("payload truncated")
    payload = packet[HEADER_STRUCT.size : expected_len]
    if verify_crc and header.crc32:
        buf = bytearray(packet[:expected_len])
        # zero CRC field before computing
        crc_offset = HEADER_STRUCT.size - 4
        buf[crc_offset:crc_offset + 4] = b"\0\0\0\0"
        if compute_crc32(buf) != header.crc32:
            raise ValueError("CRC mismatch")
    sections = parse_sections(payload, header.section_count)
    return header, sections


def parse_sections(payload: bytes, expected_count: int) -> List[Tuple[int, bytes]]:
    offset = 0
    sections: List[Tuple[int, bytes]] = []
    for _ in range(expected_count):
        if offset + 4 > len(payload):
            raise ValueError("section header truncated")
        section_type, length = struct.unpack_from(">HH", payload, offset)
        offset += 4
        if offset + length > len(payload):
            raise ValueError("section payload truncated")
        sections.append((section_type, payload[offset : offset + length]))
        offset += length
    return sections


SUMMARY_STRUCT = struct.Struct(">IIIIHHHH")


@dataclasses.dataclass
class Summary:
    dt_ms: int
    packets_total: int
    bytes_total: int
    ctrl_epoch_sent: int
    iface_count: int
    tx_count: int
    flags: int

    def pack(self) -> bytes:
        return SUMMARY_STRUCT.pack(
            self.dt_ms,
            self.packets_total,
            self.bytes_total,
            self.ctrl_epoch_sent,
            self.iface_count,
            self.tx_count,
            self.flags,
            0,  # reserved
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Summary":
        if len(data) != SUMMARY_STRUCT.size:
            raise ValueError("summary size mismatch")
        dt_ms, packets_total, bytes_total, ctrl_epoch_sent, iface_count, tx_count, flags, _reserved = SUMMARY_STRUCT.unpack(data)
        return cls(
            dt_ms=dt_ms,
            packets_total=packets_total,
            bytes_total=bytes_total,
            ctrl_epoch_sent=ctrl_epoch_sent,
            iface_count=iface_count,
            tx_count=tx_count,
            flags=flags,
        )


def make_sections(items: Iterable[Tuple[int, bytes]]) -> List[Tuple[int, bytes]]:
    return list(items)


__all__ = [
    "MAGIC",
    "ModuleType",
    "SectionType",
    "Header",
    "Summary",
    "build_packet",
    "decode_packet",
    "parse_sections",
    "compute_crc32",
    "make_sections",
]
