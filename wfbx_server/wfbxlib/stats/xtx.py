"""XTX (mesh TX) stats packet helpers."""

from __future__ import annotations

import dataclasses
import enum
import struct


class SectionType(enum.IntEnum):
    SUMMARY = 0x0100
    QUEUE = 0x0101
    SLOT = 0x0102
    EPOCH = 0x0103


SUMMARY_STRUCT = struct.Struct(
    ">IIIIIIII"
)


@dataclasses.dataclass
class Summary:
    dt_ms: int
    udp_rx_packets: int
    udp_rx_kbps_x10: int
    sent_packets: int
    sent_kbps_x10: int
    drop_overflow: int
    reserved0: int = 0
    reserved1: int = 0

    def pack(self) -> bytes:
        return SUMMARY_STRUCT.pack(
            self.dt_ms,
            self.udp_rx_packets,
            self.udp_rx_kbps_x10,
            self.sent_packets,
            self.sent_kbps_x10,
            self.drop_overflow,
            self.reserved0,
            self.reserved1,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Summary":
        if len(data) != SUMMARY_STRUCT.size:
            raise ValueError("summary size mismatch")
        values = SUMMARY_STRUCT.unpack(data)
        return cls(*values)


QUEUE_STRUCT = struct.Struct(
    ">IIII"
)


@dataclasses.dataclass
class QueueStats:
    avg: int
    min: int
    max: int
    samples: int

    def pack(self) -> bytes:
        return QUEUE_STRUCT.pack(
            self.avg,
            self.min,
            self.max,
            self.samples,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "QueueStats":
        if len(data) != QUEUE_STRUCT.size:
            raise ValueError("queue stats size mismatch")
        return cls(*QUEUE_STRUCT.unpack(data))


SLOT_STRUCT = struct.Struct(
    ">IIII"
)


@dataclasses.dataclass
class SlotStats:
    avg: int
    min: int
    max: int
    slots: int

    def pack(self) -> bytes:
        return SLOT_STRUCT.pack(
            self.avg,
            self.min,
            self.max,
            self.slots,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "SlotStats":
        if len(data) != SLOT_STRUCT.size:
            raise ValueError("slot stats size mismatch")
        return cls(*SLOT_STRUCT.unpack(data))


EPOCH_STRUCT = struct.Struct(
    ">iIIIIIIIIII"
)


@dataclasses.dataclass
class EpochStats:
    e_epoch_base_us: int
    mx_epoch_msgs: int
    base_adv: int
    base_step_avg_us: int
    base_step_min_us: int
    base_step_max_us: int
    base_step_samples: int
    epoch_adj_count: int
    epoch_adj_avg_us: int
    epoch_adj_min_us: int
    epoch_adj_max_us: int

    def pack(self) -> bytes:
        return EPOCH_STRUCT.pack(
            self.e_epoch_base_us,
            self.mx_epoch_msgs,
            self.base_adv,
            self.base_step_avg_us,
            self.base_step_min_us,
            self.base_step_max_us,
            self.base_step_samples,
            self.epoch_adj_count,
            self.epoch_adj_avg_us,
            self.epoch_adj_min_us,
            self.epoch_adj_max_us,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "EpochStats":
        if len(data) != EPOCH_STRUCT.size:
            raise ValueError("epoch stats size mismatch")
        return cls(*EPOCH_STRUCT.unpack(data))


def pack_summary_section(summary: Summary) -> bytes:
    return summary.pack()


def unpack_summary_section(data: bytes) -> Summary:
    return Summary.unpack(data)


def pack_queue_section(queue: QueueStats) -> bytes:
    return queue.pack()


def unpack_queue_section(data: bytes) -> QueueStats:
    return QueueStats.unpack(data)


def pack_slot_section(slot: SlotStats) -> bytes:
    return slot.pack()


def unpack_slot_section(data: bytes) -> SlotStats:
    return SlotStats.unpack(data)


def pack_epoch_section(epoch: EpochStats) -> bytes:
    return epoch.pack()


def unpack_epoch_section(data: bytes) -> EpochStats:
    return EpochStats.unpack(data)


__all__ = [
    "SectionType",
    "Summary",
    "QueueStats",
    "SlotStats",
    "EpochStats",
    "pack_summary_section",
    "unpack_summary_section",
    "pack_queue_section",
    "unpack_queue_section",
    "pack_slot_section",
    "unpack_slot_section",
    "pack_epoch_section",
    "unpack_epoch_section",
]
