"""Helpers for working with Linux TAP interfaces and linking them to bridges."""

from __future__ import annotations

import os
import struct
import subprocess
from typing import Iterable, Optional, Sequence, Tuple

import fcntl

TUN_DEVICE = "/dev/net/tun"

TUNSETIFF = 0x400454CA
TUNSETPERSIST = 0x400454CB
TUNSETOWNER = 0x400454CC
TUNSETGROUP = 0x400454CE

IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IFF_MULTI_QUEUE = 0x0100


class TapError(RuntimeError):
    """Raised when TAP operations fail."""


def _pack_u32(value: int) -> bytes:
    return struct.pack("I", int(value))


def open_tap(
    name: str,
    *,
    persist: bool = False,
    multi_queue: bool = False,
    owner: Optional[int] = None,
    group: Optional[int] = None,
) -> Tuple[int, str]:
    """Create (or attach to) a TAP interface.

    Returns (fd, actual_name).
    """
    if not os.path.exists(TUN_DEVICE):
        raise TapError(f"TAP device '{TUN_DEVICE}' is unavailable (Linux only feature)")
    try:
        fd = os.open(TUN_DEVICE, os.O_RDWR)
    except OSError as exc:
        raise TapError(f"failed to open {TUN_DEVICE}: {exc}") from exc

    flags = IFF_TAP | IFF_NO_PI
    if multi_queue:
        flags |= IFF_MULTI_QUEUE
    ifr = struct.pack("16sH", name.encode("ascii", "ignore"), flags)
    buf = bytearray(ifr)

    try:
        fcntl.ioctl(fd, TUNSETIFF, buf)
    except OSError as exc:
        os.close(fd)
        raise TapError(f"failed to create TAP '{name}': {exc}") from exc

    actual = buf[:16].split(b"\0", 1)[0].decode("ascii", "ignore")

    try:
        if owner is not None:
            fcntl.ioctl(fd, TUNSETOWNER, _pack_u32(owner))
        if group is not None:
            fcntl.ioctl(fd, TUNSETGROUP, _pack_u32(group))
        fcntl.ioctl(fd, TUNSETPERSIST, _pack_u32(1 if persist else 0))
    except OSError as exc:
        os.close(fd)
        raise TapError(f"failed to configure TAP '{actual}': {exc}") from exc

    return fd, actual


def set_persist(fd: int, enabled: bool) -> None:
    """Enable or disable persistence for an open TAP descriptor."""
    fcntl.ioctl(fd, TUNSETPERSIST, _pack_u32(1 if enabled else 0))


def configure_iface(
    name: str,
    *,
    mtu: Optional[int] = None,
    txqueuelen: Optional[int] = None,
    mac: Optional[str] = None,
    up: bool = True,
) -> None:
    """Configure interface parameters via `ip link`."""
    cmds: Sequence[Sequence[str]] = []
    if mtu is not None:
        cmds += [["ip", "link", "set", "dev", name, "mtu", str(int(mtu))]]
    if txqueuelen is not None:
        cmds += [["ip", "link", "set", "dev", name, "txqueuelen", str(int(txqueuelen))]]
    if mac is not None:
        cmds += [["ip", "link", "set", "dev", name, "address", mac]]
    if up:
        cmds += [["ip", "link", "set", "dev", name, "up"]]

    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError as exc:
            raise TapError("`ip` command not found; cannot configure TAP") from exc
        except subprocess.CalledProcessError as exc:
            raise TapError(f"failed to execute '{' '.join(cmd)}': {exc}") from exc


def delete_iface(name: str) -> None:
    """Remove a TAP interface by name (best-effort)."""
    if not name:
        return
    try:
        subprocess.run(
            ["ip", "link", "delete", "dev", name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise TapError(f"failed to delete interface '{name}': {exc}") from exc
    except FileNotFoundError as exc:
        raise TapError("`ip` command not found; cannot delete TAP") from exc


def ensure_bridge(name: str, *, stp: Optional[bool] = None, up: bool = True) -> None:
    """Create a bridge if it does not yet exist."""
    exists = os.path.exists(f"/sys/class/net/{name}")
    if not exists:
        try:
            subprocess.run(
                ["ip", "link", "add", name, "type", "bridge"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            raise TapError(f"failed to create bridge '{name}': {exc}") from exc
        except FileNotFoundError as exc:
            raise TapError("`ip` command not found; cannot create bridge") from exc
    if stp is not None:
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", name, "type", "bridge", "stp_state", "1" if stp else "0"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            raise TapError(f"failed to configure STP for '{name}': {exc}") from exc
    if up:
        configure_iface(name, up=True)


def add_ifaces_to_bridge(bridge: str, ifaces: Iterable[str]) -> None:
    for iface in ifaces:
        iface = iface.strip()
        if not iface:
            continue
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", iface, "master", bridge],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            raise TapError(f"failed to add '{iface}' to bridge '{bridge}': {exc}") from exc
        configure_iface(iface, up=True)


__all__ = [
    "TapError",
    "open_tap",
    "set_persist",
    "configure_iface",
    "delete_iface",
    "ensure_bridge",
    "add_ifaces_to_bridge",
]
