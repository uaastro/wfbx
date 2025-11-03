# L2 TAP Tunnel over wfbX

This module provides bidirectional transport of Ethernet frames over the existing
wfbX UDP pipeline. Each endpoint runs `l2tap`, connecting a TAP device
to the UDP sockets. To splice the remote L2 into the local LAN you can add the
TAP interface to a bridge.

## Minimal Configuration

Add sections similar to the following in `wfbx_server.cfg`:

```ini
[l2tap_ground]
l2tap_ip_rx = 0.0.0.0
l2tap_port_rx = 6000
l2tap_ip_tx = 10.10.0.2
l2tap_port_tx = 6001
l2tap_bridge = br-wfbx

[l2tap_air]
l2tap_ip_rx = 0.0.0.0
l2tap_port_rx = 6001
l2tap_ip_tx = 10.10.0.1
l2tap_port_tx = 6000
l2tap_bridge = br-wfbx
```

Each instance uses the TAP name from `DEFAULT` (wfbxtap0) and its own pair of UDP
ports. The TAP is always brought UP, created without persistence and single-queue.
At startup the service removes any stale interface with the same name and assigns
a fresh locally administered MAC address so both endpoints avoid conflicts.
Ensure the radio chain provides slots in both directions for the chosen ports.

## Bridge Management

- `l2tap_bridge=<name>` — attach the TAP to an existing bridge.
- `l2tap_bridge_stp=auto|on|off` — control STP behaviour.

If you do not need a bridge (point-to-point), leave those fields empty and assign
IP/routes on `wfbxtap0` manually.

## Monitoring

The module reports to statd using the `L2_TAP` module type. The summary payload encodes
`pkts_tx`, `rate_tx` (tenths of kbps), `pkts_rx`, and `rate_rx` (tenths of kbps).
`wfbx_top` converts the rates back to floating-point kbps for display. The text preview
contains the same counters plus TAP/UDP drop statistics for quick inspection. Statistics
emit once per `l2tap_stat_period` (default 1000 ms). If the TAP cannot be removed or the
stats socket setup fails, `l2tap` exits with a non-zero status so `wfbx_server` can
restart the unit.

### Summary Field Mapping

`l2tap` reuses the generic `SUMMARY` structure as follows:

- `packets_total` — TAP frames transmitted during the window.
- `bytes_total` — TAP frames received during the window.
- `ctrl_epoch_sent` — transmit rate in kbps × 10 (tenths of kbps).
- `iface_count` — receive rate in kbps × 10.
- `tx_count` — count of TAP write drops (UDP → TAP path).
- `flags` — count of UDP send drops (TAP → UDP path).

## Limitations

- The default MTU is 1500. Reduce it if required to fit inside the available
  RF frame budget (consider FEC/encapsulation overhead).
- Reliable bidirectional L2 requires a dedicated return radio path/slot.
- When bridging into an active LAN, enable STP or otherwise prevent loops.
