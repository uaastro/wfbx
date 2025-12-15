#!/usr/bin/env bash
set -e

# This script switches networking from NetworkManager to systemd-networkd,
# creates a bridge br0, adds eth0 to it, and configures auto-bridging of tap* interfaces.

# ==== 0. Basic checks ====

if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root (sudo)." >&2
    exit 1
fi

echo "=== Switching to systemd-networkd + bridge br0 (eth0 + tap*) ==="

NETDIR="/etc/systemd/network"
BACKUP_DIR="/root/network-backup-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"

echo "[1/6] Backing up existing network config to $BACKUP_DIR ..."

# Backup NetworkManager configs (if present)
if [ -d /etc/NetworkManager ]; then
    cp -a /etc/NetworkManager "$BACKUP_DIR/NetworkManager"
fi

# Backup existing systemd-networkd configs (if any)
if [ -d "$NETDIR" ]; then
    cp -a "$NETDIR" "$BACKUP_DIR/systemd-network"
else
    mkdir -p "$NETDIR"
fi

echo "[2/6] Disabling NetworkManager (if present) ..."

if systemctl list-unit-files | grep -q '^NetworkManager\.service'; then
    systemctl disable --now NetworkManager.service || true
fi

if systemctl list-unit-files | grep -q '^NetworkManager-wait-online\.service'; then
    systemctl disable --now NetworkManager-wait-online.service || true
fi

# Optionally: prevent accidental restart
# systemctl mask NetworkManager.service NetworkManager-wait-online.service || true

echo "[3/6] Enabling systemd-networkd (and systemd-resolved) ..."

if systemctl list-unit-files | grep -q '^systemd-networkd\.service'; then
    systemctl enable systemd-networkd.service
    systemctl restart systemd-networkd.service || true
else
    echo "ERROR: systemd-networkd.service not found. Is your systemd installation complete?" >&2
    exit 1
fi

# DNS через systemd-resolved (если есть)
if systemctl list-unit-files | grep -q '^systemd-resolved\.service'; then
    systemctl enable systemd-resolved.service
    systemctl restart systemd-resolved.service || true

    # Use systemd-resolved stub resolv.conf
    if [ -e /run/systemd/resolve/stub-resolv.conf ]; then
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi
fi

echo "[4/6] Creating bridge configuration for br0 + eth0 + tap* ..."

# Clean only our own files if they existed
rm -f "$NETDIR"/10-br0.netdev \
      "$NETDIR"/20-br0.network \
      "$NETDIR"/30-eth0.network \
      "$NETDIR"/40-tap.network \
      "$NETDIR"/05-eth0.link \
      "$NETDIR"/05-br0.link

# 05-eth0.link: random MAC for eth0 on each appearance
cat > "$NETDIR/05-eth0.link" <<'EOF'
[Match]
Name=eth0

[Link]
# New random locally administered MAC every time eth0 appears
MACAddressPolicy=random
# Optional: set fixed speed and duplex
#AutoNegotiate=no
#BitsPerSecond=100M
#Duplex=full
EOF

# 10-br0.netdev: define the bridge device
cat > "$NETDIR/10-br0.netdev" <<'EOF'
[NetDev]
Name=br0
Kind=bridge
MACAddress=02:00:01:44:00:45
EOF

# 20-br0.network: configure IP for the bridge
# By default: DHCP on br0 (bridge gets IP from upstream via eth0).
# If you want static IP instead, change the [Network] section manually.
cat > "$NETDIR/20-br0.network" <<'EOF'
[Match]
Name=br0

[Network]
# Use DHCP on the bridge:
#DHCP=yes

# If you prefer static IP, comment DHCP=yes and use:
Address=192.168.144.45/24
Gateway=192.168.144.1
DNS=8.8.8.8

ConfigureWithoutCarrier=yes
EOF

# 30-eth0.network: attach eth0 to br0
# If your interface name is different (e.g. enp1s0), change "Name=eth0".
cat > "$NETDIR/30-eth0.network" <<'EOF'
[Match]
Name=eth0

[Network]
Bridge=br0

# No IP directly on eth0, only on br0
LinkLocalAddressing=no
LLMNR=no
MulticastDNS=no
DHCP=no
EOF

# 40-tap.network: automatically attach tap* (and wfbx* if needed) to br0
cat > "$NETDIR/40-tap.network" <<'EOF'
[Match]
Name=tap* wfbx*

[Network]
Bridge=br0

# No IP on TAPs
LinkLocalAddressing=no
LLMNR=no
MulticastDNS=no
DHCP=no
EOF

echo "[5/6] Reloading systemd-networkd with new configs ..."

systemctl daemon-reload
systemctl restart systemd-networkd.service

echo "[6/6] Current link state (networkctl):"
networkctl list || true

cat <<'EOF'

=== DONE ===

What has been done:
  - NetworkManager disabled.
  - systemd-networkd enabled and restarted.
  - Bridge br0 created via:
      /etc/systemd/network/10-br0.netdev
  - br0 is configured to use DHCP (20-br0.network) or static IP.
  - eth0 is enslaved into br0 (30-eth0.network).
  - Any interface named tap* or wfbx* will be automatically added to br0 (40-tap.network).

Notes:
  * Make sure your physical interface is really "eth0".
    If it is different, edit 30-eth0.network and change Name=... accordingly.
  * After you start wfbx and it creates tap0 (or wfbxtap0),
    systemd-networkd will instantly attach it to br0.
  * Use:
        networkctl status br0
        ip addr show br0
        bridge link
    to inspect the bridge and its ports.

If you lose connectivity, use local console or serial and adjust configs under /etc/systemd/network.
Backup of old configs is stored in /root/network-backup-<timestamp>.
EOF
