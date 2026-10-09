#!/usr/bin/env bash
set -euo pipefail

startup_failure() {
    # FirewallD writes backend errors to a file, including on kernels that lack
    # required nftables features. Keep those errors in Compose's failure logs.
    if [ -f /var/log/firewalld ]; then
        python -c 'from pathlib import Path; print("\n".join(line[:500] for line in Path("/var/log/firewalld").read_text().splitlines() if "ERROR:" in line))'
    fi
}
trap startup_failure ERR

# Both the bus and firewall belong to this container. No systemd is needed.
mkdir -p /run/dbus
dbus-uuidgen --ensure
dbus-daemon --system --fork
# Retain kernel protection when the E2E test deliberately stops the daemon.
sed -i 's/^CleanupOnExit=.*/CleanupOnExit=no/' /etc/firewalld/firewalld.conf
/usr/sbin/firewalld --nofork --nopid &
echo "$!" > /run/test-firewalld.pid

for attempt in {1..60}; do
    if firewall-cmd --state; then
        break
    fi
    kill -0 "$(cat /run/test-firewalld.pid)"
    sleep 0.5
done
firewall-cmd --state
python /test/services.py &
exec python /test/api.py
