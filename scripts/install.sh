#!/usr/bin/env bash
# Build + install NIMBUSA — Cloud Security Control Center with NIMBUSA SHIELD.
#
#   binary        /usr/local/bin/nimbusa   (real file, so granted non-root users can exec)
#   firewall      /usr/local/lib/nimbusa/nimbusa-firewall.sh
#   config        /etc/nimbusa/config.toml (created if absent)
#   state         /var/lib/nimbusa/        (registry, ddos/, audit/)
#   access group  'nimbusa'                (members may run the tool; root always can)
#   sudoers       /etc/sudoers.d/nimbusa   (granted users auto-elevate)
#   service       nimbusa-shield.service   (optional headless engine — see below)
#
# Re-run after every code change to redeploy. Idempotent and non-destructive:
# existing AVNI data is migrated forward, never deleted.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/nimbusa-rs"
BIN=/usr/local/bin/nimbusa
LIBDIR=/usr/local/lib/nimbusa
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"

echo "==> building NIMBUSA (release)"
( cd "$SRC" && "$CARGO" build --release >/dev/null )

echo "==> directories"
install -d -m 0755 /etc/nimbusa /var/lib/nimbusa /var/lib/nimbusa/ddos /var/lib/nimbusa/audit /var/log/nimbusa "$LIBDIR"

echo "==> firewall helper -> $LIBDIR"
install -m 0755 "$REPO/scripts/nimbusa-firewall.sh" "$LIBDIR/nimbusa-firewall.sh"

echo "==> 'nimbusa' access group"
groupadd -f nimbusa

echo "==> sudoers drop-in (auto-elevation for granted users)"
cat >/etc/sudoers.d/nimbusa <<'EOF'
# NIMBUSA control center — members of the 'nimbusa' group may run the tool as root.
%nimbusa ALL=(root) NOPASSWD: /usr/local/bin/nimbusa
EOF
chmod 440 /etc/sudoers.d/nimbusa
if ! visudo -cf /etc/sudoers.d/nimbusa >/dev/null; then
  echo "!! sudoers validation failed — removing drop-in"; rm -f /etc/sudoers.d/nimbusa; exit 1
fi

echo "==> installing binary -> $BIN"
rm -f "$BIN"
install -o root -g root -m 0755 "$SRC/target/release/nimbusa" "$BIN"

echo "==> initialising firewall (ipset + iptables, migrates legacy AVNI state)"
bash "$LIBDIR/nimbusa-firewall.sh" restore || true

echo "==> seeding config + arming SHIELD enforcement path"
"$BIN" config init || true
"$BIN" ddos enable || true

# Optional headless engine: keeps the SHIELD running (detect/mitigate/recover/
# audit) even when no TUI is open. The TUI/CLI still work standalone without it.
if [ "${WITH_SERVICE:-0}" = "1" ]; then
  echo "==> installing nimbusa-shield.service"
  install -m 0644 "$REPO/scripts/nimbusa-shield.service" /etc/systemd/system/nimbusa-shield.service
  systemctl daemon-reload
  systemctl enable --now nimbusa-shield.service
fi

echo
echo "OK — NIMBUSA installed."
echo "  run the control center:   nimbusa"
echo "  shield status:            nimbusa ddos status"
echo "  safe local demo:          nimbusa ddos simulate http-flood"
echo "  granted users:            $(getent group nimbusa | cut -d: -f4)"
