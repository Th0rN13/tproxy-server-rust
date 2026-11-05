#!/usr/bin/env bash
set -euo pipefail
umask 077

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
hostname=
secret=
binary=
site_dir="$here/site"
gateway=
network=remnawave-network
caddyfile=/opt/remnawave/caddy/Caddyfile
caddy_container=caddy

usage() {
	echo "usage: sudo $0 --hostname notes.example.com [--secret 32-hex] [--binary PATH] [--site-dir DIR] [--gateway IP] [--network NAME] [--caddyfile PATH] [--caddy-container NAME]" >&2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--hostname) hostname="${2:-}"; shift 2 ;;
		--secret) secret="${2:-}"; shift 2 ;;
		--binary) binary="${2:-}"; shift 2 ;;
		--site-dir) site_dir="${2:-}"; shift 2 ;;
		--gateway) gateway="${2:-}"; shift 2 ;;
		--network) network="${2:-}"; shift 2 ;;
		--caddyfile) caddyfile="${2:-}"; shift 2 ;;
		--caddy-container) caddy_container="${2:-}"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) usage; exit 2 ;;
	esac
done

if [[ "${EUID}" -ne 0 ]]; then
	echo "run this installer as root" >&2
	exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
	echo "this deployment targets x86_64 Linux" >&2
	exit 1
fi
if [[ -z "$hostname" ]] || [[ ! "$hostname" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || [[ "$hostname" != *.* ]]; then
	echo "--hostname must be a lowercase ASCII DNS name" >&2
	exit 2
fi
if [[ ! -d "$site_dir" ]] || [[ ! -r "$site_dir/index.html" ]]; then
	echo "--site-dir must contain a readable index.html" >&2
	exit 2
fi

if [[ -z "$binary" ]] && [[ ! -x /usr/local/bin/tproxy-server ]]; then
	echo "--binary is required on the first install" >&2
	exit 2
fi
if [[ -n "$binary" ]]; then
	if [[ ! -f "$binary" ]] || [[ "$(head -c 4 "$binary" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]]; then
		echo "--binary must be a Linux ELF executable" >&2
		exit 2
	fi
fi

if [[ -z "$secret" ]] && [[ -f /opt/tproxy/profiles.json ]]; then
	secret="$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{32\}\)".*/\1/p' /opt/tproxy/profiles.json | head -n 1)"
fi
if [[ -z "$secret" ]]; then
	secret="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
fi
if [[ ! "$secret" =~ ^[0-9a-f]{32}$ ]]; then
	echo "--secret must be 32 lowercase hex characters" >&2
	exit 2
fi

if [[ -z "$gateway" ]] && command -v docker >/dev/null 2>&1 && docker network inspect "$network" >/dev/null 2>&1; then
	gateway="$(docker network inspect "$network" --format '{{(index .IPAM.Config 0).Gateway}}')"
fi
gateway="${gateway:-172.18.0.1}"
if [[ ! "$gateway" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
	echo "the bridge gateway is not an IPv4 address: $gateway" >&2
	exit 2
fi
bridge_subnet=
if command -v docker >/dev/null 2>&1 && docker network inspect "$network" >/dev/null 2>&1; then
	bridge_subnet="$(docker network inspect "$network" --format '{{(index .IPAM.Config 0).Subnet}}')"
fi
bridge_subnet="${bridge_subnet:-172.18.0.0/16}"

"$here/install-mtproxy.sh"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends ca-certificates curl socat nftables

if ! id tproxy >/dev/null 2>&1; then
	useradd --system --home /nonexistent --shell /usr/sbin/nologin tproxy
fi

if [[ -n "$binary" ]]; then
	install -o root -g root -m 0755 "$binary" /usr/local/bin/tproxy-server
fi

install -d -o root -g root -m 0755 /opt/tproxy /opt/tproxy/public
if [[ -z "$(find /opt/tproxy/public -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	cp -a "$site_dir/." /opt/tproxy/public/
	chown -R root:root /opt/tproxy/public
	chmod -R a+rX /opt/tproxy/public
else
	echo "keeping the existing /opt/tproxy/public; update it and restart tproxy.service"
fi

if [[ ! -e /opt/tproxy/token.key ]]; then
	head -c 32 /dev/urandom > /opt/tproxy/token.key
fi
if [[ "$(wc -c < /opt/tproxy/token.key)" -ne 32 ]]; then
	echo "/opt/tproxy/token.key must contain exactly 32 bytes" >&2
	exit 1
fi
chown tproxy:tproxy /opt/tproxy/token.key
chmod 0400 /opt/tproxy/token.key

cat > /opt/tproxy/config.json <<EOF
{
  "public_hostname": "$hostname",
  "listen": "127.0.0.1:8080",
  "admin_listen": "127.0.0.1:8081",
  "public_dir": "/opt/tproxy/public",
  "static_routes": "legacy",
  "token_key_file": "/opt/tproxy/token.key",
  "profiles_file": "/opt/tproxy/profiles.json"
}
EOF
cat > /opt/tproxy/profiles.json <<EOF
{"profiles":[{"name":"default","secret":"$secret","backend":"127.0.0.1:2398","carrier_mode":"https"}]}
EOF
chown root:tproxy /opt/tproxy/config.json
chmod 0640 /opt/tproxy/config.json
chown tproxy:tproxy /opt/tproxy/profiles.json
chmod 0400 /opt/tproxy/profiles.json

local_address="$(ip -4 route get 149.154.175.50 2>/dev/null |
	sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]\+\).*/\1/p' | head -n 1)"
public_address=
for probe in https://api.ipify.org https://ifconfig.co/ip https://icanhazip.com; do
	candidate="$(curl --fail --silent --show-error --location --ipv4 --max-time 15 \
		--proto '=https' --proto-redir '=https' --tlsv1.2 "$probe" 2>/dev/null |
		tr -d '[:space:]')" || continue
	if [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		public_address="$candidate"
		break
	fi
done
if [[ -z "$public_address" ]]; then
	public_address="$(getent ahostsv4 "$hostname" 2>/dev/null | awk 'NR==1 {print $1}')"
fi
nat_args=
if [[ -n "$local_address" ]] && [[ -n "$public_address" ]] && [[ "$local_address" != "$public_address" ]]; then
	nat_args="--nat-info $local_address:$public_address"
	echo "MTProxy is behind NAT ($local_address -> $public_address), using $nat_args"
fi

cat > /etc/mtproxy/mtproxy.env <<EOF
MTPROXY_SECRET=$secret
MTPROXY_WORKERS=1
MTPROXY_MAX_CONNECTIONS=4096
MTPROXY_NAT_ARGS=$nat_args
EOF
chown root:mtproxy /etc/mtproxy/mtproxy.env
chmod 0640 /etc/mtproxy/mtproxy.env

install -m 0644 "$here/tproxy.service" /etc/systemd/system/tproxy.service
install -m 0644 "$here/mtproxy.service" /etc/systemd/system/mtproxy.service
install -m 0644 "$here/tproxy-firewall.service" /etc/systemd/system/tproxy-firewall.service
install -m 0644 "$here/refresh-mtproxy-config.service" /etc/systemd/system/refresh-mtproxy-config.service
install -m 0644 "$here/refresh-mtproxy-config.timer" /etc/systemd/system/refresh-mtproxy-config.timer
install -m 0755 "$here/refresh-mtproxy-config.sh" /usr/local/sbin/refresh-mtproxy-config
install -m 0644 "$here/firewall.nft" /opt/tproxy/firewall.nft
sed "s/__GATEWAY__/$gateway/g" "$here/tproxy-bridge.service" > /etc/systemd/system/tproxy-bridge.service
chown root:root /etc/systemd/system/tproxy-bridge.service
chmod 0644 /etc/systemd/system/tproxy-bridge.service

/usr/local/bin/tproxy-server -config /opt/tproxy/config.json -check

if crontab -l >/dev/null 2>&1; then
	current_crontab="$(crontab -l)"
	crontab_backup="/root/crontab.before-tproxy.$(date +%Y%m%d%H%M%S)"
	if printf '%s\n' "$current_crontab" | grep -q -E 'MTProxy\.service|/opt/MTProxy/proxy-multi\.conf'; then
		printf '%s\n' "$current_crontab" > "$crontab_backup"
		chmod 0600 "$crontab_backup"
		printf '%s\n' "$current_crontab" | grep -v -E 'MTProxy\.service|/opt/MTProxy/proxy-multi\.conf' | crontab - || true
	fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
	ufw allow from "$bridge_subnet" to any port 8082 proto tcp >/dev/null
fi

if [[ ! -f "$caddyfile" ]]; then
	echo "no Caddyfile at $caddyfile; add $here/Caddyfile.tproxy to your edge manually" >&2
elif ! grep -Fq "https://$hostname {" "$caddyfile"; then
	caddy_backup="$caddyfile.before-tproxy.$(date +%Y%m%d%H%M%S)"
	cp -a "$caddyfile" "$caddy_backup"
	{
		printf '\n'
		sed -e "s/__HOSTNAME__/$hostname/g" -e "s/__GATEWAY__/$gateway/g" "$here/Caddyfile.tproxy"
	} >> "$caddyfile"
	if ! docker exec "$caddy_container" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
		mv -f "$caddy_backup" "$caddyfile"
		echo "the new Caddy site block did not validate; the previous Caddyfile is back" >&2
		exit 1
	fi
	docker exec "$caddy_container" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
fi

systemctl daemon-reload
systemctl enable --now tproxy-firewall.service
systemctl enable --now mtproxy.service
systemctl restart mtproxy.service
systemctl enable --now tproxy-bridge.service
systemctl enable --now tproxy.service
systemctl enable --now refresh-mtproxy-config.timer

relay_ready=
for _ in $(seq 1 20); do
	if curl --fail --silent --output /dev/null http://127.0.0.1:8081/readyz; then
		relay_ready=1
		break
	fi
	sleep 1
done
if [[ -z "$relay_ready" ]]; then
	echo "tproxy-server did not become ready; inspect journalctl -u tproxy.service" >&2
	exit 1
fi

public_ready=
for _ in $(seq 1 30); do
	if curl --fail --silent --output /dev/null "https://$hostname/"; then
		public_ready=1
		break
	fi
	sleep 1
done
if [[ -z "$public_ready" ]]; then
	echo "https://$hostname/ is not answering yet; check the certificate and the bridge" >&2
fi

echo
echo "Proxy server: $hostname"
echo "Proxy secret: $secret"
echo "Proxy link:   https://t.me/webproxy?server=$hostname&secret=$secret"
echo "Check: systemctl --no-pager --full status mtproxy tproxy-bridge tproxy"
echo "Check: curl --fail http://127.0.0.1:8081/readyz"
