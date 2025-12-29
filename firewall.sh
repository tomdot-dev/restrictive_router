#!/usr/bin/env bash
# router-nat.sh — minimal Linux router + NAT masquerade + block LAN->WAN to private/non-public destinations
#
# Usage:
#   sudo ./router-nat.sh --wan eth0 --lan eth1
# Optional:
#   --backend nft|iptables   (default: auto; prefers nft if available)
#   --flush                 (DANGEROUS: flushes existing firewall rules before applying)
#   --ipv6                  (also enable IPv6 forwarding + block ULA/link-local/loopback on LAN->WAN)
#
# Notes:
# - This only filters *routed/forwarded* traffic. It cannot stop LAN clients from reaching private IPs on the same L2 segment.
# - “Private/non-public” list below includes RFC1918 plus common non-public ranges; edit to taste.
set -euo pipefail

WAN=""
LAN=""
BACKEND="auto"
FLUSH=0
IPV6=0

usage() {
  cat >&2 <<'EOF'
Usage: sudo ./router-nat.sh --wan <ifname> --lan <ifname> [--backend nft|iptables] [--flush] [--ipv6]
EOF
  exit 2
}

die() { echo "Error: $*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wan) WAN="${2:-}"; shift 2;;
    --lan) LAN="${2:-}"; shift 2;;
    --backend) BACKEND="${2:-}"; shift 2;;
    --flush) FLUSH=1; shift;;
    --ipv6) IPV6=1; shift;;
    -h|--help) usage;;
    *) die "Unknown argument: $1";;
  esac
done

[[ -n "$WAN" && -n "$LAN" ]] || usage
[[ "$WAN" != "$LAN" ]] || die "--wan and --lan must be different interfaces"

have ip || die "ip(8) not found"
ip link show dev "$WAN" >/dev/null 2>&1 || die "WAN interface not found: $WAN"
ip link show dev "$LAN" >/dev/null 2>&1 || die "LAN interface not found: $LAN"

# Enable forwarding (runtime; persist via /etc/sysctl.d/ if desired)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if [[ "$IPV6" -eq 1 ]]; then
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
fi

if [[ "$BACKEND" == "auto" ]]; then
  if have nft; then BACKEND="nft"; else BACKEND="iptables"; fi
fi

apply_nft() {
  have nft || die "nft(8) not found"

  if [[ "$FLUSH" -eq 1 ]]; then
    nft flush ruleset
  else
    # Remove only what we create
    nft list table inet natrouter >/dev/null 2>&1 && nft delete table inet natrouter
    nft list table ip natrouter_nat >/dev/null 2>&1 && nft delete table ip natrouter_nat
  fi

  # “Private/non-public” destinations to block on LAN->WAN forwarding.
  # Keep RFC1918; the rest are commonly considered non-public.
  # If you truly only want RFC1918, delete everything except 10/8, 172.16/12, 192.168/16.
  local NONPUBLIC4='{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8 }'

  # IPv6 “private-ish” destinations (ULA + link-local + loopback)
  local NONPUBLIC6='{ fc00::/7, fe80::/10, ::1/128 }'

  nft -f - <<EOF
table inet natrouter {
  set nonpublic4 {
    type ipv4_addr
    flags interval
    elements = $NONPUBLIC4
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state invalid drop
    ct state established,related accept

    # Block LAN clients from reaching private/non-public destinations *via WAN*
    iifname "$LAN" oifname "$WAN" ip daddr @nonpublic4 ct state new drop

    $( [[ "$IPV6" -eq 1 ]] && echo "iifname \"$LAN\" oifname \"$WAN\" ip6 daddr $NONPUBLIC6 ct state new drop" )

    # Allow LAN -> WAN forwarding
    iifname "$LAN" oifname "$WAN" accept
  }
}

table ip natrouter_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "$WAN" masquerade
  }
}
EOF
}

apply_iptables() {
  have iptables || die "iptables(8) not found"

  if [[ "$FLUSH" -eq 1 ]]; then
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F || true
  fi

  # Default: drop forwarded traffic unless allowed below (simple router stance)
  iptables -P FORWARD DROP

  # Accept established/related
  iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Block LAN->WAN to private/non-public destinations (new connections)
  local blocks=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "100.64.0.0/10"
    "169.254.0.0/16"
  )
  for cidr in "${blocks[@]}"; do
    iptables -C FORWARD -i "$LAN" -o "$WAN" -d "$cidr" -m conntrack --ctstate NEW -j DROP 2>/dev/null \
      || iptables -A FORWARD -i "$LAN" -o "$WAN" -d "$cidr" -m conntrack --ctstate NEW -j DROP
  done

  # Allow LAN -> WAN
  iptables -C FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT

  # NAT masquerade out WAN
  iptables -t nat -C POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE

  if [[ "$IPV6" -eq 1 ]]; then
    if have ip6tables; then
      ip6tables -P FORWARD DROP
      ip6tables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
        || ip6tables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

      # Block ULA + link-local + loopback on LAN->WAN (new connections)
      local blocks6=("fc00::/7" "fe80::/10" "::1/128")
      for cidr6 in "${blocks6[@]}"; do
        ip6tables -C FORWARD -i "$LAN" -o "$WAN" -d "$cidr6" -m conntrack --ctstate NEW -j DROP 2>/dev/null \
          || ip6tables -A FORWARD -i "$LAN" -o "$WAN" -d "$cidr6" -m conntrack --ctstate NEW -j DROP
      done

      ip6tables -C FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null \
        || ip6tables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
    else
      echo "Warning: --ipv6 requested but ip6tables not found; IPv6 filtering not applied." >&2
    fi
  fi
}

case "$BACKEND" in
  nft) apply_nft;;
  iptables) apply_iptables;;
  *) die "Invalid --backend: $BACKEND (expected nft or iptables)";;
esac

echo "OK: routing+NAT configured ($BACKEND). WAN=$WAN LAN=$LAN"
