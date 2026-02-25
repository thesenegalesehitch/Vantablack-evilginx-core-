#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl gnupg apt-transport-https ca-certificates
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/deb/debian.deb.txt | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update -y
apt-get install -y caddy
cat >/etc/caddy/Caddyfile <<EOF
{
        email ${email}
}
${domain} {
        encode gzip
        header {
                Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
                X-Content-Type-Options "nosniff"
                X-Frame-Options "DENY"
                Referrer-Policy "no-referrer"
                Content-Security-Policy "default-src 'self'; script-src 'self'"
        }
        reverse_proxy ${wg_peer_address}:8080
}
EOF
systemctl enable caddy
systemctl restart caddy
apt-get install -y wireguard
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
umask 077
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${wg_server_address}
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/server.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = ${wg_peer_public_key}
AllowedIPs = ${wg_peer_allowed_ips}
PersistentKeepalive = 25
EOF
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
