#!/bin/bash
# Zivpn UDP Module installer
# Creator Zahid Islam
# Optimized config by ChatGPT (NO OTHER CHANGES)

echo -e "Updating server"
sudo apt-get update && apt-get upgrade -y

systemctl stop zivpn.service 1> /dev/null 2> /dev/null

echo -e "Downloading UDP Service"
wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 \
-O /usr/local/bin/zivpn 1> /dev/null 2> /dev/null

chmod +x /usr/local/bin/zivpn
mkdir -p /etc/zivpn 1> /dev/null 2> /dev/null

# ================================
# OPTIMIZED CONFIG (ONLY CHANGE)
# ================================
cat <<EOF > /etc/zivpn/config.json
{
  "listen": ":5667",
  "mode": "udp",
  "config": ["zi"],

  "performance": {
    "udp_buffer_size": 16777216,
    "udp_read_buffer": 16777216,
    "udp_write_buffer": 16777216,
    "max_packet_size": 1400,
    "mtu": 1400
  },

  "network": {
    "enable_fragmentation": false,
    "enable_reassembly": false,
    "reuse_port": true,
    "fast_open": true
  },

  "concurrency": {
    "worker": 8,
    "max_sessions": 10000
  },

  "timeout": {
    "handshake": 5,
    "read": 30,
    "write": 30,
    "idle": 60,
    "keepalive": 10
  },

  "retry": {
    "enable": true,
    "max_attempt": 5,
    "interval_ms": 300
  },

  "security": {
    "tls": true,
    "cert": "zivpn.crt",
    "key": "zivpn.key"
  },

  "logging": {
    "level": "info",
    "disable_access_log": true
  }
}
EOF
# ================================

echo "Generating cert files:"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
-subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
-keyout "/etc/zivpn/zivpn.key" \
-out "/etc/zivpn/zivpn.crt"

sysctl -w net.core.rmem_max=16777216 1> /dev/null 2> /dev/null
sysctl -w net.core.wmem_max=16777216 1> /dev/null 2> /dev/null

cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo -e "ZIVPN UDP Passwords"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config

if [ -n "$input_config" ]; then
    IFS=',' read -r -a config <<< "$input_config"
    if [ ${#config[@]} -eq 1 ]; then
        config+=(${config[0]})
    fi
else
    config=("zi")
fi

new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"
sed -i -E "s/\"config\": ?\[[^]]*\]/${new_config_str}/g" /etc/zivpn/config.json

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service

iptables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) \
-p udp --dport 6000:19999 -j DNAT --to-destination :5667

ufw allow 6000:19999/udp
ufw allow 5667/udp

rm -f zi.* 1> /dev/null 2> /dev/null

echo -e "ZIVPN UDP Installed (Optimized)"
