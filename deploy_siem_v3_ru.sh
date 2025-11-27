#!/bin/bash

# Остановка при любой ошибке
set -e

# Цвета для красоты
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Установка SIEM (Rsyslog + Loki v3 + Promtail v3) ===${NC}"
echo "Конфигурация: MikroTik -> Rsyslog (File) -> Promtail -> Loki"
echo "Версии ПО: Loki v3.3.2, Promtail v3.3.2"
echo ""

# --- 1. Ввод данных ---
read -p "Введите IP адрес вашего MikroTik: " MIKROTIK_IP

if [ -z "$MIKROTIK_IP" ]; then
    echo -e "${RED}Ошибка: IP адрес не введен.${NC}"
    exit 1
fi

# Используем последние стабильные бинарники v3
LOKI_VER="3.3.2"
PROMTAIL_VER="3.3.2"

# --- 2. Подготовка системы ---
echo -e "${BLUE}[1/7] Обновление пакетов...${NC}"
apt-get update -qq
apt-get install -y -qq rsyslog wget unzip curl

# --- 3. Настройка Rsyslog (Буфер) ---
echo -e "${BLUE}[2/7] Настройка Rsyslog...${NC}"

# Включаем UDP 1514
sed -i '/module(load="imudp")/s/^#//g' /etc/rsyslog.conf
sed -i '/input(type="imudp" port="514")/s/^#//g' /etc/rsyslog.conf
# Меняем порт на 1514
sed -i 's/port="514"/port="1514"/g' /etc/rsyslog.conf
# Отключаем imklog (чтобы не спамил ошибками в LXC)
sed -i '/module(load="imklog")/s/^/#/g' /etc/rsyslog.conf

# Создаем конфиг фильтрации (пишем логи микротика в отдельный файл)
cat > /etc/rsyslog.d/mikrotik.conf <<EOF
if \$fromhost-ip == '$MIKROTIK_IP' then {
    action(type="omfile" file="/var/log/mikrotik.log")
    stop
}
EOF

# Создаем файл лога с правильными правами
touch /var/log/mikrotik.log
chmod 644 /var/log/mikrotik.log

# Настройка ротации (чтобы диск не забился)
cat > /etc/logrotate.d/mikrotik <<EOF
/var/log/mikrotik.log {
    daily
    rotate 7
    size 100M
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

systemctl restart rsyslog

# --- 4. Установка Loki v3 ---
echo -e "${BLUE}[3/7] Установка Loki v$LOKI_VER...${NC}"
cd /tmp
wget -q "https://github.com/grafana/loki/releases/download/v${LOKI_VER}/loki-linux-amd64.zip"
unzip -q -o loki-linux-amd64.zip
mv loki-linux-amd64 /usr/local/bin/loki
chmod +x /usr/local/bin/loki

# Пользователь и папки
if ! id "loki" &>/dev/null; then useradd --no-create-home --shell /bin/false loki; fi
mkdir -p /var/lib/loki
chown -R loki:loki /var/lib/loki
mkdir -p /etc/loki

# Конфиг Loki (Адаптирован под v3: tsdb + schema v13)
cat > /etc/loki/config.yaml <<EOF
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

compactor:
  working_directory: /var/lib/loki/compactor
  delete_request_store: filesystem

analytics:
  reporting_enabled: false
EOF

# Systemd unit для Loki
cat > /etc/systemd/system/loki.service <<EOF
[Unit]
Description=Loki service
After=network.target

[Service]
Type=simple
User=loki
ExecStart=/usr/local/bin/loki -config.file /etc/loki/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# --- 5. База GeoIP ---
echo -e "${BLUE}[4/7] Скачивание GeoIP (P3TERX)...${NC}"
mkdir -p /etc/promtail
wget -q -O /etc/promtail/GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"

# --- 6. Установка Promtail v3 ---
echo -e "${BLUE}[5/7] Установка Promtail v$PROMTAIL_VER...${NC}"
cd /tmp
wget -q "https://github.com/grafana/loki/releases/download/v${PROMTAIL_VER}/promtail-linux-amd64.zip"
unzip -q -o promtail-linux-amd64.zip
mv promtail-linux-amd64 /usr/local/bin/promtail
chmod +x /usr/local/bin/promtail

mkdir -p /var/lib/promtail

# Конфиг Promtail (Читаем файл от Rsyslog + GeoIP)
cat > /etc/promtail/config.yaml <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: "mikrotik_via_rsyslog"
          __path__: /var/log/mikrotik.log

    pipeline_stages:
      # Регулярка для формата Firewall (IP:PORT->)
      - regex:
          expression: ',\s(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+->'

      # Регулярка для формата src-address=
      - regex:
          expression: 'src-address=(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

      # GeoIP lookup
      - geoip:
          db: "/etc/promtail/GeoLite2-City.mmdb"
          source: "source_ip"
          db_type: "city"

      # Упаковка данных
      - pack:
          labels:
            - source_ip
            - geoip_country_name
            - geoip_city_name
            - geoip_location_latitude
            - geoip_location_longitude
EOF

# Systemd unit для Promtail
cat > /etc/systemd/system/promtail.service <<EOF
[Unit]
Description=Promtail service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/promtail -config.file /etc/promtail/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# --- 7. Финал ---
echo -e "${BLUE}[6/7] Запуск сервисов...${NC}"
systemctl daemon-reload
systemctl enable loki promtail
systemctl restart loki promtail

# Чистка мусора
rm -f /tmp/loki-linux-amd64.zip /tmp/promtail-linux-amd64.zip /tmp/loki-linux-amd64 /tmp/promtail-linux-amd64

MY_IP=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}=== ГОТОВО! СИСТЕМА УСТАНОВЛЕНА ===${NC}"
echo "-----------------------------------------------------------"
echo "Настройте MikroTik (Terminal):"
echo "1. Создайте Action:"
echo "   /system logging action add name=lokisyslog target=remote remote=$MY_IP remote-port=1514 src-address=0.0.0.0 remote-log-format=bsd-syslog syslog-time-format=bsd-syslog syslog-facility=local0"
echo "   (Или remote-log-format=default, если v7 ругается)"
echo ""
echo "2. Включите логирование:"
echo "   /system logging add topics=info action=lokisyslog"
echo "   /system logging add topics=error action=lokisyslog"
echo "   /system logging add topics=firewall action=lokisyslog"
echo ""
echo "3. Включите лог в правиле Firewall Drop:"
echo "   /ip firewall filter set [find action=drop chain=input] log=yes log-prefix=\"FW_DROP\""
echo "-----------------------------------------------------------"
echo "Grafana Data Source URL: http://$MY_IP:3100"
