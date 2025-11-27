#!/bin/bash

# Остановка при ошибке
set -e

# Цвета для вывода
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Автоматическая установка SIEM (Rsyslog + Loki v3 + Promtail v3) ===${NC}"
echo "Версии: v3.6.2"
echo "Источник GeoIP: P3TERX (GitHub)"
echo ""

# --- 1. Сбор переменных ---
read -p "Введите IP адрес вашего MikroTik (откуда пойдут логи): " MIKROTIK_IP

LOKI_VERSION="3.6.2"
PROMTAIL_VERSION="3.6.2"

# --- 2. Подготовка системы ---
echo -e "${BLUE}[1/7] Обновление системы и установка зависимостей...${NC}"
apt-get update -qq
apt-get install -y -qq rsyslog wget unzip curl

# --- 3. Настройка Rsyslog ---
echo -e "${BLUE}[2/7] Настройка Rsyslog (Буфер)...${NC}"

# Включаем UDP 1514
sed -i '/module(load="imudp")/s/^#//g' /etc/rsyslog.conf
sed -i '/input(type="imudp" port="514")/s/^#//g' /etc/rsyslog.conf
# Меняем порт на 1514 (если он был 514)
sed -i 's/port="514"/port="1514"/g' /etc/rsyslog.conf
# Отключаем imklog чтобы не ругался в LXC
sed -i '/module(load="imklog")/s/^/#/g' /etc/rsyslog.conf

# Создаем фильтр для Микротика
cat > /etc/rsyslog.d/mikrotik.conf <<EOF
# Фильтр логов MikroTik в отдельный файл
if \$fromhost-ip == '$MIKROTIK_IP' then {
    action(type="omfile" file="/var/log/mikrotik.log")
    stop
}
EOF

# Создаем пустой лог и даем права
touch /var/log/mikrotik.log
chmod 644 /var/log/mikrotik.log

# Настройка ротации
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

# --- 4. Установка Loki ---
echo -e "${BLUE}[3/7] Установка Loki v$LOKI_VERSION...${NC}"
cd /tmp
# В версии 3.x имя файла может содержать build info, но ссылка обычно стандартная
wget -q "https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-amd64.zip"
unzip -q loki-linux-amd64.zip
mv loki-linux-amd64 /usr/local/bin/loki
chmod +x /usr/local/bin/loki

# Создаем пользователя и папки
if ! id "loki" &>/dev/null; then useradd --no-create-home --shell /bin/false loki; fi
mkdir -p /var/lib/loki
chown -R loki:loki /var/lib/loki
mkdir -p /etc/loki

# Конфиг Loki (АДАПТИРОВАН ПОД v3.x: tsdb + schema v13)
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

# В v3 compactor берет настройки из common, shared_store не нужен
compactor:
  working_directory: /var/lib/loki/compactor
  delete_request_store: filesystem

analytics:
  reporting_enabled: false
EOF

# Сервис Loki
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

# --- 5. Скачивание GeoIP (P3TERX) ---
echo -e "${BLUE}[4/7] Скачивание базы GeoIP (Latest)...${NC}"
mkdir -p /etc/promtail

wget -q -O /etc/promtail/GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"

if [ -f "/etc/promtail/GeoLite2-City.mmdb" ]; then
    echo "База GeoIP успешно загружена."
else
    echo "Ошибка загрузки GeoIP! Проверьте интернет."
    exit 1
fi

# --- 6. Установка Promtail ---
echo -e "${BLUE}[5/7] Установка Promtail v$PROMTAIL_VERSION...${NC}"
cd /tmp
wget -q "https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-amd64.zip"
unzip -q promtail-linux-amd64.zip
mv promtail-linux-amd64 /usr/local/bin/promtail
chmod +x /usr/local/bin/promtail

# Создаем папки для Promtail
mkdir -p /var/lib/promtail

# Конфиг Promtail (С GeoIP и чтением файла от rsyslog)
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
      # 1. Попытка №1: Ищем формат Firewall (IP:PORT->)
      - regex:
          expression: ',\s(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+->'

      # 2. Попытка №2: Ищем классический формат (src-address=)
      - regex:
          expression: 'src-address=(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

      # 3. GeoIP
      - geoip:
          db: "/etc/promtail/GeoLite2-City.mmdb"
          source: "source_ip"
          db_type: "city"

      # 4. Упаковка
      - pack:
          labels:
            - source_ip
            - geoip_country_name
            - geoip_city_name
            - geoip_location_latitude
            - geoip_location_longitude
EOF

# Сервис Promtail
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

# --- 7. Запуск ---
echo -e "${BLUE}[6/7] Запуск сервисов...${NC}"
systemctl daemon-reload
systemctl enable loki promtail
systemctl restart loki promtail

# Чистка
rm -f /tmp/loki* /tmp/promtail*

MY_IP=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}=== УСТАНОВКА (v3.6.2) ЗАВЕРШЕНА! ===${NC}"
echo "--------------------------------------------------"
echo "Настройки для MikroTik (Terminal):"
echo "/system logging action add name=lokisyslog target=remote remote=$MY_IP remote-port=1514 src-address=0.0.0.0 remote-log-format=bsd-syslog syslog-time-format=bsd-syslog syslog-facility=local0"
echo "/system logging add topics=info action=lokisyslog"
echo "/system logging add topics=error action=lokisyslog"
echo "/system logging add topics=firewall action=lokisyslog"
echo "/ip firewall filter set [find action=drop chain=input] log=yes log-prefix=\"FW_DROP\""
echo "--------------------------------------------------"
echo "Адрес для Grafana (Loki URL): http://$MY_IP:3100"
