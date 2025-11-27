# 🛡️ Guide: Cyber Attack Map with MikroTik & Grafana

**Stack:** MikroTik → Rsyslog (LXC) → Promtail → Loki → Grafana.

-----

## Phase 1. Server Setup (Proxmox LXC)

We use **Rsyslog** as a reliable buffer to receive UDP logs from MikroTik and write them to a specific file.

### 1\. Prepare the LXC Container

Access the console of your container (where Rsyslog and Promtail will run).

**Install Rsyslog (if not present):**

```bash
apt update && apt install -y rsyslog curl unzip
```

**Configure Rsyslog to receive UDP:**
Open the main config:

```bash
nano /etc/rsyslog.conf
```

Uncomment these lines (remove the `#`):

```conf
module(load="imudp")
input(type="imudp" port="1514")
```

*(Optional: Comment out `module(load="imklog")` to avoid "permission denied" errors in LXC).*

**Configure isolation (Filter MikroTik logs to a separate file):**
Create a new config file:

```bash
nano /etc/rsyslog.d/mikrotik.conf
```

Paste the following (Replace `192.168.X.X` with your MikroTik's IP):

```conf
if $fromhost-ip == '192.168.X.X' then {
    action(type="omfile" file="/var/log/mikrotik.log")
    stop
}
```

**Configure Log Rotation (Prevent disk overflow):**
Create the rotation config:

```bash
nano /etc/logrotate.d/mikrotik
```

Paste:

```conf
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
```

**Restart Rsyslog:**

```bash
systemctl restart rsyslog
```

-----

## Phase 2. Promtail Configuration

Promtail will read the `/var/log/mikrotik.log` file, resolve IPs to locations, and push data to Loki.

### 1\. Download GeoIP Database

You need the `GeoLite2-City.mmdb` file.

```bash
wget https://github.com/P3TERX/GeoLite.mmdb/releases/download/2025.11.25/GeoLite2-City.mmdb
```
### 2\. Configure Promtail

Edit the config file:

```bash
nano /etc/promtail/config.yaml
```

Paste this content (Ensure `clients: url` points to your Loki instance):

```yaml
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
      # 1. Attempt to match Firewall format (IP:PORT->)
      - regex:
          expression: ',\s(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+->'

      # 2. Attempt to match standard format (src-address=)
      - regex:
          expression: 'src-address=(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

      # 3. Perform GeoIP Lookup
      - geoip:
          db: "/etc/promtail/GeoLite2-City.mmdb"
          source: "source_ip"
          db_type: "city"

      # 4. Pack metadata into the log line
      - pack:
          labels:
            - source_ip
            - geoip_country_name
            - geoip_city_name
            - geoip_location_latitude
            - geoip_location_longitude
```

**Create positions directory and restart:**

```bash
mkdir -p /var/lib/promtail
systemctl restart promtail
```

-----

## Phase 3. MikroTik Configuration

Configure the router to send logs to your server.

### 1\. Create Logging Action

Run this in the MikroTik terminal (Replace `192.168.X.Y` with your LXC IP):

```mikrotik
/system logging action add \
    name=lokisyslog \
    target=remote \
    remote=192.168.X.Y \
    remote-port=1514 \
    src-address=0.0.0.0 \
    remote-log-format=bsd-syslog \
    syslog-time-format=bsd-syslog \
    syslog-facility=local0
```

*(Note: If you are on RouterOS v7 and `bsd-syslog` is missing, use `remote-log-format=default`)*.

### 2\. Add Logging Rules

```mikrotik
/system logging add topics=info action=lokisyslog
/system logging add topics=error action=lokisyslog
/system logging add topics=firewall action=lokisyslog
```

### 3\. Enable Firewall Logging (Crucial\!)

To see attacks, you must enable the `Log` checkbox on your Drop rule:

```mikrotik
/ip firewall filter set [find action=drop chain=input] log=yes log-prefix="FW_DROP"
```

### 4\. Clean Local Logs (Optional)

To prevent firewall logs from spamming the WinBox log window:

```mikrotik
/system logging set [find target=memory topics~"info"] topics=info,!firewall
```

-----

## Phase 4. Visualization in Grafana

### Import the Geomap Panel

1.  In Grafana, go to **New Dashboard** -\> **Add Visualization**.
2.  Select **Loki** as the data source.
3.  In the right sidebar, look for the **"Panel JSON"** icon (or go to Inspect -\> Panel JSON).
4.  Paste the code below and click **Apply**.

**Panel JSON:**

```json
{
  "type": "geomap",
  "title": "Attack Map (By Country)",
  "datasource": { "type": "loki", "uid": "ff5cy9c2r02kgb" },
  "targets": [
    {
      "refId": "A",
      "expr": "topk(200, sum by (geoip_country_name) (count_over_time({job=\"mikrotik_via_rsyslog\"} | unpack | geoip_country_name != \"\" [$__range])))",
      "queryType": "instant",
      "format": "table"
    }
  ],
  "transformations": [
    { "id": "labelsToFields", "options": { "mode": "columns" } },
    { "id": "merge", "options": {} },
    { "id": "convertFieldType", "options": { "fields": {}, "conversions": [ { "targetField": "Value", "destinationType": "number" } ] } },
    { "id": "organize", "options": { "renameByName": { "Value": "Attack Count", "geoip_country_name": "Country", "Value #A": "Attack Count" } } }
  ],
  "fieldConfig": {
    "defaults": {
      "color": { "mode": "thresholds" },
      "thresholds": {
        "mode": "absolute",
        "steps": [
          { "color": "green", "value": null },
          { "color": "#00aeff", "value": 50 },
          { "color": "#EAB839", "value": 200 },
          { "color": "orange", "value": 500 },
          { "color": "red", "value": 1000 },
          { "color": "purple", "value": 5000 }
        ]
      }
    },
    "overrides": [
      { "matcher": { "id": "byName", "options": "Time" }, "properties": [ { "id": "custom.hideFrom", "value": { "legend": true, "tooltip": true, "viz": true } } ] },
      { "matcher": { "id": "byName", "options": "Attack Count" }, "properties": [ { "id": "color", "value": { "mode": "thresholds" } } ] }
    ]
  },
  "options": {
    "view": { "id": "coords", "lat": 55, "lon": 60, "zoom": 2, "allLayers": true },
    "layers": [
      {
        "type": "markers",
        "name": "Attacks",
        "config": {
          "style": {
            "size": { "fixed": 5, "min": 8, "max": 40, "field": "Attack Count" },
            "color": { "field": "Attack Count" },
            "opacity": 0.6,
            "symbol": { "mode": "fixed", "fixed": "img/icons/marker/circle.svg" }
          },
          "showLegend": true
        },
        "location": { "mode": "lookup", "lookup": "Country" },
        "tooltip": true
      }
    ]
  }
}
```
<img width="642" height="419" alt="изображение" src="https://github.com/user-attachments/assets/f76354d1-6929-4bbd-9eb9-585a09be63a2" />

