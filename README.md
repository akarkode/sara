# ARGUS — Automated Recon & Gathering Utility System

Self-hosted recon automation web app for bug bounty and penetration testing. Runs reconnaissance tools sequentially on a target domain, streams results in real-time to the browser, and exports findings as PDF or CSV with status code filtering.

## Features

- **Subdomain discovery & HTTP probing** (subfinder + httpx as one unit)
- **Directory & file fuzzing** with ffuf
- **Web technology fingerprinting** via WhatWeb
- **WAF detection** using WAFw00f
- **DNS enumeration** with dig
- **Domain WHOIS lookup**
- **Port scanning & service detection** via Nmap
- **Selectable tools** — choose which recon tools to run per scan
- **Real-time output streaming** to browser via SSE
- **Status code color-coding** — 2xx/3xx/4xx/5xx visually distinct in terminal
- **Filtered export** — export PDF/CSV filtered by status code
- **Custom wordlist** support for ffuf
- **Structured data parsing** — all tool output parsed into structured fields
- **Low-resource design** — optimized for 512MB VPS

## Requirements

- Python 3.10+
- Go 1.18+ (for subfinder, httpx)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [ffuf](https://github.com/ffuf/ffuf)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [WAFw00f](https://github.com/EnableSecurity/wafw00f)
- [Nmap](https://nmap.org/)
- dig (usually pre-installed, part of `dnsutils`)
- whois (usually pre-installed)

## Local Setup

```bash
git clone <repo-url>
cd argus
pip install -r requirements.txt
```

Install Go-based tools:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

Install other tools:
```bash
pip install wafw00f
sudo apt install -y whatweb nmap dnsutils whois
```

Configure and run:
```bash
cp .env.example .env
uvicorn main:app --host 127.0.0.1 --port 8000
```

## VPS Setup (Debian)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip golang-go git nmap whatweb dnsutils whois
```

```bash
export PATH=$PATH:$(go env GOPATH)/bin
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
pip install wafw00f
```

```bash
git clone <repo-url> /opt/argus
cd /opt/argus
pip install -r requirements.txt
cp .env.example .env
```

Nginx reverse proxy (`/etc/nginx/sites-available/argus`):
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/argus /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

Systemd service (`/etc/systemd/system/argus.service`):
```ini
[Unit]
Description=ARGUS Recon App
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/argus
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 127.0.0.1 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now argus
```

Optional basic auth:
```bash
sudo apt install -y apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin
```

Add to Nginx location block:
```nginx
auth_basic "ARGUS";
auth_basic_user_file /etc/nginx/.htpasswd;
```

## Usage

1. Open `http://localhost:8000`
2. Select recon tools to run (checkboxes)
3. Enter target domain and click **SCAN**
4. Watch real-time output with color-coded status codes
5. Filter terminal output by status code (2xx/3xx/4xx/5xx)
6. Export results as PDF or CSV with status code filters

## Disclaimer

For authorized security testing only. Always obtain proper written permission before scanning any target.
