# novatun (نوواتون)

<div align="center">

**High-Performance, DPI-Resistant Custom Tunneling Protocol in Go**  
*پروتکل تونلینگ اختصاصی، فوق‌سریع و مقاوم در برابر فیلترینگ عمیق (DPI)*

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/vpncore1/novatun?color=blue)](https://github.com/vpncore1/novatun/releases)

[English](#english-documentation) • [راهنمای فارسی](#راهنمای-فارسی)

</div>

---

## راهنمای فارسی

پروتکل **novatun** یک راهکار امنیتی و انتقال ترافیک لایه پایین بر بستر Go است که با هدف عبور از سیستم‌های بازرسی عمیق بسته‌ها (DPI)، فایروال‌های ملی و مسدودسازی‌های آماری طراحی شده است.

### ویژگی‌های کلیدی:
- **رمزنگاری سرتاسری مدرن:** الگوریتم ChaCha20-Poly1305 با تعویض کلید X25519 ECDH بر پایه PSK.
- **بدون هرگونه هدر یا امضای پروتکل:** پکت‌ها و داده‌های روی سیم (Wire) کاملاً غیرقابل تفکیک از نویز تصادفی انتروپی بالا هستند.
- **پدینگ پویا و تصادفی:** هر فریم دارای ۱۶ تا ۱۲۸ بایت Padding تصادفی برای شکست الگوهای آماری و طول پکت است.
- **استگانوگرافی و استتار وب (WebSocket Camouflage):** امکان پوشش ترافیک در قالب پکت‌های استاندارد RFC 6455 بر روی پورت اختصاصی مخفی (Stealth Port) همراه با هدایت کاوش‌های غیرمجاز فایروال (Active Probing Fallback).
- **پل خودکار پنل ثنایی (x-ui / 3x-ui Bridge):** سرور ایران به طور خودکار پورت‌های پنل خارج (`443, 80, 2053, 2083, 2087, 8443` و...) را به لوپ‌بک سرور خارج فوروارد می‌کند. بدون نیاز به هیچ ابزار کمکی دیگر!
- **مالتی‌پلکسینگ با راندمان بالا:** مبتنی بر HashiCorp Yamux جهت اشتراک صدها استریم هم‌زمان روی یک نشست امن.
- **پشتیبانی کامل از TCP و UDP:** تونل‌سازی شفاف صوت (VoIP)، DNS از راه دور و بازی‌ها.

---

### نصب آسان با یک دستور (One-Line Installer)

برای نصب بر روی اوبونتو/دبیان/سنت‌او‌اس، دستور زیر را در ترمینال اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vpncore1/novatun/main/scripts/install.sh)
```

#### نحوه راه‌اندازی سریع در ۲ مرحله (مخصوص پنل ثنایی):

#### گام ۱: اجرا روی سرور خارج (Server Kharej - Exit Node)
1. اسکریپت بالا را روی سرور خارج اجرا کرده و گزینه `1` را انتخاب کنید.
2. پورت تونل مخفی را انتخاب کنید (پیش‌فرض `9443`).
3. در پایان، اسکریپت یک **دستور تک‌خطی اختصاصی برای سرور ایران** چاپ می‌کند. آن را کپی کنید.

#### گام ۲: اجرا روی سرور ایران (Server Iran - Relay Node)
1. دستور تک‌خطی چاپ شده از مرحله قبل را در ترمینال سرور ایران پیست و اینتر کنید.
2. تبریک! تونل متصل شد و تمام پورت‌های پنل خارج (`443, 80, 2053, 8443, ...`) روی سرور ایران باز شدند.
3. اکنون در نرم‌افزارهای کلاینت (v2rayNG, V2rayN, Streisand) فقط کافیست **آدرس سرور را IP سرور ایران** قرار دهید. ترافیک به صورت نامرئی و با سرعت بالا به پنل ثنایی در خارج هدایت می‌شود.

---

## English Documentation

**novatun** is a state-of-the-art tunneling protocol and VPN core designed from the ground up to resist state-level Deep Packet Inspection (DPI), active probing attacks, and statistical traffic fingerprinting.

### Architecture Highlights
- **Cryptographic Primitives:** ChaCha20-Poly1305 AEAD with PFS (Perfect Forward Secrecy) via X25519 ECDH + 32-byte Pre-Shared Key (PSK).
- **Zero Static Signatures:** Handshakes and transport frames resemble indistinguishable pseudo-random white noise.
- **Dynamic Random Padding:** Every frame prepends dynamic padding (16–128 bytes) to disrupt packet-size distribution profiling.
- **Transport Steganography:** Standard RFC 6455 WebSocket framing over TCP port 443 with probe mitigation reverse-proxying.
- **Multiplexed Streaming:** Zero-allocation stream multiplexing via Yamux over a single long-lived resilient session.
- **Full TCP & UDP Transport:** Complete transparent tunneling of datagrams and streams (SOCKS5 RFC 1928 + Full TUN VPN).

---

### One-Command Quick Install

Run on any standard Linux server (Ubuntu, Debian, CentOS, AlmaLinux, Rocky):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vpncore1/novatun/main/scripts/install.sh)
```

### Manual Configuration Schema

#### Server (`/etc/novatun/kharej.json`):
```json
{
  "listen": ":443",
  "psk": "e1f2a3b4c5d6...64_HEX_CHARS",
  "mode": "ws",
  "path": "/api/v1/stream-xyz",
  "fallback_addr": "127.0.0.1:80",
  "log_level": "info"
}
```

#### Client / Relay (`/etc/novatun/iran.json`):
```json
{
  "server": "KHAREJ_IP:443",
  "psk": "e1f2a3b4c5d6...64_HEX_CHARS",
  "mode": "ws",
  "host": "KHAREJ_IP",
  "path": "/api/v1/stream-xyz",
  "socks": "0.0.0.0:1080",
  "tun": false,
  "tun_name": "novatun0"
}
```

### Managing Systemd Services
```bash
# Check status
systemctl status novatun-kharej   # On exit node
systemctl status novatun-iran     # On relay node

# View live logs
journalctl -u novatun-kharej -f
journalctl -u novatun-iran -f
```

---

### Building from Source

```bash
# Clone repository
git clone https://github.com/vpncore1/novatun.git
cd novatun

# Build Server and Client binaries
go build -ldflags="-s -w" -o novatun-server ./cmd/server
go build -ldflags="-s -w" -o novatun-client ./cmd/client

# Run tests
go test -v ./...
```

### License
Released under the [MIT License](LICENSE).
