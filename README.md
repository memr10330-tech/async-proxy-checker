# ⚡ Async Proxy Checker & Anonymity Judge

An asynchronous, high-speed CLI tool built with Python, `asyncio`, and `aiohttp` to validate proxy pools, benchmark latencies, and determine anonymity levels across multiple protocols (**HTTP, HTTPS, SOCKS4, SOCKS5**).

Designed specifically for **web scraping, anti-bot bypass workflows, and data harvesting pipelines**.

---

## ✨ Features

- 🚀 **High-Throughput Asynchronous Engine**: Test hundreds or thousands of proxies concurrently using `asyncio` and `aiohttp`.
- 🌐 **Multi-Protocol Support**: Seamlessly checks `HTTP`, `HTTPS`, `SOCKS4`, and `SOCKS5` (including authenticated proxies).
- 🛡️ **Three-Tier Anonymity Detection**:
  - **Elite (Level 1)**: The destination server cannot identify your real IP and cannot detect that you are using a proxy.
  - **Anonymous (Level 2)**: The destination knows you are using a proxy (via `Via` or forwarding headers), but your real IP is masked.
  - **Transparent (Level 3)**: Your real IP address is leaked in `X-Forwarded-For` or request headers.
- ⏱️ **Latency Benchmarking**: Accurately tracks round-trip ping time in milliseconds (`ms`).
- 📊 **Terminal Dashboard**: Beautiful, real-time progress bar and formatted results table powered by `rich`.
- 💾 **Dual Output Export**: Automatically saves valid proxies to both `working_proxies.txt` (clean list) and `working_proxies.json` (detailed diagnostics).

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<YOUR_USERNAME>/async-proxy-checker.git
   cd async-proxy-checker
   ```

2. **Create a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Quick Start

1. Add your proxies to `proxies.txt` (one per line). Supported formats:
   ```text
   192.168.1.1:8080
   http://192.168.1.1:8080
   socks5://192.168.1.1:1080
   socks5://username:password@192.168.1.1:1080
   ```

2. Run the checker:
   ```bash
   python proxy_checker.py
   ```

---

## ⚙️ CLI Options & Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-f`, `--file` | `proxies.txt` | Path to text file containing proxy list |
| `-c`, `--concurrency` | `50` | Maximum number of concurrent connections |
| `-t`, `--timeout` | `8.0` | Connection timeout per proxy in seconds |
| `-o`, `--output` | `working_proxies.txt` | Output file for active proxies list |
| `--json` | `working_proxies.json` | Detailed JSON output file |

### Example with custom parameters:
```bash
python proxy_checker.py --file my_proxies.txt --concurrency 100 --timeout 5.0
```

---

## 📋 Sample Output

```text
┌──────────┬───────────────────────────────┬──────────────────┬───────────┬───────────────┐
│ Protocol │ Proxy Address                 │ External IP      │   Latency │   Anonymity   │
├──────────┼───────────────────────────────┼──────────────────┼───────────┼───────────────┤
│ SOCKS5   │ socks5://185.220.101.5:9050   │ 185.220.101.5    │ 142.10 ms │     Elite     │
│ HTTP     │ http://51.158.111.242:8811    │ 51.158.111.242   │ 312.45 ms │   Anonymous   │
└──────────┴───────────────────────────────┴──────────────────┴───────────┴───────────────┘
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page or submit pull requests.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
