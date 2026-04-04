<p align="center">
  <img src="https://img.shields.io/badge/version-2.1-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Claude%20%7C%20GPT--4-purple?style=for-the-badge" />
</p>

<h1 align="center">🦅 HawkEye v2.1</h1>
<p align="center"><b>AI-Powered Bug Bounty Automation Tool</b></p>
<p align="center">
  Automated recon → vulnerability scanning → AI analysis → professional report
</p>

---

## Features

| Module | Tools | What it finds |
|--------|-------|---------------|
| **Recon** | subfinder, assetfinder, crt.sh, waybackurls, katana | Subdomains, endpoints, JS files |
| **Live Detection** | httpx (ProjectDiscovery) | Live hosts, status codes |
| **Vulnerability Scan** | nuclei (all templates) | CVEs, misconfigs, exposures |
| **CORS** | Built-in | Origin reflection, null origin, subdomain spoofing |
| **XSS** | dalfox | Reflected/DOM XSS with PoC |
| **SQLi** | nuclei + gf-style filtering | SQL injection via parameter analysis |
| **Path Discovery** | ffuf | Hidden endpoints, admin panels |
| **Vhost Fuzzing** | ffuf (Host header) | Hidden virtual hosts |
| **Hidden Params** | arjun | Undocumented GET/POST parameters |
| **Port Scan** | nmap | Open ports, services |
| **JS Analysis** | AI (regex + LLM) | API keys, secrets, internal URLs |
| **AI Validation** | DeepSeek / Claude / GPT-4 | False positive filtering, PoC generation |

## Quick Start

```bash
# 1. Clone
git clone https://github.com/A-cyb3r/hawkeye.git
cd hawkeye

# 2. Install dependencies
chmod +x install.sh && ./install.sh

# 3. Configure API key
cp .env.example .env
nano .env  # Add your AI API key (DeepSeek recommended — cheapest)

# 4. Scan
./hawkeye --target example.com --verbose
```

## Usage

```
./hawkeye [flags]

Flags:
  --target    string   Target domain (required)
  --verbose            Show detailed scan progress
  --skip-recon         Skip recon phase (faster, use if subdomains known)
  --config    string   Config file path (default: config.yaml)
  --output    string   Output directory for reports (default: ./reports)
  --check-tools        Check installed tools and exit
  -h, --help           Help
```

### Examples

```bash
# Full scan with verbose output
./hawkeye --target target.com --verbose

# Skip recon (faster, scan only the main domain)
./hawkeye --target target.com --skip-recon --verbose

# Custom config
./hawkeye --target target.com --config my-config.yaml

# Check all tools are installed
./hawkeye --check-tools
```

## Installation

### Requirements

- Go 1.21+
- Linux (Ubuntu 20.04+ / Kali / Debian)

### Automatic (recommended)

```bash
./install.sh
```

### Manual

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest

# System
sudo apt install nmap -y

# Optional (hidden parameter discovery)
pip3 install arjun

# Nuclei templates
nuclei -update-templates

# Build
go build -o hawkeye ./cmd/main.go
```

## Configuration

Copy `.env.example` to `.env` and add your API key:

```bash
cp .env.example .env
```

Edit `config.yaml` for advanced options:

```yaml
ai:
  provider: "deepseek"          # deepseek | claude | openai | openrouter
  api_key: "${DEEPSEEK_API_KEY}" # reads from .env automatically

scanning:
  tools:
    ffuf:
      vhost_fuzzing: true       # discover hidden virtual hosts
    arjun:
      enabled: true             # hidden parameter discovery
    dalfox:
      blind_url: ""             # optional: blind XSS callback

reporting:
  language: "ar"                # ar | en
  include_poc: true
```

## AI Providers

| Provider | Model | Cost/1M tokens | Notes |
|----------|-------|----------------|-------|
| **DeepSeek** | deepseek-chat | $0.28 input / $1.10 output | Recommended |
| **Claude** | claude-sonnet-4 | $3 / $15 | Best accuracy |
| **OpenAI** | gpt-4o-mini | $0.15 / $0.60 | Good balance |
| **OpenRouter** | any model | varies | Access all models |

## Output

Reports are saved to `./reports/` as Markdown:

```
reports/
└── bug_bounty_report_2026-04-04_12-27-45.md
```

Each report includes:
- Executive summary with risk score
- AI-validated findings only (false positives filtered)
- Evidence and PoC for each vulnerability
- Severity distribution
- Subdomains discovered

## Pipeline

```
Target Domain
     │
     ▼
┌─────────────┐
│  Phase 1    │  subfinder + assetfinder + crt.sh + wayback + katana
│  Recon      │  → subdomains, URLs, JS files
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Phase 2    │  httpx → nuclei → CORS → nmap → ffuf → arjun → dalfox → SQLi
│  Scanning   │  → raw findings (all severities)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Phase 3    │  AI validates each finding, filters false positives,
│  AI Review  │  generates Arabic/English analysis + PoC
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Phase 4    │  Markdown report with executive summary
│  Report     │
└─────────────┘
```

## Legal

> **This tool is for authorized security testing only.**
> Only scan systems you own or have explicit written permission to test.
> See [SECURITY.md](SECURITY.md) for full policy.

---

<p align="center">
  Developed by <a href="https://twitter.com/A_cyb3r">@A_cyb3r</a> · MIT License
</p>
