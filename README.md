```
                                                                        
  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗███████╗        
  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝        
  ███████║███████║██║ █╗ ██║█████╔╝ █████╗   ╚████╔╝ █████╗          
  ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝          
  ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗███████╗   ██║   ███████╗        
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝       
                                                          v2.1 🦅      
         A I - P o w e r e d   B u g   B o u n t y   A g e n t        
```

<p align="center">
  <img src="https://img.shields.io/badge/version-2.1-0d1117?style=for-the-badge&labelColor=0d1117&color=58a6ff" />
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Claude%20%7C%20GPT--4-a855f7?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux-f97316?style=for-the-badge&logo=linux&logoColor=white" />
</p>

<p align="center">
  <b>Recon → Scan → AI Validation → Report</b><br/>
  One command. Full attack surface. Zero noise.
</p>

---

## What is HawkEye?

HawkEye is a full-pipeline bug bounty automation agent written in Go.  
It chains recon tools, vulnerability scanners, and an AI validator into a single workflow —  
producing a clean, analyst-grade report with confirmed findings only.

```
./hawkeye -d hackerone-target.com
```

That's it. HawkEye handles the rest.

---

## Pipeline

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                         TARGET DOMAIN                            │
  └─────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 1 — RECON                                                │
  │                                                                 │
  │  subfinder · assetfinder · crt.sh · C99.nl · waybackurls       │
  │  katana · gau                                                   │
  │                                                                 │
  │  → subdomains · live URLs · JS files · parameters              │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 2 — SCANNING (parallel)                                  │
  │                                                                 │
  │  httpx         → live host detection + status codes            │
  │  nuclei        → CVEs · misconfigs · exposures · takeovers     │
  │  CORS engine   → origin reflection · null · subdomain spoof    │
  │  ffuf          → hidden paths · admin panels · vhost fuzzing   │
  │  dalfox        → reflected & DOM XSS with PoC                  │
  │  arjun         → undocumented GET/POST parameters              │
  │  nmap          → open ports · service fingerprinting           │
  │  SQLi scanner  → injection via parameter analysis              │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 2.5 — JS ANALYSIS                                        │
  │                                                                 │
  │  Regex engine  → API keys · secrets · endpoints · S3 buckets   │
  │  AI (LLM)      → deep analysis of app bundles (12KB/file)      │
  │                                                                 │
  │  Detects: AWS/GitHub/Stripe/Firebase keys · JWT tokens         │
  │           hardcoded passwords · internal API routes            │
  │           DOM XSS sinks · postMessage issues · SSRF vectors    │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 3 — AI VALIDATION                                        │
  │                                                                 │
  │  Every finding is reviewed by the AI:                          │
  │  · Confirms real vs false positive                             │
  │  · Assigns CVSS-informed severity                              │
  │  · Generates PoC for each confirmed finding                    │
  │  · Writes impact assessment + remediation                      │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 4 — REPORT                                               │
  │                                                                 │
  │  Markdown report with:                                         │
  │  · Executive summary · Risk score · Severity breakdown         │
  │  · Confirmed findings only · Evidence + PoC per finding        │
  └─────────────────────────────────────────────────────────────────┘
```

---

## Modules

| Module | Engine | Finds |
|---|---|---|
| Subdomain Recon | subfinder · assetfinder · crt.sh · C99 | Live subdomains |
| URL Discovery | waybackurls · katana · gau | Endpoints, parameters |
| Live Detection | httpx | HTTP status, ports, tech |
| Vulnerability Scan | nuclei (full templates) | CVEs, misconfigs, exposures |
| CORS Testing | Built-in Go engine | Origin reflection, null origin, subdomain spoof, HTTP downgrade |
| Directory Fuzzing | ffuf | Hidden paths, admin panels, sensitive files |
| Vhost Discovery | ffuf (Host header) | Internal virtual hosts |
| XSS | dalfox | Reflected & DOM XSS with working PoC |
| SQLi | nuclei + param filter | SQL injection vectors |
| Hidden Params | arjun | Undocumented GET/POST params |
| Port Scan | nmap | Open ports, service versions |
| JS Analysis | Regex + LLM | API keys, secrets, endpoints, tokens |
| AI Validation | DeepSeek / Claude / GPT-4 | False positive filtering + PoC |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Btr4k/bugbounty-agent.git
cd bugbounty-agent

# 2. Install all dependencies
chmod +x install.sh && ./install.sh

# 3. Set your AI key
cp .env.example .env
echo "DEEPSEEK_API_KEY=your-key-here" >> .env

# 4. Build
go build -o hawkeye ./cmd/main.go

# 5. Scan
./hawkeye -d target.com
```

---

## Usage

```
./hawkeye [flags]

Required:
  -d, --domain      string   Target domain (e.g. example.com)

Options:
  -v, --verbose              Show detailed progress
      --skip-recon           Skip recon phase (use if subdomains already known)
      --js-only              Run JS analysis only (no scanning)
      --deep                 Deep scan — more threads, more templates
      --config     string    Config file path (default: config.yaml)
      --output     string    Report output directory (default: ./reports)
      --check-tools          Check installed tools and exit
  -h, --help                 Show help
```

### Examples

```bash
# Standard full scan
./hawkeye -d target.com

# Full scan with live output
./hawkeye -d target.com --verbose

# JS secrets/endpoints only (fast)
./hawkeye -d target.com --js-only

# Deep scan (more coverage, slower)
./hawkeye -d target.com --deep --verbose

# Skip subdomain enumeration (scan known scope only)
./hawkeye -d target.com --skip-recon

# Verify tools are installed
./hawkeye --check-tools
```

---

## Installation

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali, Parrot)
- **Go**: 1.21 or later
- **RAM**: 512MB minimum, 2GB recommended for deep scans

### Automatic (recommended)

```bash
chmod +x install.sh && ./install.sh
```

The installer handles Go tools, system packages, nuclei templates, and SecLists.

### Manual

```bash
# Core Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# System tools
sudo apt install -y nmap seclists

# Optional — hidden parameter discovery
pip3 install arjun

# Nuclei templates
nuclei -update-templates

# Build HawkEye
go build -o hawkeye ./cmd/main.go
```

---

## Configuration

### AI Provider

Edit `config.yaml` or set env vars in `.env`:

```yaml
ai:
  provider: "deepseek"            # deepseek | claude | openai | openrouter
  api_key: "${DEEPSEEK_API_KEY}"  # loaded from .env automatically
  model: "deepseek-chat"
  max_tokens: 2000
```

### Supported AI Providers

| Provider | Model | Input / Output (per 1M tokens) | Recommended For |
|---|---|---|---|
| **DeepSeek** | deepseek-chat | $0.28 / $1.10 | Default — best cost/quality ratio |
| **Claude** | claude-sonnet-4 | $3 / $15 | Highest accuracy |
| **OpenAI** | gpt-4o-mini | $0.15 / $0.60 | Fast and cheap |
| **OpenRouter** | any model | varies | Multi-model access |

### Wordlist (ffuf)

For maximum path discovery coverage, install SecLists:

```bash
sudo apt install seclists
# Wordlist auto-detected at: /usr/share/seclists/Discovery/Web-Content/common.txt
```

Or specify a custom path in `config.yaml`:

```yaml
scanning:
  tools:
    ffuf:
      wordlist_path: "/path/to/your/wordlist.txt"
```

Without SecLists, HawkEye falls back to a built-in list of ~130 high-value paths  
(.env, .git, admin panels, actuators, swagger, etc.) — still useful, but limited.

### Blind XSS

```yaml
scanning:
  tools:
    dalfox:
      blind_url: "https://your-burp-collaborator.com"
```

---

## Output

Reports are saved to `./reports/` in Markdown:

```
reports/
└── bug_bounty_report_2026-04-04_16-41-25.md
```

### Report Structure

```
Executive Summary
  └── Risk score · Finding counts · Subdomains discovered

Critical Findings
  └── Title · URL · Evidence · AI Analysis · PoC

High / Medium / Low Findings
  └── Same structure

Subdomain List
  └── All discovered subdomains
```

---

## CORS Severity Guide

HawkEye's built-in CORS engine distinguishes between actually exploitable misconfigs  
and header combinations that browsers block:

| Pattern | Severity | Exploitable? |
|---|---|---|
| Origin reflected + `credentials: true` | **Critical** | Yes — browser allows it |
| Null origin + `credentials: true` | **High** | Yes — via sandboxed iframe |
| Subdomain spoof + `credentials: true` | **High** | Yes — register matching domain |
| `*` + `credentials: true` | **Medium** | No — browsers block per spec |
| Origin reflected, no credentials | **High** | Yes — public data readable |
| HTTP origin on HTTPS + credentials | **High** | Yes — requires MITM |

---

## Legal

> **HawkEye is for authorized security testing only.**  
> Only use this tool against systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> See [SECURITY.md](SECURITY.md) for the full responsible disclosure policy.

---

<p align="center">
  Built by <a href="https://github.com/Btr4k">@Btr4k</a> &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; v2.1
</p>
