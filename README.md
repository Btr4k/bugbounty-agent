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
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
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
./hawkeye --target hackerone-target.com
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
  │  katana                                                         │
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
  │  nmap          → open ports                                     │
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
  │           DOM XSS sinks · postMessage issues                   │
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
| Subdomain Recon | subfinder · assetfinder · crt.sh · C99 | Subdomains |
| URL Discovery | waybackurls · katana | Endpoints, parameters, JS files |
| Live Detection | httpx | Live hosts, HTTP status, tech stack |
| Vulnerability Scan | nuclei (full templates) | CVEs, misconfigs, exposures, takeovers |
| CORS Testing | Built-in Go engine | Origin reflection, null origin, subdomain spoof, HTTP downgrade |
| Directory Fuzzing | ffuf | Hidden paths, admin panels, sensitive files |
| Vhost Discovery | ffuf (Host header) | Hidden virtual hosts |
| XSS | dalfox | Reflected & DOM XSS with PoC |
| SQLi | nuclei + param filter | SQL injection vectors |
| Hidden Params | arjun | Undocumented GET/POST parameters |
| Port Scan | nmap | Open ports |
| JS Analysis | Regex + LLM | API keys, secrets, endpoints, S3 buckets, tokens |
| AI Validation | DeepSeek / Claude / GPT-4 | False positive filtering + PoC generation |

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
./hawkeye --target target.com
```

---

## Usage

```
./hawkeye [flags]

Required:
  -t, --target      string   Target domain (e.g. example.com)

Options:
  -v, --verbose              Show detailed scan progress
  -c, --config     string    Config file path (default: config.yaml)
  -o, --output     string    Report output directory (default: ./reports)
      --skip-recon           Skip recon phase (subdomains already known)
      --skip-scan            Skip vulnerability scanning phase
      --js-only              Run JS analysis only (skips recon and scanning)
      --ai-provider string   Override AI provider: claude | deepseek | openai | openrouter
      --ai-model    string   Override AI model name
  -h, --help                 Show help
```

### Examples

```bash
# Standard full scan
./hawkeye --target target.com

# Full scan with live progress output
./hawkeye --target target.com --verbose

# JS secrets and endpoints only (fast, no scanning)
./hawkeye --target target.com --js-only

# Skip subdomain enumeration
./hawkeye --target target.com --skip-recon

# Skip scanning, run AI analysis on recon output only
./hawkeye --target target.com --skip-scan

# Use a specific AI provider for this run
./hawkeye --target target.com --ai-provider claude --ai-model claude-sonnet-4-20250514

# Use short flags
./hawkeye -t target.com -v
```

---

## Installation

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali, Parrot)
- **Go**: 1.24 or later
- **RAM**: 512MB minimum, 2GB recommended for large targets

### Automatic (recommended)

```bash
chmod +x install.sh && ./install.sh
```

The installer handles Go tools, system packages, and nuclei templates.

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
sudo apt install -y nmap

# Optional — hidden parameter discovery
pip3 install arjun

# Wordlist for ffuf (strongly recommended)
sudo apt install seclists

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
| **Claude** | claude-sonnet-4-20250514 | $3 / $15 | Highest accuracy |
| **OpenAI** | gpt-4o-mini | $0.15 / $0.60 | Fast and cheap |
| **OpenRouter** | any model | varies | Multi-model access |

### Wordlist (ffuf)

For maximum path discovery coverage, install SecLists:

```bash
sudo apt install seclists
# Auto-detected at: /usr/share/seclists/Discovery/Web-Content/common.txt
```

Or specify a custom path in `config.yaml`:

```yaml
scanning:
  tools:
    ffuf:
      wordlist_path: "/path/to/your/wordlist.txt"
```

Without SecLists, HawkEye falls back to a built-in list of ~130 high-value paths  
(.env, .git, admin panels, Spring actuators, swagger, etc.) — functional but limited coverage.

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

## CORS Severity Reference

HawkEye's built-in CORS engine tests multiple attack vectors and assigns severity  
based on actual exploitability — not just header presence:

| Pattern | Severity | Exploitable? |
|---|---|---|
| Origin reflected + `credentials: true` | **Critical** | Yes — any attacker site can steal authenticated data |
| Null origin + `credentials: true` | **High** | Yes — exploitable via sandboxed iframe |
| Subdomain spoof + `credentials: true` | **High** | Yes — attacker registers a matching domain |
| HTTP origin on HTTPS + `credentials: true` | **High** | Yes — requires network MITM position |
| Origin reflected, no credentials | **High** | Yes — public/unauthenticated data readable cross-origin |
| Subdomain spoof, no credentials | **Medium** | Partial — weak origin validation, no credentials |
| `*` + `credentials: true` | **Medium** | No — browsers reject this combination per CORS spec |

---

## Legal

> **HawkEye is for authorized security testing only.**  
> Only use this tool against systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> See [SECURITY.md](SECURITY.md) for the full responsible disclosure policy.

---

<p align="center">
  Built by <a href="https://x.com/A_cyb3r">@A_cyb3r</a> &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; v2.1
</p>
