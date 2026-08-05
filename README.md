<p align="center">
  <img src="hawkeye-banner-v2.2.0.png" alt="HawkEye AI-Powered Bug Bounty Agent" width="720" />
</p>

<p align="center">
  <a href="https://github.com/Btr4k/bugbounty-agent/releases"><img src="https://img.shields.io/badge/version-2.3.0-0d1117?style=for-the-badge&labelColor=0d1117&color=58a6ff" alt="HawkEye version 2.3.0" /></a>
  <a href="https://github.com/Btr4k/bugbounty-agent/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Btr4k/bugbounty-agent/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI status" /></a>
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.25 or later" />
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Claude%20%7C%20OpenAI%20%7C%20OpenRouter-a855f7?style=for-the-badge" alt="Supported AI providers" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/platform-Linux-f97316?style=for-the-badge&logo=linux&logoColor=white" alt="Linux" />
</p>

<p align="center">
  <b>Recon → Scan → AI Validation → Report</b><br/>
  One command. Scoped attack surface. High-signal findings.
</p>

---

## What is HawkEye?

HawkEye is a full-pipeline bug bounty automation agent written in Go.  
It chains recon tools, vulnerability scanners, and an AI-assisted validator into a single workflow,
producing a scoped report that separates confirmed, manual-review, and rejected candidates.

```
./hawkeye -d your-authorized-host.example
```

Run it only after validating the configuration, traffic limits, and written
authorization for that exact host.

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
  │  PHASE 2 — SCANNING (sequential, one scanner at a time)         │
  │                                                                 │
  │  httpx   → live host detection + status codes                  │
  │  nuclei  → CVEs · misconfigs · exposures · takeovers (alone)   │
  │  dalfox  → reflected XSS with PoC                              │
  │  nmap    → opt-in reconnaissance only                          │
  │                                                                 │
  │  Scanners run one at a time to avoid OOM kills on modest hosts. │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 2.5 — JS ANALYSIS                                        │
  │                                                                 │
  │  Regex engine  → grounded credential/token candidates          │
  │  AI (LLM)      → bounded analysis of app bundles (12KB/file)   │
  │                                                                 │
  │  Detects: AWS/GitHub/Stripe keys · JWT tokens                  │
  │           hardcoded passwords · database credentials           │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 3 — VALIDATION PIPELINE                                  │
  │                                                                 │
  │  Every finding passes deterministic checks and AI review:      │
  │  · Rejects unsupported and likely false-positive results       │
  │  · Requires type-specific references to captured evidence      │
  │  · Preserves tool-captured reproduction commands               │
  │  · Writes impact assessment + remediation                      │
  └─────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  PHASE 4 — REPORT                                               │
  │                                                                 │
  │  Markdown report with:                                         │
  │  · Executive summary · Risk score · Severity breakdown         │
  │  · Validation-pipeline findings only · Captured evidence       │
  └─────────────────────────────────────────────────────────────────┘
```

---

## Modules

| Module | Engine | Finds |
|---|---|---|
| Subdomain Recon | subfinder · assetfinder · crt.sh · C99 | Subdomains |
| URL Discovery | waybackurls · katana | Endpoints, parameters, JS files |
| Live Detection | httpx | Live hosts used by downstream scanners |
| Vulnerability Scan | nuclei (high-value templates) | CVEs, misconfigs, exposures, takeovers, SQLi/injection templates |
| XSS | dalfox | Reflected XSS with PoC |
| Port Scan (opt-in) | nmap | Recon observations only |
| JS Analysis | Regex + prompt-visible LLM grounding | Credential, key, and token candidates requiring manual verification |
| Validation Pipeline | Deterministic rules + DeepSeek / Claude / GPT-4 | False-positive filtering + evidence review |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Btr4k/bugbounty-agent.git
cd bugbounty-agent

# 2. Install all dependencies
chmod +x install.sh && ./install.sh

# 3. With the sample provider:auto, set exactly one real provider key
cp .env.example .env
chmod 600 .env
# Edit .env and replace the matching placeholder with a real key

# 4. Scan the exact host only (safe default)
./hawkeye -d your-authorized-host.example

# Add this only when the program explicitly authorizes all subdomains
./hawkeye -d your-authorized-host.example --include-subdomains
```

---

## Usage

```
./hawkeye [flags]

Required (either flag works):
  -d, --domain      string   Authorized target domain
  -t, --target      string   Target domain (alias for -d/--domain)

Options:
  -v, --verbose              Show detailed scan progress
  -c, --config     string    Config file path (default: config.yaml)
  -o, --output     string    Report output directory (default: ./reports)
      --skip-recon           Skip recon phase (subdomains already known)
      --skip-scan            Skip vulnerability scanning phase
      --js-only              Run JS analysis only (skips vulnerability scanning)
      --include-subdomains   Explicitly authorize the target and its discovered subdomains
      --ai-provider string   Override AI provider: auto | claude | deepseek | openai | openrouter
      --ai-model    string   Override AI model name
      --check-config        Validate the config file and exit
      --version              Show HawkEye version
  -h, --help                 Show help
```

### Examples

```bash
# Exact-host scan (safe default)
./hawkeye -d your-authorized-host.example

# Wildcard-scope scan, only when *.your-authorized-host.example is explicitly authorized
./hawkeye -d your-authorized-host.example --include-subdomains

# Full scan with live progress output
./hawkeye -d your-authorized-host.example --verbose

# JS credential and token analysis only (fast, no vulnerability scanning)
./hawkeye -d your-authorized-host.example --js-only

# Skip subdomain enumeration
./hawkeye -d your-authorized-host.example --skip-recon

# Skip scanning, run AI analysis on recon output only
./hawkeye -d your-authorized-host.example --skip-scan

# Use a specific AI provider for this run
./hawkeye -d your-authorized-host.example --ai-provider claude --ai-model claude-sonnet-5

# Use short flags
./hawkeye -t your-authorized-host.example -v
```

---

## Installation

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali, Parrot)
- **Go**: 1.25 or later
- **RAM**: 512MB minimum, 2GB recommended for large targets

### Automatic (recommended)

```bash
chmod +x install.sh && ./install.sh
```

The installer pins the Go tools and installs the optional system packages.
It uses the Nuclei templates already present on the machine; set
`HAWKEYE_UPDATE_TEMPLATES=1` only when you intentionally want to update that
mutable template set during installation.

### Manual

```bash
# Core Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.12.0
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.0
go install github.com/projectdiscovery/katana/cmd/katana@v1.4.0
go install github.com/tomnomnom/assetfinder@v0.1.1
go install github.com/tomnomnom/waybackurls@v0.1.0
go install github.com/hahwul/dalfox/v2@v2.12.0

# System tools (optional — nmap port scanning is opt-in)
sudo apt install -y nmap

# Optional mutable template update; review template changes before production use
nuclei -update-templates

# Build HawkEye
go build -o hawkeye ./cmd/main.go
```

---

## Configuration

### AI Provider

Copy `.env.example` to `.env` and fill exactly one provider key when using the
sample `provider: "auto"`. Auto-detection fails closed when zero or multiple
real provider keys are present. Alternatively, select a provider explicitly in
`config.yaml`; HawkEye never switches it because another provider's key exists.

| Provider | Environment Variable | Default Model |
|---|---|---|
| Claude | `ANTHROPIC_API_KEY` | `claude-sonnet-5` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-v4-flash` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| OpenRouter | `OPENROUTER_API_KEY` | `deepseek/deepseek-v4-flash` |

These reviewed defaults were checked against the providers' official model
catalogs on 2026-08-05. Model availability is external state; re-check the
[Claude model lifecycle](https://platform.claude.com/docs/en/about-claude/model-deprecations),
[DeepSeek model list](https://api-docs.deepseek.com/api/list-models), and
[OpenAI model API](https://platform.openai.com/docs/api-reference/models), and
[OpenRouter model page](https://openrouter.ai/deepseek/deepseek-v4-flash/api)
before a later release.

To select a provider explicitly, edit `config.yaml`:

```yaml
ai:
  provider: "deepseek"            # deepseek | claude | openai | openrouter | custom
  api_key: "${DEEPSEEK_API_KEY}"  # loaded from .env automatically
  model: "deepseek-v4-flash"
  max_tokens: 8000
```

The `--ai-provider` flag can select `auto`, `claude`, `deepseek`, `openai`, or
`openrouter` for one run. A `custom` provider cannot be selected safely with
that flag alone: configure its key, model, and endpoint together in YAML.

For an OpenAI-compatible custom endpoint, both `model` and `base_url` are
required:

```yaml
ai:
  provider: "custom"
  api_key: "${AI_API_KEY}"
  model: "your-model"
  base_url: "https://your-endpoint.example/v1"
```

A custom endpoint receives the API credential and the redacted finding
context. Use only an endpoint you operate or explicitly trust, and review its
data-retention policy before sending any authorized target data.

### Scope and Rate Limits

The domain supplied with `--domain` or `--target` authorizes that exact host by
default. Subdomains are authorized only with `--include-subdomains`. HawkEye
rejects public suffixes, single-label targets, IP spellings, out-of-scope hosts,
and private/loopback/link-local DNS destinations in its guarded HTTP client.

Use `excluded_subdomains` for assets that the program explicitly excludes, and
set `rate_limit` to match the program's rules:

```yaml
target:
  excluded_subdomains:
    - "production.example.com"
    - "*.third-party.example.com"

scanning:
  rate_limit: 25
```

Always review the target program's written scope before starting a scan.

### Authenticated Testing

HawkEye can attach authorized test-account headers and cookies to its guarded
internal HTTPS downloader. Credentials are intentionally never placed in
external scanner command lines.

```env
TARGET_TOKEN=replace-with-a-limited-test-token
TARGET_SESSION=replace-with-a-limited-test-session
```

```yaml
authentication:
  allowed_hosts:
    - "https://app.example.com"
    - "https://*.api.example.com:443"
  headers:
    Authorization: "Bearer ${TARGET_TOKEN}"
  cookies:
    session: "${TARGET_SESSION}"
```

Authentication values are expanded from environment variables, restricted to
the exact HTTPS scheme/host/port rule on every redirect, and redacted before
AI/report/log output. External tools currently run unauthenticated because their
header flags expose secrets through process arguments.

Use only a dedicated, low-privilege test account. `allowed_hosts` is required
and prevents credentials from being sent to an origin that is not explicitly
permitted. Never use personal, production, or administrator sessions.

### Safety and Limitations

- Automated and AI-reviewed findings still require manual verification before
  submission.
- Regex and AI-only credential detections remain `manual-review`; pattern
  presence alone never proves that a credential is active or reportable.
- Discovered credentials are masked before AI, reports, and terminal output;
  replacement markers retain only the detector type, never secret characters.
- URL query values are removed from AI/report-safe URLs while parameter names
  are retained for analysis. Redaction is defense in depth, not a formal DLP
  guarantee: novel encodings, secrets embedded in paths or bodies, and unknown
  credential formats may evade pattern-based detection. Never put credentials
  in a target URL, and review report artifacts before sharing them.
- Validation decisions are separated into `confirmed`, `manual-review`, and
  `rejected`; only confirmed findings appear as reportable vulnerabilities.
- A partial scan or failed external tool is reported as incomplete; it does not
  mean the target is secure.
- Active scanners can generate substantial traffic. Set `rate_limit`, disable
  prohibited modules, and follow the program's rules.
- The guarded internal HTTP client blocks private and special-use destinations,
  but external scanners perform their own DNS resolution. Use a restrictive
  egress policy when scanning domains whose DNS you do not control; DNS changes
  or rebinding can otherwise invalidate the pre-scan address check.
- External scanner binaries are trusted local dependencies, not sandboxed
  plugins. The agent minimizes their environment, bounds output, and terminates
  their process groups, but a malicious binary may still read files available
  to the current OS user or deliberately detach. Run scans as a dedicated
  low-privilege user or container with a dedicated home directory, read-only
  inputs, and restrictive egress.
- Deterministic behavioral evals guard against known false-confirmation,
  post-model adversarial-output, scope, and grounding regressions, but they are
  not a claim of real-world precision/recall, zero hallucinations, or zero bias.
- The optional `hunter` is disabled by default. When enabled, it writes
  explicitly unverified attack hypotheses; even an "observed" lead means only
  that its path/parameter appeared in recon, not that a vulnerability exists.

### C99.nl API (Optional Subdomain Intelligence)

C99.nl can add another source of subdomain candidates. It is disabled by
default; HawkEye continues with its other enabled sources when C99 is not used.

**Get a key:** Register at [c99.nl](https://c99.nl) → Dashboard → API Key

Add it to `.env`:

```env
C99_API_KEY=your-api-key-here
```

Then explicitly opt in through `config.yaml`:

```yaml
c99:
  api_key: "${C99_API_KEY}"
  enabled: true
```

To disable C99 without removing the key:

```yaml
c99:
  enabled: false
```

---

### Blind XSS

Blind-XSS callbacks send requests from the tested application to an external
service. Configure one only when the program rules explicitly permit
out-of-band testing and you control or trust the callback service; otherwise
leave `blind_url` empty.

```yaml
scanning:
  tools:
    dalfox:
      blind_url: "https://your-burp-collaborator.com"
```

---

## Output

Reports are saved to `./reports/` in Markdown:

The report directory must be private. The installer creates it with mode
`0700`; for a manually created or custom output directory, run
`mkdir -p reports && chmod 700 reports` before scanning. HawkEye refuses a
pre-existing shared directory and never changes its permissions implicitly.

```
reports/
└── bug_bounty_report_2026-04-04_16-41-25.md
```

### Report Structure

```
Executive Summary
  └── Coverage grade · measured work · confirmed/manual/rejected counts

Submission Ready / Low Value
  └── Confirmed findings with captured evidence and confidence

Manual Review Required
  └── Candidates plus the exact missing evidence

Rejected / Not Reportable
  └── Candidate and rejection reason

Subdomain List
  └── In-scope discovered subdomains
```

---

## Troubleshooting

### Enabled tools are missing

HawkEye checks every enabled external tool before scanning and exits with the
installation command for anything missing. Run `./install.sh`, or disable the
unused tool in `config.yaml`.

### An optional recon or scanner tool times out

HawkEye continues with successful tools and marks the assessment as partial.
The final report lists failed optional tools so missing coverage is explicit.
Certificate Transparency requests use IPv4 to avoid hosts with broken IPv6
connectivity.

### Unknown field in config

This means the `hawkeye` binary is older than the accompanying `config.yaml`.
Download both from the same release archive, rebuild from the current source,
or verify compatibility with:

```bash
./hawkeye --check-config
```

### AI API key is required

Copy `.env.example` to `.env`, replace one AI-provider placeholder with a real
key, and run HawkEye from the repository directory. Do not commit `.env`;
it is intentionally ignored by Git.

### Develop and Test

```bash
# Run the test suite
go test ./...

# Run the deterministic behavior evaluation suite
go test ./evals/...

# Run static analysis
go vet ./...

# Build the CLI
go build -trimpath -o hawkeye ./cmd/main.go
```

See [CHANGELOG.md](CHANGELOG.md) for release changes and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

---

## Legal

> **HawkEye is for authorized security testing only.**  
> Only use this tool against systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> See [SECURITY.md](SECURITY.md) for the full responsible disclosure policy.

---

<p align="center">
  Built by <a href="https://x.com/A_cyb3r">@A_cyb3r</a> &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; v2.3.0
</p>
