#!/usr/bin/env bash
# ============================================================
# HawkEye v2.3.0 — Reproducible Dependency Installer
# Tested on: Ubuntu 20.04+, Debian 11+, Kali Linux
# Usage: chmod +x install.sh && ./install.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗███████╗"
echo "  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝"
echo "  ███████║███████║██║ █╗ ██║█████╔╝ █████╗   ╚████╔╝ █████╗  "
echo "  ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝  "
echo "  ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗███████╗   ██║   ███████╗"
echo "  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝"
echo -e "                 Dependency Installer v2.3.0${RESET}"
echo ""

# ─── Check OS ────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    warn "Not running as root — some installs may need sudo"
fi

OS=$(uname -s)
if [[ "$OS" != "Linux" ]]; then
    error "This installer supports Linux only"
fi

# ─── Check Go ────────────────────────────────────────────────
check_go() {
    if ! command -v go &>/dev/null; then
        error "Go is not installed. Install from: https://go.dev/dl/"
    fi
    GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go version: $GO_VER"
    if [[ "$(printf '%s\n' "1.25.0" "$GO_VER" | sort -V | head -n1)" != "1.25.0" ]]; then
        error "Go 1.25 or later is required. Install it from: https://go.dev/dl/"
    fi
    success "Go found"
}

# ─── Install Go tools ────────────────────────────────────────
install_go_tools() {
    info "Installing Go-based security tools..."

    # Versions are intentionally pinned. Upgrade them in a reviewed change so
    # two HawkEye installations run the same scanner code.
    declare -A GO_TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.12.0"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.0"
        ["dalfox"]="github.com/hahwul/dalfox/v2@v2.12.0"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@v0.1.1"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@v0.1.0"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@v1.4.0"
    )

    for tool in "${!GO_TOOLS[@]}"; do
        info "Installing pinned $tool..."
        go install "${GO_TOOLS[$tool]}" || error "$tool failed to install"
    done
}

# ─── Install system tools ────────────────────────────────────
install_system_tools() {
    info "Installing system tools (nmap)..."

    if command -v apt-get &>/dev/null; then
        apt-get install -y -q nmap 2>/dev/null && success "nmap installed" || warn "nmap failed"
    elif command -v yum &>/dev/null; then
        yum install -y -q nmap 2>/dev/null && success "nmap installed" || warn "nmap failed"
    else
        warn "Package manager not found — install nmap manually"
    fi
}

# ─── Download nuclei templates ───────────────────────────────
setup_nuclei() {
    if [[ "${HAWKEYE_UPDATE_TEMPLATES:-0}" == "1" ]] && command -v nuclei &>/dev/null; then
        info "Updating nuclei templates..."
        nuclei -update-templates -silent && success "Nuclei templates updated" || error "Template update failed"
    else
        info "Skipping mutable Nuclei template update (set HAWKEYE_UPDATE_TEMPLATES=1 to opt in)"
    fi
}

# ─── Build HawkEye ───────────────────────────────────────────
build_hawkeye() {
    info "Building HawkEye..."
    go build -o hawkeye ./cmd/main.go && success "HawkEye built successfully: ./hawkeye" || error "Build failed"
}

# ─── Setup .env ──────────────────────────────────────────────
setup_env() {
    if [[ ! -f ".env" ]]; then
        cp .env.example .env
        chmod 600 .env
        warn "Created .env from template — edit it and add your API keys:"
        warn "  nano .env"
    else
        chmod 600 .env
        success "Restricted existing .env permissions to 0600"
        success ".env already exists"
    fi
}

# ─── Setup private report directory ─────────────────────────
setup_reports() {
    if [[ -L "reports" ]] || [[ -e "reports" && ! -d "reports" ]]; then
        error "reports must be a real directory, not a symlink or file"
    fi
    mkdir -p reports
    chmod 700 reports
    success "Report directory permissions set to 0700"
}

# ─── Run ─────────────────────────────────────────────────────
check_go
hawkeye_tool_bin="${GOBIN:-$(go env GOPATH)/bin}"
export PATH="$hawkeye_tool_bin:$HOME/.local/bin:$PATH"
install_system_tools
install_go_tools
setup_nuclei
build_hawkeye
setup_env
setup_reports

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✅ Installation complete!${RESET}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Next steps:"
echo -e "  1. Edit ${CYAN}.env${RESET} and add your AI API key"
echo -e "  2. Exact-host safe default: ${CYAN}./hawkeye --target your-authorized-host.example --verbose${RESET}"
echo -e "     Authorized apex + subdomains: ${CYAN}./hawkeye --target your-authorized-host.example --include-subdomains --verbose${RESET}"
echo ""
echo -e "  Docs: ${CYAN}https://github.com/Btr4k/bugbounty-agent${RESET}"
echo ""
