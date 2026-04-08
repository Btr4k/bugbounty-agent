#!/usr/bin/env bash
# ============================================================
# HawkEye v2.1 — Dependency Installer
# Tested on: Ubuntu 20.04+, Debian 11+, Kali Linux
# Usage: chmod +x install.sh && ./install.sh
# ============================================================

set -e

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
echo -e "                  Dependency Installer v2.1${RESET}"
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
    success "Go found"
}

# ─── Install Go tools ────────────────────────────────────────
install_go_tools() {
    info "Installing Go-based security tools..."

    declare -A GO_TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    )

    for tool in "${!GO_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            success "$tool already installed"
        else
            info "Installing $tool..."
            go install "${GO_TOOLS[$tool]}" 2>/dev/null && success "$tool installed" || warn "$tool failed to install"
        fi
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

# ─── Install Python tools ────────────────────────────────────
install_python_tools() {
    info "Installing Python tools (arjun)..."

    if command -v pip3 &>/dev/null; then
        pip3 install arjun -q 2>/dev/null && success "arjun installed" || warn "arjun failed"
    else
        warn "pip3 not found — install Python3 then: pip3 install arjun"
    fi
}

# ─── Download nuclei templates ───────────────────────────────
setup_nuclei() {
    if command -v nuclei &>/dev/null; then
        info "Updating nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null && success "Nuclei templates updated" || warn "Template update failed"
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
        warn "Created .env from template — edit it and add your API keys:"
        warn "  nano .env"
    else
        success ".env already exists"
    fi
}

# ─── Run ─────────────────────────────────────────────────────
check_go
install_system_tools
install_go_tools
install_python_tools
setup_nuclei
build_hawkeye
setup_env

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✅ Installation complete!${RESET}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Next steps:"
echo -e "  1. Edit ${CYAN}.env${RESET} and add your AI API key"
echo -e "  2. Run: ${CYAN}./hawkeye --target example.com --verbose${RESET}"
echo ""
echo -e "  Docs: ${CYAN}https://github.com/Btr4k/bugbounty-agent${RESET}"
echo ""
