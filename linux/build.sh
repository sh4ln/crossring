#!/bin/bash
# CROSSRING Linux Build Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== CROSSRING Linux Build ===${NC}"

# Check dependencies
check_deps() {
    echo "Checking dependencies..."
    
    DEPS="cmake g++ pkg-config libsqlite3-dev"
    
    for dep in $DEPS; do
        if ! dpkg -l | grep -q $dep; then
            echo -e "${RED}Missing: $dep${NC}"
            echo "Install with: sudo apt install $dep"
            exit 1
        fi
    done
    
    # Optional: libbpf for eBPF support
    if dpkg -l | grep -q libbpf-dev; then
        echo -e "${GREEN}eBPF support available${NC}"
        USE_EBPF="ON"
    else
        echo -e "${YELLOW}eBPF not available, using audit fallback${NC}"
        USE_EBPF="OFF"
    fi
    
    # Optional: GTK4 for GUI
    if dpkg -l | grep -q libgtk-4-dev; then
        echo -e "${GREEN}GTK4 GUI available${NC}"
        BUILD_GUI="ON"
    else
        echo -e "${YELLOW}GTK4 not available, skipping GUI${NC}"
        BUILD_GUI="OFF"
    fi
}

# Build
build() {
    mkdir -p build
    cd build
    
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DUSE_EBPF=$USE_EBPF \
        -DBUILD_GUI=$BUILD_GUI
    
    make -j$(nproc)
    
    echo -e "${GREEN}Build complete!${NC}"
}

# Install
install() {
    echo "Installing CROSSRING..."
    
    sudo make install
    
    # Create directories
    sudo mkdir -p /var/lib/crossring
    sudo mkdir -p /etc/crossring
    sudo mkdir -p /etc/apparmor.d/crossring
    
    # Enable service
    sudo systemctl daemon-reload
    sudo systemctl enable crossring
    
    echo -e "${GREEN}Installation complete!${NC}"
    echo "Start with: sudo systemctl start crossring"
}

# Package
package() {
    echo "Creating packages..."
    cpack -G DEB
    cpack -G RPM
    echo -e "${GREEN}Packages created in build/!${NC}"
}

# Main
case "${1:-build}" in
    deps)
        check_deps
        ;;
    build)
        check_deps
        build
        ;;
    install)
        install
        ;;
    package)
        package
        ;;
    all)
        check_deps
        build
        install
        ;;
    *)
        echo "Usage: $0 {deps|build|install|package|all}"
        exit 1
        ;;
esac
