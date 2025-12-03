#!/usr/bin/env bash

echo "[*] Checking if Go is installed..."
if ! command -v go >/dev/null 2>&1; then
    echo "[!] Go not found. Installing..."
    sudo apt install golang -y
else
    echo "[*] Go is already installed."
fi

# Detect shell
if [ "$SHELL" = "/bin/zsh" ]; then
    RC_FILE="$HOME/.zshrc"
elif [ "$SHELL" = "/bin/bash" ]; then
    RC_FILE="$HOME/.bashrc"
else
    # fallback
    RC_FILE="$HOME/.bashrc"
fi

echo "[*] Updating PATH and GOPATH in $RC_FILE"

# Add Go path only if not already present
grep -qxF 'export GOPATH=$HOME/go' "$RC_FILE" || echo 'export GOPATH=$HOME/go' >> "$RC_FILE"
grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' "$RC_FILE" || echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> "$RC_FILE"
echo "[*] Sourcing $RC_FILE"
source "$RC_FILE"
chmod +x jscan
sudo cp jscan /usr/local/bin/

echo "[*] Installing katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "[*] Building Spidey..."
go build -o spidey spidey.go

echo "[*] Moving spidey binary to /usr/local/bin..."
sudo mv spidey /usr/local/bin/
sudo chmod +x /usr/local/bin/spidey

echo "[✔] Installation complete! Spidey is now available system-wide."

