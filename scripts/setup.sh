#!/bin/bash
set -e

echo "=== KARMA — Kubernetes Attack & Remediation Mapping Agent ==="
echo ""

# Check prerequisites
echo "[1/3] Checking prerequisites..."
for cmd in python3 kind kubectl docker; do
    if ! which $cmd &>/dev/null; then
        echo "  WARNING: $cmd not found"
    else
        echo "  ✓ $cmd found: $($cmd --version 2>&1 | head -1)"
    fi
done

# Install kind if missing
if ! which kind &>/dev/null; then
    echo ""
    echo "Installing kind..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install kind
    else
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.32.0/kind-linux-amd64
        chmod +x ./kind
        sudo mv ./kind /usr/local/bin/kind
    fi
    echo "  ✓ kind installed"
fi

# Install kubectl if missing
if ! which kubectl &>/dev/null; then
    echo ""
    echo "Installing kubectl..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install kubectl
    else
        curl -LO "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
        chmod +x ./kubectl
        sudo mv ./kubectl /usr/local/bin/kubectl
    fi
    echo "  ✓ kubectl installed"
fi

# Backend setup
echo ""
echo "[2/3] Setting up Python backend..."
cd "$(dirname "$0")/../backend"
python3 -m venv venv 2>/dev/null || python3 -m venv venv --without-pip
source venv/bin/activate 2>/dev/null || source venv/bin/activate
pip install --quiet --upgrade pip 2>/dev/null || true
pip install --quiet -r requirements.txt
echo "  ✓ Backend dependencies installed"

echo ""
echo "[3/3] Setup complete!"
echo ""
echo "To run KARMA:"
echo ""
echo "  python3 cli.py"
echo ""
echo "For auto-remediation (optional), set your Anthropic API key:"
echo ""
echo "  export ANTHROPIC_API_KEY=\"sk-ant-...\""
echo "  python3 cli.py"
echo ""
