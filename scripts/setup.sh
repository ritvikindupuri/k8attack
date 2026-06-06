#!/bin/bash
set -e

echo "=== K8s Attack Platform Setup ==="
echo ""

# Check prerequisites
echo "[1/5] Checking prerequisites..."
for cmd in python3 node npm kind kubectl docker; do
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
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
        chmod +x ./kind
        sudo mv ./kind /usr/local/bin/kind
    fi
    echo "  ✓ kind installed"
fi

# Backend setup
echo ""
echo "[2/5] Setting up Python backend..."
cd "$(dirname "$0")/../backend"
python3 -m venv venv 2>/dev/null || python3 -m venv venv --without-pip
source venv/bin/activate 2>/dev/null || source venv/bin/activate
pip install --quiet --upgrade pip 2>/dev/null || true
pip install --quiet -r requirements.txt
echo "  ✓ Backend dependencies installed"

# Frontend setup
echo ""
echo "[3/5] Setting up frontend..."
cd "$(dirname "$0")/../frontend"
npm install --silent 2>&1 | tail -1
echo "  ✓ Frontend dependencies installed"

echo ""
echo "[4/5] Setup complete!"
echo ""
echo "To start the platform:"
echo ""
echo "  Terminal 1 (Backend - with AI remediation):"
echo "    cd backend && source venv/bin/activate && ANTHROPIC_API_KEY=\"sk-ant-...\" python main.py"
echo ""
echo "  Terminal 1 (Backend - without AI remediation):"
echo "    cd backend && source venv/bin/activate && python main.py"
echo ""
echo "  Terminal 2 (Frontend):"
echo "    cd frontend && npm run dev"
echo ""
echo "  Then open http://localhost:3000"
echo ""
echo "[5/5] Then open http://localhost:3000 in your browser"
