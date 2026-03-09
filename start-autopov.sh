#!/bin/bash
# Start AutoPoV - Backend in Docker, Frontend locally

set -e

echo "=========================================="
echo "Starting AutoPoV"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if .env exists and has API key
if [ ! -f .env ]; then
    print_error ".env file not found!"
    echo "Please create .env file with your OPENROUTER_API_KEY"
    exit 1
fi

if ! grep -q "OPENROUTER_API_KEY=sk-" .env; then
    print_error "OPENROUTER_API_KEY not found in .env!"
    echo "Please add your OpenRouter API key to .env:"
    echo "  OPENROUTER_API_KEY=sk-or-v1-your-key-here"
    exit 1
fi

# Step 1: Build and start Backend in Docker
print_info "Step 1: Building and starting Backend in Docker..."
docker-compose up --build -d backend

# Step 2: Wait for backend to be ready
print_info "Step 2: Waiting for backend to start..."
for i in {1..60}; do
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        print_info "Backend is ready!"
        break
    fi
    echo -n "."
    sleep 1
    if [ $i -eq 60 ]; then
        print_error "Backend failed to start within 60 seconds"
        echo "Check logs with: docker-compose logs backend"
        exit 1
    fi
done

# Step 3: Install frontend dependencies if needed
cd frontend
if [ ! -d "node_modules" ]; then
    print_info "Step 3: Installing frontend dependencies..."
    npm install
else
    print_info "Step 3: Frontend dependencies already installed"
fi

# Step 4: Start Frontend
print_info "Step 4: Starting Frontend..."
echo ""
print_info "=========================================="
print_info "AutoPoV is running!"
print_info "=========================================="
print_info "Backend API:  http://localhost:8000"
print_info "Frontend UI:  http://localhost:5173"
print_info "API Docs:     http://localhost:8000/docs"
print_info "=========================================="
echo ""
print_info "Press Ctrl+C to stop the frontend"
echo ""

npm run dev -- --host
