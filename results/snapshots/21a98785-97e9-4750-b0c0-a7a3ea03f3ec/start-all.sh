#!/bin/bash
# Start AutoPoV Backend (Docker) and Frontend (Local)

set -e

echo "=========================================="
echo "Starting AutoPoV with Docker Backend"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if .env exists
if [ ! -f .env ]; then
    print_warning ".env file not found! Creating from .env.example..."
    cp .env.example .env
    echo "Please edit .env and add your OPENROUTER_API_KEY"
    exit 1
fi

# Start Backend in Docker
print_info "Starting Backend in Docker..."
docker-compose up -d backend

# Wait for backend to be ready
print_info "Waiting for backend to start..."
for i in {1..30}; do
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        print_info "Backend is ready!"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        print_warning "Backend may not be ready yet. Check logs with: docker-compose logs backend"
    fi
done

# Start Frontend locally
cd frontend
if [ ! -d "node_modules" ]; then
    print_info "Installing frontend dependencies..."
    npm install
fi

print_info "Starting Frontend..."
print_info "Backend: http://localhost:8000"
print_info "Frontend: http://localhost:5173"
print_info "API Docs: http://localhost:8000/docs"
echo ""
print_info "Press Ctrl+C to stop the frontend"
npm run dev -- --host
