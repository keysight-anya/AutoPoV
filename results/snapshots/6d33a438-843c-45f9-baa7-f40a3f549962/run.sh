#!/bin/bash

# AutoPoV Startup Script
# Usage: ./run.sh [backend|frontend|both]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Python installation
check_python() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_status "Python version: $PYTHON_VERSION"
    else
        print_error "Python 3 is not installed"
        exit 1
    fi
}

# Check Node.js installation
check_node() {
    if command_exists node; then
        NODE_VERSION=$(node --version)
        print_status "Node.js version: $NODE_VERSION"
    else
        print_error "Node.js is not installed"
        exit 1
    fi
}

# Setup virtual environment
setup_venv() {
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    print_status "Activating virtual environment..."
    source venv/bin/activate
    
    # Install dependencies
    if [ ! -f "venv/.installed" ] || [ "requirements.txt" -nt "venv/.installed" ]; then
        print_status "Installing Python dependencies..."
        pip install --upgrade pip
        pip install -r requirements.txt
        touch venv/.installed
    fi
}

# Start backend
start_backend() {
    print_status "Starting AutoPoV Backend..."
    
    check_python
    setup_venv
    
    # Check if .env exists
    if [ ! -f ".env" ]; then
        print_warning ".env file not found. Copying from .env.example..."
        cp .env.example .env
        print_warning "Please edit .env and add your API keys before running again."
        exit 1
    fi
    
    # Create necessary directories
    mkdir -p data results/povs results/runs
    
    print_status "Starting FastAPI server on http://localhost:8000"
    print_status "API documentation: http://localhost:8000/api/docs"
    
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
}

# Start frontend
start_frontend() {
    print_status "Starting AutoPoV Frontend..."
    
    check_node
    
    cd frontend
    
    # Install dependencies
    if [ ! -d "node_modules" ]; then
        print_status "Installing Node.js dependencies..."
        npm install
    fi
    
    print_status "Starting Vite dev server on http://localhost:5173"
    
    npm run dev
}

# Start both
start_both() {
    print_status "Starting AutoPoV Backend and Frontend..."
    
    # Start backend in background
    check_python
    setup_venv
    
    if [ ! -f ".env" ]; then
        print_warning ".env file not found. Copying from .env.example..."
        cp .env.example .env
        print_warning "Please edit .env and add your API keys before running again."
        exit 1
    fi
    
    mkdir -p data results/povs results/runs
    
    print_status "Starting FastAPI server on http://localhost:8000"
    uvicorn app.main:app --host 0.0.0.0 --port 8000 &
    BACKEND_PID=$!
    
    # Wait for backend to start
    sleep 3
    
    # Start frontend
    cd frontend
    
    if [ ! -d "node_modules" ]; then
        print_status "Installing Node.js dependencies..."
        npm install
    fi
    
    print_status "Starting Vite dev server on http://localhost:5173"
    npm run dev &
    FRONTEND_PID=$!
    
    # Trap to kill both processes on exit
    trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM EXIT
    
    # Wait for both
    wait
}

# Show help
show_help() {
    cat << EOF
AutoPoV Startup Script

Usage: ./run.sh [COMMAND]

Commands:
    backend     Start only the FastAPI backend
    frontend    Start only the React frontend
    both        Start both backend and frontend (default)
    test        Run the test suite
    help        Show this help message

Examples:
    ./run.sh backend      # Start just the API server
    ./run.sh frontend     # Start just the web UI
    ./run.sh both         # Start both services
    ./run.sh test         # Run tests

Environment:
    Make sure to create a .env file with your API keys:
    cp .env.example .env
    
    Required for online mode:
    - OPENROUTER_API_KEY
    
    Required for admin operations:
    - ADMIN_API_KEY

EOF
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    check_python
    setup_venv
    
    pytest tests/ -v
}

# Main
main() {
    case "${1:-both}" in
        backend)
            start_backend
            ;;
        frontend)
            start_frontend
            ;;
        both)
            start_both
            ;;
        test)
            run_tests
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
