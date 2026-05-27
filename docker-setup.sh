#!/bin/bash
# AutoPoV Docker Setup Script
# This script helps you set up Docker and run AutoPoV in containers

set -e

echo "=========================================="
echo "AutoPoV Docker Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed!"
    echo ""
    echo "To install Docker on Ubuntu/WSL:"
    echo "1. Update packages:"
    echo "   sudo apt-get update"
    echo ""
    echo "2. Install prerequisites:"
    echo "   sudo apt-get install -y ca-certificates curl gnupg"
    echo ""
    echo "3. Add Docker's official GPG key:"
    echo "   sudo install -m 0755 -d /etc/apt/keyrings"
    echo "   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
    echo "   sudo chmod a+r /etc/apt/keyrings/docker.gpg"
    echo ""
    echo "4. Add Docker repository:"
    echo '   echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null'
    echo ""
    echo "5. Install Docker:"
    echo "   sudo apt-get update"
    echo "   sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
    echo ""
    echo "6. Add your user to docker group (to run docker without sudo):"
    echo "   sudo usermod -aG docker $USER"
    echo "   newgrp docker"
    echo ""
    exit 1
else
    print_info "Docker is already installed ?"
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed!"
    echo "It should be installed with Docker. Please check your Docker installation."
    exit 1
else
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    print_info "Docker Compose is available ?"
fi

# Check if .env file exists
if [ ! -f .env ]; then
    print_warning ".env file not found!"
    echo "Creating .env from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        print_info ".env file created. Please edit it with your API keys."
    else
        print_error ".env.example not found! Cannot create .env file."
        exit 1
    fi
else
    print_info ".env file exists ?"
fi

# Check if OPENROUTER_API_KEY is set
if ! grep -q "OPENROUTER_API_KEY=" .env || grep -q "OPENROUTER_API_KEY=$" .env; then
    print_warning "OPENROUTER_API_KEY is not set in .env file!"
    echo "Please add your OpenRouter API key to the .env file:"
    echo "   OPENROUTER_API_KEY=sk-or-v1-your-key-here"
    echo ""
fi

echo ""
echo "=========================================="
echo "Docker Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Build and start the containers:"
echo "   $COMPOSE_CMD up --build"
echo ""
echo "2. Or run in detached mode (background):"
echo "   $COMPOSE_CMD up --build -d"
echo ""
echo "3. Access the applications:"
echo "   - Backend API: http://localhost:8000"
echo "   - Frontend UI: http://localhost:5173"
echo ""
echo "4. View logs:"
echo "   $COMPOSE_CMD logs -f"
echo ""
echo "5. Stop the containers:"
echo "   $COMPOSE_CMD down"
echo ""
echo "6. To run a scan using Docker:"
echo "   docker exec -it autopov-backend python -m cli.autopov scan <repo-url> --api-key <your-key>"
echo ""
