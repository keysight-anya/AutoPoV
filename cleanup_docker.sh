#!/bin/bash
#
# AutoPoV Docker Cleanup Script
# Comprehensive cleanup of Docker resources
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run docker commands safely
run_docker_cmd() {
    local cmd="$1"
    local description="$2"
    
    print_info "$description..."
    if eval "$cmd" 2>/dev/null; then
        print_info "✓ Success"
        return 0
    else
        print_warn "✗ Failed or nothing to clean"
        return 1
    fi
}

# Show current usage
show_usage() {
    echo ""
    echo "============================================================"
    echo "CURRENT DOCKER DISK USAGE"
    echo "============================================================"
    docker system df
    echo "============================================================"
}

# Show Docker info
show_info() {
    echo ""
    echo "============================================================"
    echo "DOCKER INFO"
    echo "============================================================"
    docker info --format "Docker Version: {{.ServerVersion}}" 2>/dev/null || echo "Docker: Not running"
    echo ""
    echo "Running Containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Size}}" 2>/dev/null || echo "  None"
    echo ""
    echo "Images:"
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null || echo "  None"
    echo "============================================================"
}

# Cleanup functions
cleanup_autopov_containers() {
    print_info "Stopping AutoPoV containers..."
    docker ps -aq --filter "name=autopov" 2>/dev/null | xargs -r docker stop 2>/dev/null || true
    
    print_info "Removing AutoPoV containers..."
    docker ps -aq --filter "name=autopov" 2>/dev/null | xargs -r docker rm -f 2>/dev/null || true
}

cleanup_all_containers() {
    print_info "Removing all stopped containers..."
    docker container prune -f
}

cleanup_autopov_images() {
    print_info "Removing AutoPoV images..."
    docker images -q --filter "reference=*autopov*" 2>/dev/null | xargs -r docker rmi -f 2>/dev/null || true
}

cleanup_dangling_images() {
    print_info "Removing dangling images..."
    docker image prune -f
}

cleanup_all_unused_images() {
    print_info "Removing ALL unused images..."
    docker image prune -a -f
}

cleanup_autopov_volumes() {
    print_info "Removing AutoPoV volumes..."
    docker volume ls -q --filter "name=autopov" 2>/dev/null | xargs -r docker volume rm 2>/dev/null || true
}

cleanup_dangling_volumes() {
    print_info "Removing dangling volumes..."
    docker volume prune -f
}

cleanup_build_cache() {
    print_info "Removing build cache..."
    docker builder prune -f
}

cleanup_all_build_cache() {
    print_info "Removing ALL build cache..."
    docker builder prune -a -f
}

cleanup_networks() {
    print_info "Removing unused networks..."
    docker network prune -f
}

system_prune() {
    print_info "Running docker system prune..."
    docker system prune -f
}

system_prune_all() {
    print_info "Running COMPLETE docker system prune..."
    docker system prune -a -f --volumes
}

# Help function
show_help() {
    cat << EOF
AutoPoV Docker Cleanup Script

Usage: $0 [OPTION]

Options:
    -a, --all       Aggressive cleanup - removes everything including unused images
    -A, --autopov   Clean only AutoPoV-related resources
    -s, --safe      Safe cleanup - only removes stopped containers, dangling images/volumes
    -S, --show      Show current Docker usage without cleaning
    -f, --force     Skip confirmation prompt
    -h, --help      Show this help message

Examples:
    $0 --all        # Complete cleanup (aggressive)
    $0 --autopov    # Clean only AutoPoV resources
    $0 --safe       # Safe cleanup (default)
    $0 --show       # Show usage only

EOF
}

# Main function
main() {
    local mode="safe"
    local force=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--all)
                mode="all"
                shift
                ;;
            -A|--autopov)
                mode="autopov"
                shift
                ;;
            -s|--safe)
                mode="safe"
                shift
                ;;
            -S|--show)
                mode="show"
                shift
                ;;
            -f|--force)
                force=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running or not installed"
        exit 1
    fi
    
    # Show current usage
    show_usage
    
    # If show mode, exit after showing
    if [ "$mode" = "show" ]; then
        show_info
        exit 0
    fi
    
    # Confirmation prompt
    if [ "$force" = false ]; then
        echo ""
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        
        case $mode in
            all)
                echo "WARNING: This will remove ALL unused Docker data:"
                echo "  - All stopped containers"
                echo "  - All unused images (not just dangling)"
                echo "  - All unused volumes"
                echo "  - All build cache"
                echo "  - All unused networks"
                ;;
            autopov)
                echo "This will remove AutoPoV-related Docker resources:"
                echo "  - All AutoPoV containers"
                echo "  - All AutoPoV images"
                echo "  - All AutoPoV volumes"
                ;;
            safe)
                echo "This will remove unused Docker resources:"
                echo "  - All stopped containers"
                echo "  - Dangling images"
                echo "  - Dangling volumes"
                echo "  - Build cache"
                echo "  - Unused networks"
                ;;
        esac
        
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo ""
        read -p "Are you sure? [y/N]: " response
        
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_info "Cancelled."
            exit 0
        fi
    fi
    
    echo ""
    echo "============================================================"
    echo "STARTING CLEANUP"
    echo "============================================================"
    
    case $mode in
        all)
            cleanup_autopov_containers
            cleanup_all_containers
            cleanup_autopov_images
            cleanup_all_unused_images
            cleanup_autopov_volumes
            cleanup_dangling_volumes
            cleanup_all_build_cache
            cleanup_networks
            system_prune_all
            ;;
        autopov)
            cleanup_autopov_containers
            cleanup_autopov_images
            cleanup_autopov_volumes
            ;;
        safe)
            cleanup_autopov_containers
            cleanup_all_containers
            cleanup_dangling_images
            cleanup_dangling_volumes
            cleanup_build_cache
            cleanup_networks
            system_prune
            ;;
    esac
    
    echo ""
    echo "============================================================"
    echo "CLEANUP COMPLETE"
    echo "============================================================"
    
    # Show usage after cleanup
    show_usage
}

# Run main function
main "$@"
