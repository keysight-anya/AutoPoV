#!/usr/bin/env python3
"""
AutoPoV Docker Cleanup Script
Comprehensive cleanup of Docker resources used by AutoPoV
"""

import subprocess
import sys
import argparse
from typing import List, Tuple


def run_command(cmd: List[str], description: str) -> Tuple[bool, str]:
    """Run a shell command and return success status and output"""
    print(f"\n[+] {description}...")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            if output:
                print(f"    {output}")
            print(f"    ✓ Success")
            return True, output
        else:
            error = result.stderr.strip() if result.stderr else "Unknown error"
            print(f"    ✗ Failed: {error}")
            return False, error
    except subprocess.TimeoutExpired:
        print(f"    ✗ Timeout")
        return False, "Timeout"
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return False, str(e)


def cleanup_autopov_containers() -> bool:
    """Stop and remove all AutoPoV-related containers"""
    # Stop containers with autopov in the name
    run_command(
        ["docker", "ps", "-aq", "--filter", "name=autopov"],
        "Finding AutoPoV containers"
    )
    
    success, _ = run_command(
        ["docker", "stop", "$(docker", "ps", "-aq", "--filter", "name=autopov)", "2>/dev/null"],
        "Stopping AutoPoV containers"
    )
    
    success, _ = run_command(
        ["docker", "rm", "-f", "$(docker", "ps", "-aq", "--filter", "name=autopov)", "2>/dev/null"],
        "Removing AutoPoV containers"
    )
    
    return True


def cleanup_all_stopped_containers() -> bool:
    """Remove all stopped containers"""
    success, output = run_command(
        ["docker", "container", "prune", "-f"],
        "Removing all stopped containers"
    )
    return success


def cleanup_autopov_images() -> bool:
    """Remove AutoPoV Docker images"""
    # Remove images with autopov in the name
    run_command(
        ["docker", "images", "-q", "--filter", "reference=*autopov*"],
        "Finding AutoPoV images"
    )
    
    success, _ = run_command(
        ["bash", "-c", "docker rmi -f $(docker images -q --filter reference=*autopov*) 2>/dev/null || true"],
        "Removing AutoPoV images"
    )
    
    return True


def cleanup_dangling_images() -> bool:
    """Remove dangling (untagged) images"""
    success, output = run_command(
        ["docker", "image", "prune", "-f"],
        "Removing dangling images"
    )
    return success


def cleanup_all_unused_images() -> bool:
    """Remove all unused images (not just dangling)"""
    success, output = run_command(
        ["docker", "image", "prune", "-a", "-f"],
        "Removing all unused images"
    )
    return success


def cleanup_autopov_volumes() -> bool:
    """Remove AutoPoV volumes"""
    run_command(
        ["docker", "volume", "ls", "-q", "--filter", "name=autopov"],
        "Finding AutoPoV volumes"
    )
    
    success, _ = run_command(
        ["bash", "-c", "docker volume rm $(docker volume ls -q --filter name=autopov) 2>/dev/null || true"],
        "Removing AutoPoV volumes"
    )
    
    return True


def cleanup_dangling_volumes() -> bool:
    """Remove dangling volumes"""
    success, output = run_command(
        ["docker", "volume", "prune", "-f"],
        "Removing dangling volumes"
    )
    return success


def cleanup_build_cache() -> bool:
    """Remove Docker build cache"""
    success, output = run_command(
        ["docker", "builder", "prune", "-f"],
        "Removing build cache"
    )
    return success


def cleanup_all_build_cache() -> bool:
    """Remove all build cache (including used)"""
    success, output = run_command(
        ["docker", "builder", "prune", "-a", "-f"],
        "Removing all build cache"
    )
    return success


def cleanup_networks() -> bool:
    """Remove unused networks"""
    success, output = run_command(
        ["docker", "network", "prune", "-f"],
        "Removing unused networks"
    )
    return success


def system_prune() -> bool:
    """Complete system prune (containers, networks, images, build cache)"""
    success, output = run_command(
        ["docker", "system", "prune", "-f"],
        "Running docker system prune"
    )
    return success


def system_prune_all() -> bool:
    """Complete system prune including unused images"""
    success, output = run_command(
        ["docker", "system", "prune", "-a", "-f", "--volumes"],
        "Running complete docker system prune (includes unused images and volumes)"
    )
    return success


def show_docker_usage():
    """Show current Docker disk usage"""
    print("\n" + "="*60)
    print("CURRENT DOCKER DISK USAGE")
    print("="*60)
    run_command(["docker", "system", "df"], "Docker disk usage")
    print("="*60)


def show_docker_info():
    """Show Docker info"""
    print("\n" + "="*60)
    print("DOCKER INFO")
    print("="*60)
    run_command(["docker", "info", "--format", "{{.Name}}: {{.ServerVersion}}"], "Docker version")
    run_command(["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Size}}"], "Running containers")
    run_command(["docker", "images", "--format", "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"], "Images")
    print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="AutoPoV Docker Cleanup - Comprehensive cleanup of Docker resources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cleanup_docker.py --all          # Complete cleanup (aggressive)
  python cleanup_docker.py --autopov      # Clean only AutoPoV resources
  python cleanup_docker.py --safe         # Safe cleanup (keeps used images)
  python cleanup_docker.py --show         # Show current usage only
        """
    )
    
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Aggressive cleanup - removes everything including unused images and build cache"
    )
    
    parser.add_argument(
        "--autopov", "-A",
        action="store_true",
        help="Clean only AutoPoV-related resources (containers, images, volumes)"
    )
    
    parser.add_argument(
        "--safe", "-s",
        action="store_true",
        help="Safe cleanup - only removes stopped containers, dangling images/volumes, and build cache"
    )
    
    parser.add_argument(
        "--show", "-S",
        action="store_true",
        help="Show current Docker usage without cleaning"
    )
    
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Skip confirmation prompt"
    )
    
    args = parser.parse_args()
    
    # Default to safe if no option specified
    if not any([args.all, args.autopov, args.safe, args.show]):
        args.safe = True
    
    # Show current usage
    show_docker_usage()
    
    if args.show:
        show_docker_info()
        return
    
    # Confirmation prompt
    if not args.force:
        print("\n" + "!"*60)
        if args.all:
            print("WARNING: This will remove ALL unused Docker data including:")
            print("  - All stopped containers")
            print("  - All unused images (not just dangling)")
            print("  - All unused volumes")
            print("  - All build cache")
            print("  - All unused networks")
        elif args.autopov:
            print("This will remove AutoPoV-related Docker resources:")
            print("  - All AutoPoV containers")
            print("  - All AutoPoV images")
            print("  - All AutoPoV volumes")
        else:
            print("This will remove unused Docker resources:")
            print("  - All stopped containers")
            print("  - Dangling images")
            print("  - Dangling volumes")
            print("  - Build cache")
            print("  - Unused networks")
        print("!"*60)
        
        response = input("\nAre you sure? [y/N]: ")
        if response.lower() not in ['y', 'yes']:
            print("Cancelled.")
            sys.exit(0)
    
    print("\n" + "="*60)
    print("STARTING CLEANUP")
    print("="*60)
    
    if args.all:
        # Aggressive cleanup
        cleanup_autopov_containers()
        cleanup_all_stopped_containers()
        cleanup_autopov_images()
        cleanup_all_unused_images()
        cleanup_autopov_volumes()
        cleanup_dangling_volumes()
        cleanup_all_build_cache()
        cleanup_networks()
        system_prune_all()
    
    elif args.autopov:
        # AutoPoV-specific cleanup
        cleanup_autopov_containers()
        cleanup_autopov_images()
        cleanup_autopov_volumes()
    
    else:
        # Safe cleanup
        cleanup_autopov_containers()
        cleanup_all_stopped_containers()
        cleanup_dangling_images()
        cleanup_dangling_volumes()
        cleanup_build_cache()
        cleanup_networks()
        system_prune()
    
    print("\n" + "="*60)
    print("CLEANUP COMPLETE")
    print("="*60)
    
    # Show usage after cleanup
    show_docker_usage()


if __name__ == "__main__":
    main()
