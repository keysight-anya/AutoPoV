#!/usr/bin/env python3
"""
AutoPoV ChromaDB Weekly Cleanup Script
Clears out old vector data to prevent disk space issues
"""

import os
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path


def get_chroma_path() -> str:
    """Get ChromaDB persistence path from environment or default"""
    return os.getenv("CHROMA_PERSIST_DIR", "./data/chroma")


def cleanup_chromadb(older_than_days: int = 7, dry_run: bool = False) -> dict:
    """
    Clean up ChromaDB data older than specified days
    
    Args:
        older_than_days: Remove data older than this many days
        dry_run: If True, only show what would be deleted
    
    Returns:
        Dict with cleanup statistics
    """
    chroma_path = Path(get_chroma_path())
    
    if not chroma_path.exists():
        print(f"ChromaDB path does not exist: {chroma_path}")
        return {"deleted": 0, "errors": 0, "space_freed_mb": 0}
    
    cutoff_date = datetime.now() - timedelta(days=older_than_days)
    stats = {"deleted": 0, "errors": 0, "space_freed_mb": 0}
    
    print(f"Cleaning up ChromaDB data older than {older_than_days} days")
    print(f"Cutoff date: {cutoff_date.isoformat()}")
    print(f"Path: {chroma_path}")
    print("-" * 60)
    
    # Get all files in chroma directory
    for item in chroma_path.rglob("*"):
        if item.is_file():
            try:
                # Get file modification time
                mtime = datetime.fromtimestamp(item.stat().st_mtime)
                size_mb = item.stat().st_size / (1024 * 1024)
                
                if mtime < cutoff_date:
                    print(f"{'[DRY RUN] ' if dry_run else ''}Deleting: {item.relative_to(chroma_path)} ({size_mb:.2f} MB, modified: {mtime.isoformat()})")
                    
                    if not dry_run:
                        item.unlink()
                    
                    stats["deleted"] += 1
                    stats["space_freed_mb"] += size_mb
                    
            except Exception as e:
                print(f"Error processing {item}: {e}")
                stats["errors"] += 1
    
    # Remove empty directories
    if not dry_run:
        for item in sorted(chroma_path.rglob("*"), reverse=True):
            if item.is_dir() and not any(item.iterdir()):
                try:
                    item.rmdir()
                    print(f"Removed empty directory: {item.relative_to(chroma_path)}")
                except Exception:
                    pass
    
    print("-" * 60)
    print(f"Cleanup complete:")
    print(f"  Files {'would be ' if dry_run else ''}deleted: {stats['deleted']}")
    print(f"  Space {'would be ' if dry_run else ''}freed: {stats['space_freed_mb']:.2f} MB")
    print(f"  Errors: {stats['errors']}")
    
    return stats


def reset_chromadb(dry_run: bool = False) -> dict:
    """
    Completely reset ChromaDB - delete all data
    
    Args:
        dry_run: If True, only show what would be deleted
    
    Returns:
        Dict with reset statistics
    """
    chroma_path = Path(get_chroma_path())
    
    if not chroma_path.exists():
        print(f"ChromaDB path does not exist: {chroma_path}")
        return {"deleted": 0, "space_freed_mb": 0}
    
    stats = {"deleted": 0, "space_freed_mb": 0}
    
    print(f"{'[DRY RUN] ' if dry_run else ''}Resetting ChromaDB - deleting all data")
    print(f"Path: {chroma_path}")
    print("-" * 60)
    
    for item in chroma_path.rglob("*"):
        if item.is_file():
            try:
                size_mb = item.stat().st_size / (1024 * 1024)
                print(f"{'[DRY RUN] ' if dry_run else ''}Deleting: {item.relative_to(chroma_path)} ({size_mb:.2f} MB)")
                
                if not dry_run:
                    item.unlink()
                
                stats["deleted"] += 1
                stats["space_freed_mb"] += size_mb
                
            except Exception as e:
                print(f"Error deleting {item}: {e}")
    
    # Remove all directories
    if not dry_run:
        for item in sorted(chroma_path.rglob("*"), reverse=True):
            if item.is_dir():
                try:
                    item.rmdir()
                except Exception:
                    pass
    
    print("-" * 60)
    print(f"Reset complete:")
    print(f"  Files {'would be ' if dry_run else ''}deleted: {stats['deleted']}")
    print(f"  Space {'would be ' if dry_run else ''}freed: {stats['space_freed_mb']:.2f} MB")
    
    return stats


def setup_cron_job():
    """Instructions for setting up weekly cron job"""
    script_path = Path(__file__).resolve()
    
    cron_line = f"0 2 * * 0 /usr/bin/python3 {script_path} --weekly"
    
    print("\n" + "=" * 60)
    print("CRON SETUP INSTRUCTIONS")
    print("=" * 60)
    print("To run this cleanup weekly, add the following to your crontab:")
    print(f"\n  {cron_line}\n")
    print("Run 'crontab -e' and paste the line above.")
    print("This will run every Sunday at 2:00 AM.")
    print("=" * 60)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="AutoPoV ChromaDB Cleanup - Manage vector store disk usage"
    )
    
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Delete data older than this many days (default: 7)"
    )
    
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset all ChromaDB data (DANGER: deletes everything)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting"
    )
    
    parser.add_argument(
        "--weekly",
        action="store_true",
        help="Run in weekly cleanup mode (logs to file)"
    )
    
    parser.add_argument(
        "--setup-cron",
        action="store_true",
        help="Show instructions for setting up weekly cron job"
    )
    
    args = parser.parse_args()
    
    if args.setup_cron:
        setup_cron_job()
        return
    
    # Setup logging for weekly mode
    if args.weekly:
        log_dir = Path("./logs")
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / f"chromadb_cleanup_{datetime.now().strftime('%Y%m%d')}.log"
        
        import logging
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        logging.getLogger('').addHandler(console)
        
        print(f"Logging to: {log_file}")
    
    # Run cleanup
    if args.reset:
        print("WARNING: This will delete ALL ChromaDB data!")
        response = input("Are you sure? Type 'yes' to continue: ")
        if response.lower() != 'yes':
            print("Cancelled.")
            sys.exit(0)
        
        reset_chromadb(dry_run=args.dry_run)
    else:
        cleanup_chromadb(older_than_days=args.days, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
