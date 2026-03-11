#!/usr/bin/env python3
"""Test background task execution"""
import sys
sys.path.insert(0, '/home/user/AutoPoV/autopov')

import asyncio
from app.scan_manager import get_scan_manager

async def test_scan():
    """Test creating and running a scan"""
    print("Creating scan...")
    scan_id = get_scan_manager().create_scan(
        codebase_path='/tmp',
        model_name='openai/gpt-4o',
        cwes=['CWE-89']
    )
    print(f"Created scan: {scan_id}")
    
    print("\nStarting scan execution...")
    try:
        result = await get_scan_manager().run_scan_async(scan_id)
        print(f"Scan completed: {result}")
    except Exception as e:
        print(f"Scan failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_scan())
