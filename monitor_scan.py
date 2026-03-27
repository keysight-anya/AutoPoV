#!/usr/bin/env python3
"""
AutoPoV Scan Monitor - Track scan progress in real-time
"""
import sys
import time
import json
sys.path.insert(0, '/home/user/AutoPoV/autopov')

import os
import requests

API_KEY = os.environ.get("AUTOPOV_API_KEY", "")
BASE_URL = "http://localhost:8000/api"

def get_scan_status(scan_id):
    """Get current scan status"""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    try:
        response = requests.get(f"{BASE_URL}/scan/{scan_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching status: {e}")
        return None

def monitor_scan(scan_id):
    """Monitor a scan until completion"""
    print(f"Monitoring scan: {scan_id}")
    print("=" * 60)
    
    last_logs_count = 0
    
    while True:
        status = get_scan_status(scan_id)
        if not status:
            time.sleep(2)
            continue
        
        # Clear screen (optional)
        # print("\033[2J\033[H")
        
        print(f"\nStatus: {status.get('status', 'unknown').upper()}")
        print(f"Progress: {status.get('progress', 0)}%")
        print(f"Scan ID: {scan_id}")
        print("-" * 60)
        
        # Show logs
        logs = status.get('logs', [])
        if logs:
            print("\nLogs:")
            for log in logs[last_logs_count:]:
                print(f"  {log}")
            last_logs_count = len(logs)
        
        # Show result if completed
        if status.get('status') in ['completed', 'failed']:
            print("\n" + "=" * 60)
            print("SCAN FINISHED")
            print("=" * 60)
            result = status.get('result', {})
            if result:
                print(f"Total Findings: {result.get('total_findings', 0)}")
                print(f"Confirmed: {result.get('confirmed_vulns', 0)}")
                print(f"Duration: {result.get('duration_s', 0):.2f}s")
            break
        
        time.sleep(2)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 monitor_scan.py <scan_id>")
        print("\nRecent scans:")
        # List recent scans
        headers = {"Authorization": f"Bearer {API_KEY}"}
        try:
            response = requests.get(f"{BASE_URL}/history?limit=5", headers=headers, timeout=5)
            if response.status_code == 200:
                scans = response.json().get('scans', [])
                for scan in scans:
                    print(f"  {scan['scan_id'][:8]}... - {scan['status']} - {scan.get('duration_s', 0):.1f}s")
        except Exception as e:
            print(f"Could not fetch history: {e}")
        sys.exit(1)
    
    scan_id = sys.argv[1]
    monitor_scan(scan_id)
