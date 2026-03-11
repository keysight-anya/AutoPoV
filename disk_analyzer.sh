#!/bin/bash

# AutoPoV Disk Space Analyzer
# This script identifies the biggest space consumers in your WSL/Docker environment.

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}   AutoPoV System Disk Analysis           ${NC}"
echo -e "${GREEN}==========================================${NC}"

# 1. Analyze Project Folder
echo -e "\n${YELLOW}[1] Analyzing Project Directory (~/AutoPoV)${NC}"
du -sh ~/AutoPoV/* 2>/dev/null | sort -hr | head -n 10

# 2. Analyze Docker Images
echo -e "\n${YELLOW}[2] Analyzing Docker Images (The 'Engines')${NC}"
docker images --format "table {{.Repository}}\t{{.Size}}"

# 3. Analyze Docker System (Hidden Cache)
echo -e "\n${YELLOW}[3] Analyzing Docker Build Cache & Volumes${NC}"
docker system df

# 4. Check the Virtual Disk "Inflation"
# This shows how much space the Ubuntu "Balloon" is taking on Windows C:
echo -e "\n${YELLOW}[4] Checking Virtual Disk (VHDX) Actual Usage${NC}"
echo "Current internal Ubuntu usage:"
df -h / | grep /

echo -e "\n${GREEN}==========================================${NC}"
echo "Quick Fix Recommendations:"
echo "1. To clear build cache:   docker builder prune -f"
echo "2. To clear unused images: docker image prune -a"
echo "3. To shrink Windows disk: Refer to Step 2 in git_sync_guide.md"
echo -e "${GREEN}==========================================${NC}"
