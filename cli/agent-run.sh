#!/bin/bash
# AutoPoV Agent CLI Bridge
# This script sends commands directly into the running Docker container

if [ "$(docker ps -q -f name=autopov-api)" ]; then
    docker exec -it autopov-api python cli_agent_trigger.py "$@"
else
    echo "Error: The 'autopov-api' container is not running."
    echo "Please run: cd ~/AutoPoV && ./start-autopov.sh"
fi
