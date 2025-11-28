#!/bin/bash

# Ensure we are running as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Get directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_ROOT="$(dirname "$DIR")"

# Setup virtualenv if needed (assuming user has run setup.sh)
if [ -d "$PROJECT_ROOT/py/.venv" ]; then
    source "$PROJECT_ROOT/py/.venv/bin/activate"
else
    echo "Warning: .venv not found in py/.venv. Tests might fail if dependencies are missing."
fi

export PYTHONPATH=$PYTHONPATH:$PROJECT_ROOT/py

echo "========================================="
echo "Running Static Router Test Suite"
echo "========================================="

# Clean any leftover mininet/pox processes
mn -c > /dev/null 2>&1
pkill -9 -f pox.py
pkill -9 -f StaticRouterClient

echo "Running ARP Tests..."
python3 "$DIR/test_arp.py"
if [ $? -ne 0 ]; then
    echo "ARP Tests Failed!"
    exit 1
fi

echo "Running ICMP Tests..."
python3 "$DIR/test_icmp.py"
if [ $? -ne 0 ]; then
    echo "ICMP Tests Failed!"
    exit 1
fi

echo "Running Forwarding Tests..."
python3 "$DIR/test_forwarding.py"
if [ $? -ne 0 ]; then
    echo "Forwarding Tests Failed!"
    exit 1
fi

echo "Running End-to-End Tests..."
python3 "$DIR/test_e2e.py"
if [ $? -ne 0 ]; then
    echo "End-to-End Tests Failed!"
    exit 1
fi

echo "========================================="
echo "All Tests Passed Successfully!"
echo "========================================="

