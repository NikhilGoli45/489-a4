# Static Router Test Suite

This directory contains a comprehensive test suite for the Static Router project, verifying ARP, ICMP, Forwarding, and End-to-End functionality using Mininet.

## Prerequisites

- **The project must be built first!** Run the following commands from the project root:
  ```bash
  mkdir -p build
  cd build
  cmake ../cpp
  make
  ```
  The executable will be at `build/bin/StaticRouterClient`.
- Mininet must be installed.
- Python dependencies (pox, mininet) must be available (typically handled by `setup.sh`).

## Running the Tests

Run the main test runner script from the project root:

```bash
sudo ./test/run_all_tests.sh
```

**Note:** You must run as `root` (sudo) because Mininet requires root privileges to create network namespaces.

## Test Structure

- `test_arp.py`: Verifies ARP request generation, reply handling, and cache management.
- `test_icmp.py`: Verifies ICMP error messages (Net/Host/Port Unreachable, Time Exceeded) and Echo Reply.
- `test_forwarding.py`: Verifies IP forwarding logic, Longest Prefix Matching, TTL decrement, and Checksum handling.
- `test_e2e.py`: Verifies full network connectivity using `ping`, `traceroute`, and HTTP downloads.

## Test Utils

`test_utils.py` provides helper classes to manage the lifecycle of POX, Mininet, and the Static Router process. It ensures proper cleanup of resources after each test.

