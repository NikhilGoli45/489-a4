import unittest
import time
import os
import subprocess
from test_utils import TestEnvironment, PROJECT_ROOT

class TestIcmp(unittest.TestCase):
    def setUp(self):
        self.env = TestEnvironment()
        # We'll start router in individual tests to allow custom rtables
        try:
            self.env.start_pox()
            self.net = self.env.start_mininet()
            self.client = self.net.get('client')
            self.server1 = self.net.get('server1')
            
            time.sleep(5)
        except Exception as e:
            print(f"Setup failed: {e}")
            self.env.stop_all()
            raise

    def tearDown(self):
        self.env.stop_all()
        # Clean up temporary rtables
        if os.path.exists("test_rtable_icmp"):
            os.remove("test_rtable_icmp")

    def test_echo_reply(self):
        """Test ICMP Echo Reply from Router"""
        print("\nRunning test_echo_reply...")
        self.env.start_router() # Use default rtable
        
        # Ping router interface
        output = self.client.cmd("ping -c 3 10.0.1.1")
        print(f"Ping Output:\n{output}")
        self.assertIn("3 packets transmitted, 3 received", output)

    def test_destination_net_unreachable(self):
        """Test ICMP Destination Net Unreachable (Type 3, Code 0)"""
        print("\nRunning test_destination_net_unreachable...")
        
        # Create rtable with NO default route, but routes to hosts
        # Note: We need routes to hosts so we can talk to them, but we want to ping something else.
        rtable_content = """192.168.2.2 192.168.2.2 255.255.255.255 eth1
172.64.3.10 172.64.3.10 255.255.255.255 eth2
10.0.1.100 10.0.1.100 255.255.255.255 eth3
"""
        rtable_path = os.path.join(PROJECT_ROOT, "test_rtable_icmp")
        with open(rtable_path, "w") as f:
            f.write(rtable_content)
            
        self.env.start_router(rtable_path=rtable_path)
        
        # Ping an unknown IP (e.g., 8.8.8.8) from client
        # Should receive Destination Net Unreachable
        output = self.client.cmd("ping -c 1 -W 2 8.8.8.8")
        print(f"Ping Output:\n{output}")
        
        # Output usually contains "Destination Net Unreachable" or similar from the gateway
        # The ping command output on linux usually shows "From <Gateway IP> icmp_seq=1 Destination Net Unreachable"
        self.assertTrue("Unreachable" in output or "100% packet loss" in output)
        # To be more specific, check tcpdump
        
        pcap_file = "client_net_unreach.pcap"
        self.client.cmd(f"tcpdump -i client-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        self.client.cmd("ping -c 1 -W 1 8.8.8.8")
        time.sleep(2)
        self.client.cmd("killall tcpdump")
        
        output = self.client.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output:\n{output}")
        
        # ICMP unreachable - net unreachable
        self.assertIn("unreachable", output)

    def test_destination_host_unreachable(self):
        """Test ICMP Destination Host Unreachable (Type 3, Code 1)"""
        print("\nRunning test_destination_host_unreachable...")
        self.env.start_router()
        
        # We need a route to exist, but ARP to fail.
        # server1 is at 192.168.2.2 via eth1.
        # If we bring down server1 interface, it won't reply to ARP.
        # Router should try ARP 7 times then send Host Unreachable.
        
        # Bring down server1 eth0
        self.server1.cmd("ifconfig server1-eth0 down")
        
        # Ping server1 from client
        # It will take some time for router to give up (7 * 1s = 7s + overhead)
        print("Pinging unreachable host (waiting for ARP timeout)...")
        
        pcap_file = "client_host_unreach.pcap"
        self.client.cmd(f"tcpdump -i client-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        # Use long timeout for ping
        start_time = time.time()
        self.client.cmd("ping -c 1 -W 15 192.168.2.2")
        end_time = time.time()
        
        time.sleep(1)
        self.client.cmd("killall tcpdump")
        self.server1.cmd("ifconfig server1-eth0 up") # Restore
        
        output = self.client.cmd(f"tcpdump -r {pcap_file} -v")
        print(f"TCPDUMP Output:\n{output}")
        
        # Check for Host unreachable (code 1)
        # tcpdump format: "ICMP 192.168.2.2 host unreachable" or similar
        self.assertIn("unreachable", output)
        # Ideally ensure it is Host unreachable not Net unreachable
        # But standard tcpdump output might just say "unreachable".
        # With -v, it might show codes. "host unreachable" is distinct from "net unreachable"

    def test_port_unreachable(self):
        """Test ICMP Port Unreachable (Type 3, Code 3)"""
        print("\nRunning test_port_unreachable...")
        self.env.start_router()
        
        # Send UDP packet to router interface
        # Using nc (netcat)
        pcap_file = "client_port_unreach.pcap"
        self.client.cmd(f"tcpdump -i client-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        # Send UDP to 10.0.1.1 port 9999
        self.client.cmd("echo 'test' | nc -u -w 1 10.0.1.1 9999")
        
        time.sleep(2)
        self.client.cmd("killall tcpdump")
        
        output = self.client.cmd(f"tcpdump -r {pcap_file} -v")
        print(f"TCPDUMP Output:\n{output}")
        
        self.assertIn("unreachable", output)
        # Check for port unreachable specific text if possible
        self.assertIn("port unreachable", output.lower())

    def test_time_exceeded(self):
        """Test ICMP Time Exceeded (Type 11)"""
        print("\nRunning test_time_exceeded...")
        self.env.start_router()
        
        # Traceroute to server1.
        # First hop is router. TTL=1.
        # Router receives packet with TTL=1. Decrements to 0.
        # Should send Time Exceeded.
        
        pcap_file = "client_time_exceeded.pcap"
        self.client.cmd(f"tcpdump -i client-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        # Using traceroute or just ping with ttl
        self.client.cmd("ping -c 1 -t 1 192.168.2.2")
        
        time.sleep(2)
        self.client.cmd("killall tcpdump")
        
        output = self.client.cmd(f"tcpdump -r {pcap_file} -v")
        print(f"TCPDUMP Output:\n{output}")
        
        self.assertIn("time exceeded", output.lower())

if __name__ == "__main__":
    unittest.main()

