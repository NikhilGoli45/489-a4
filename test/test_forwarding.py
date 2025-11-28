import unittest
import time
import os
from test_utils import TestEnvironment, PROJECT_ROOT

class TestForwarding(unittest.TestCase):
    def setUp(self):
        self.env = TestEnvironment()
        try:
            self.env.start_pox()
            self.net = self.env.start_mininet()
            
            self.client = self.net.get('client')
            self.server1 = self.net.get('server1')
            self.server2 = self.net.get('server2')
            
            time.sleep(5)
        except Exception as e:
            print(f"Setup failed: {e}")
            self.env.stop_all()
            raise

    def tearDown(self):
        self.env.stop_all()
        if os.path.exists("test_rtable_lpm"):
            os.remove("test_rtable_lpm")

    def test_longest_prefix_match(self):
        """Test Longest Prefix Match forwarding logic"""
        print("\nRunning test_longest_prefix_match...")
        
        # Create a routing table with overlapping prefixes
        # server1 is 192.168.2.2
        # server2 is 172.64.3.10
        
        # We want to route to server1 (192.168.2.2) via eth1
        # But we'll add a less specific route via eth2 for 192.168.0.0/16
        # And a more specific route for 192.168.2.2/32 via eth1 (or just the standard one)
        
        # Standard rtable:
        # 192.168.2.2 192.168.2.2 255.255.255.255 eth1
        # 172.64.3.10 172.64.3.10 255.255.255.255 eth2
        
        # Modified rtable:
        # 192.168.0.0 172.64.3.10 255.255.0.0     eth2  (Matches 192.168.2.2, but length 16)
        # 192.168.2.2 192.168.2.2 255.255.255.255 eth1  (Matches 192.168.2.2, length 32)
        # 10.0.1.100  10.0.1.100  255.255.255.255 eth3
        
        rtable_content = """192.168.0.0 172.64.3.10 255.255.0.0 eth2
192.168.2.2 192.168.2.2 255.255.255.255 eth1
10.0.1.100 10.0.1.100 255.255.255.255 eth3
"""
        rtable_path = os.path.join(PROJECT_ROOT, "test_rtable_lpm")
        with open(rtable_path, "w") as f:
            f.write(rtable_content)
            
        self.env.start_router(rtable_path=rtable_path)
        
        # Ping server1 (192.168.2.2). Should go to eth1 (server1).
        output = self.client.cmd("ping -c 1 192.168.2.2")
        self.assertIn("1 received", output)
        
        # Verify it arrived at server1, not server2.
        # server1 should have seen the packet.
        # This is implicitly verified by ping success, as server2 wouldn't reply to 192.168.2.2 unless we configured it to.
        # And server1 wouldn't get it if routed to eth2 (server2).
        
        # Now test the less specific route.
        # Ping 192.168.1.1. Should go to eth2 (server2).
        # But server2 doesn't have this IP. 
        # We can check if packet arrives at server2 interface.
        
        pcap_file = "server2_lpm.pcap"
        self.server2.cmd(f"tcpdump -i server2-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        self.client.cmd("ping -c 1 -W 1 192.168.1.1")
        
        time.sleep(2)
        self.server2.cmd("killall tcpdump")
        
        output = self.server2.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output (Server2):\n{output}")
        
        # Should see ICMP Echo Request for 192.168.1.1 arriving at server2
        self.assertIn("IP 10.0.1.100 > 192.168.1.1", output)

    def test_ttl_decrement(self):
        """Test that TTL is decremented by 1"""
        print("\nRunning test_ttl_decrement...")
        self.env.start_router()
        
        # Capture at server1
        pcap_file = "server1_ttl.pcap"
        self.server1.cmd(f"tcpdump -i server1-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        # Ping with specific TTL=64 from client
        self.client.cmd("ping -c 1 -t 64 192.168.2.2")
        
        time.sleep(2)
        self.server1.cmd("killall tcpdump")
        
        output = self.server1.cmd(f"tcpdump -r {pcap_file} -v")
        print(f"TCPDUMP Output:\n{output}")
        
        # Look for ttl 63 (64 - 1)
        self.assertIn("ttl 63", output)

    def test_checksum_validation(self):
        """Test that packets with bad checksums are dropped"""
        print("\nRunning test_checksum_validation...")
        self.env.start_router()
        
        # We need to send a raw packet with bad checksum from client.
        # Use a python script on client.
        
        script = """
from scapy.all import *
import sys

# Create packet with bad checksum
p = IP(dst="192.168.2.2", src="10.0.1.100", ttl=64, chksum=0x1234)/ICMP()
send(p, iface="client-eth0", verbose=0)
"""
        with open("send_bad_chksum.py", "w") as f:
            f.write(script)
            
        # Copy script to client location (shared fs)
        # But client shares fs with host, so it's fine.
        
        # Start capture on server1
        pcap_file = "server1_bad_chksum.pcap"
        self.server1.cmd(f"tcpdump -i server1-eth0 -w {pcap_file} icmp &")
        time.sleep(1)
        
        # Run script on client
        self.client.cmd("python3 send_bad_chksum.py")
        
        time.sleep(2)
        self.server1.cmd("killall tcpdump")
        
        output = self.server1.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output:\n{output}")
        
        # Should NOT see the packet
        self.assertNotIn("IP 10.0.1.100 > 192.168.2.2", output)
        
        os.remove("send_bad_chksum.py")

if __name__ == "__main__":
    unittest.main()

