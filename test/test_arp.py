import unittest
import time
import sys
import os
from test_utils import TestEnvironment, run_command

class TestArp(unittest.TestCase):
    def setUp(self):
        self.env = TestEnvironment()
        try:
            self.env.start_pox()
            self.net = self.env.start_mininet()
            self.env.start_router()
            
            # Get host objects
            self.client = self.net.get('client')
            self.server1 = self.net.get('server1')
            self.server2 = self.net.get('server2')
            
            # Wait for network to stabilize
            time.sleep(5)
        except Exception as e:
            print(f"Setup failed: {e}")
            self.env.stop_all()
            raise

    def tearDown(self):
        self.env.stop_all()

    def test_arp_request_generation(self):
        """Test that router generates ARP requests when forwarding to unknown MAC"""
        print("\nRunning test_arp_request_generation...")
        
        # Start tcpdump on server1 to capture ARP requests
        # server1 IP is 192.168.2.2. Router interface is 192.168.2.1 (sw0-eth1)
        # When client pings server1, router should ARP for server1
        
        # Clear ARP cache on server1 to force it to reply to ARP? 
        # Actually we care about Router's ARP behavior. 
        # If router doesn't have server1 MAC, it sends ARP Request.
        
        # Run tcpdump in background on server1
        # Capture only ARP packets
        pcap_file = "server1_arp.pcap"
        self.server1.cmd(f"tcpdump -i server1-eth0 -w {pcap_file} arp &")
        time.sleep(1)
        
        # Client pings server1 (single packet)
        # This should trigger router to send ARP request to server1
        self.client.cmd("ping -c 1 192.168.2.2")
        
        time.sleep(2)
        self.server1.cmd("killall tcpdump")
        
        # Analyze pcap (using tcpdump to read it back)
        output = self.server1.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output:\n{output}")
        
        # Expect: ARP, Request who-has 192.168.2.2 tell 192.168.2.1
        self.assertIn("Request who-has 192.168.2.2 tell 192.168.2.1", output)

    def test_arp_reply_generation(self):
        """Test that router responds to ARP requests for its interfaces"""
        print("\nRunning test_arp_reply_generation...")
        
        # Client (10.0.1.100) pings Router Interface (10.0.1.1 - sw0-eth3)
        # Client will send ARP Request for 10.0.1.1
        # Router must reply.
        
        # We can check if ping succeeds. If ping succeeds, ARP exchange must have happened.
        output = self.client.cmd("ping -c 1 10.0.1.1")
        print(f"Ping Output:\n{output}")
        
        self.assertIn("1 packets transmitted, 1 received", output)
        
        # Verify with tcpdump on client
        pcap_file = "client_arp.pcap"
        self.client.cmd(f"tcpdump -i client-eth0 -w {pcap_file} arp &")
        time.sleep(1)
        
        # Clear client arp cache to ensure it sends request
        self.client.cmd("ip neigh flush all")
        self.client.cmd("ping -c 1 10.0.1.1")
        
        time.sleep(2)
        self.client.cmd("killall tcpdump")
        
        output = self.client.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output:\n{output}")
        
        # Expect: ARP, Reply 10.0.1.1 is-at <router-mac>
        self.assertIn("Reply 10.0.1.1 is-at", output)

    def test_arp_cache_behavior(self):
        """Test that router caches ARP entries and handles them"""
        print("\nRunning test_arp_cache_behavior...")
        
        # 1. Ping server1 from client. Router learns server1 MAC.
        self.client.cmd("ping -c 1 192.168.2.2")
        
        # 2. Start capturing on server1 again.
        pcap_file = "server1_arp_cache.pcap"
        self.server1.cmd(f"tcpdump -i server1-eth0 -w {pcap_file} arp &")
        time.sleep(1)
        
        # 3. Ping again immediately. Should NOT see another ARP request if cached.
        self.client.cmd("ping -c 1 192.168.2.2")
        
        time.sleep(1)
        self.server1.cmd("killall tcpdump")
        
        output = self.server1.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output:\n{output}")
        
        # Should be empty or minimal (maybe background noise, but not a new Request for server1)
        # Note: server1 might send ARP request for Router if its cache expired, but Router shouldn't send Request for server1.
        # We look for "Request who-has 192.168.2.2 tell 192.168.2.1"
        self.assertNotIn("Request who-has 192.168.2.2 tell 192.168.2.1", output)

    def test_arp_timeout(self):
        """Test that ARP cache entries time out"""
        print("\nRunning test_arp_timeout...")
        
        # The router timeout is 15 seconds.
        
        # 1. Ping server1 to populate cache.
        self.client.cmd("ping -c 1 192.168.2.2")
        
        # 2. Wait > 15 seconds.
        print("Waiting 16 seconds for ARP cache to expire...")
        time.sleep(16)
        
        # 3. Capture and Ping again. Should see new ARP request.
        pcap_file = "server1_arp_timeout.pcap"
        self.server1.cmd(f"tcpdump -i server1-eth0 -w {pcap_file} arp &")
        time.sleep(1)
        
        self.client.cmd("ping -c 1 192.168.2.2")
        
        time.sleep(1)
        self.server1.cmd("killall tcpdump")
        
        output = self.server1.cmd(f"tcpdump -r {pcap_file}")
        print(f"TCPDUMP Output:\n{output}")
        
        self.assertIn("Request who-has 192.168.2.2 tell 192.168.2.1", output)

if __name__ == "__main__":
    unittest.main()

