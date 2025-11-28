import unittest
import time
import os
from test_utils import TestEnvironment, PROJECT_ROOT

class TestE2E(unittest.TestCase):
    def setUp(self):
        self.env = TestEnvironment()
        try:
            self.env.start_pox()
            self.net = self.env.start_mininet()
            self.env.start_router()
            
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
        if os.path.exists("downloaded_index.html"):
            os.remove("downloaded_index.html")

    def test_ping_switch_interfaces(self):
        """Test pinging switch interfaces from hosts"""
        print("\nRunning test_ping_switch_interfaces...")
        
        # Client -> 10.0.1.1 (sw0-eth3)
        output = self.client.cmd("ping -c 1 10.0.1.1")
        self.assertIn("1 received", output)
        
        # Server1 -> 192.168.2.1 (sw0-eth1)
        output = self.server1.cmd("ping -c 1 192.168.2.1")
        self.assertIn("1 received", output)

    def test_ping_host_to_host(self):
        """Test pinging between hosts"""
        print("\nRunning test_ping_host_to_host...")
        
        # Client -> Server1
        output = self.client.cmd("ping -c 1 192.168.2.2")
        self.assertIn("1 received", output)
        
        # Client -> Server2
        output = self.client.cmd("ping -c 1 172.64.3.10")
        self.assertIn("1 received", output)
        
        # Server1 -> Server2
        output = self.server1.cmd("ping -c 1 172.64.3.10")
        self.assertIn("1 received", output)

    def test_traceroute_host_to_host(self):
        """Test traceroute between hosts"""
        print("\nRunning test_traceroute_host_to_host...")
        
        # Client -> Server1
        # Should show: 1. Router (10.0.1.1), 2. Server1 (192.168.2.2)
        # traceroute might print * * * if ICMP Time Exceeded not implemented or firewall blocked.
        # But we implemented Time Exceeded in previous tests.
        
        output = self.client.cmd("traceroute -n 192.168.2.2")
        print(f"Traceroute Output:\n{output}")
        
        # Check for router IP
        self.assertIn("10.0.1.1", output)
        # Check for server IP
        self.assertIn("192.168.2.2", output)

    def test_traceroute_to_switch(self):
        """Test traceroute to switch interface"""
        print("\nRunning test_traceroute_to_switch...")
        
        # Client -> 192.168.2.1 (sw0-eth1) - far interface
        # Should show: 1. 10.0.1.1 (sw0-eth3) or 192.168.2.1? 
        # Actually if we traceroute to router's own IP, it should just be 1 hop.
        
        output = self.client.cmd("traceroute -n 10.0.1.1")
        print(f"Traceroute Output:\n{output}")
        self.assertIn("10.0.1.1", output)

    def test_http_download(self):
        """Test HTTP download from server"""
        print("\nRunning test_http_download...")
        
        # Client downloads from Server1
        # URL: http://192.168.2.2/index.html
        
        self.client.cmd("wget -O downloaded_index.html http://192.168.2.2/index.html")
        
        # Verify file exists and has content
        # We can cat it
        output = self.client.cmd("cat downloaded_index.html")
        print(f"Downloaded File Content:\n{output}")
        
        # Check against original file
        # py/http_server1/index.html
        original_path = os.path.join(PROJECT_ROOT, "py/http_server1/index.html")
        with open(original_path, "r") as f:
            original_content = f.read()
            
        self.assertIn(original_content.strip(), output.strip())

if __name__ == "__main__":
    unittest.main()

