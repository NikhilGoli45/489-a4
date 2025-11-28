import sys
import os
import time
import subprocess
import signal
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel, info

# Add py/ directory to sys.path to import topology
sys.path.append(os.path.join(os.path.dirname(__file__), '../py'))
from topology import SpecTopo, disable_ipv6, set_default_route, set_default_route_client, starthttp, stophttp, get_ip_setting, IPBASE

# Paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
POX_DIR = os.path.join(PROJECT_ROOT, 'py')
ROUTER_EXEC = os.path.join(PROJECT_ROOT, 'build/bin/StaticRouterClient')
RTABLE_FILE = os.path.join(PROJECT_ROOT, 'rtable')

class TestEnvironment:
    def __init__(self):
        self.net = None
        self.pox_process = None
        self.router_process = None

    def start_pox(self):
        print("Starting POX Controller...")
        # Check if POX is already running to avoid conflicts? 
        # Ideally we should kill it first or ensure clean state.
        subprocess.run(["pkill", "-9", "-f", "pox.py"], stderr=subprocess.DEVNULL)
        
        cmd = ["python3", "pox/pox.py", "sr_bridge"]
        self.pox_process = subprocess.Popen(
            cmd, 
            cwd=POX_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        time.sleep(5) # Wait for POX to start

    def start_mininet(self):
        print("Starting Mininet...")
        setLogLevel('info')
        
        # Ensure previous mininet is cleaned up
        subprocess.run(["mn", "-c"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        # Change to py/ directory so topology.py can find IP_CONFIG
        original_cwd = os.getcwd()
        try:
            os.chdir(POX_DIR)
            get_ip_setting()
        finally:
            os.chdir(original_cwd)
            
        topo = SpecTopo()
        self.net = Mininet(topo=topo, controller=RemoteController, ipBase=IPBASE)
        self.net.start()
        
        server1, server2, client, router = self.net.get('server1', 'server2', 'client', 'sw0')
        
        # Import IP_SETTING from topology module
        from topology import IP_SETTING
        
        s1intf = server1.defaultIntf()
        s1intf.setIP('%s/8' % IP_SETTING['server1'])
        s2intf = server2.defaultIntf()
        s2intf.setIP('%s/8' % IP_SETTING['server2'])
        clintf = client.defaultIntf()
        clintf.setIP('%s/8' % IP_SETTING['client'])
        
        disable_ipv6(self.net)

        for host in server1, server2:
            set_default_route(host)
        set_default_route_client(client)
        
        # We don't strictly need http servers for all tests, but good to have
        starthttp(server1)
        starthttp(server2)
        
        return self.net

    def start_router(self, rtable_path=RTABLE_FILE):
        print(f"Starting Static Router with rtable: {rtable_path}...")
        
        # Try to find the router executable in common locations
        router_exec = ROUTER_EXEC
        if not os.path.exists(router_exec):
            # Try alternative locations
            alt_paths = [
                os.path.join(PROJECT_ROOT, 'build/StaticRouterClient'),
                os.path.join(PROJECT_ROOT, 'StaticRouterClient'),
            ]
            for alt_path in alt_paths:
                if os.path.exists(alt_path):
                    router_exec = alt_path
                    break
            else:
                raise RuntimeError(
                    f"Router executable not found at {ROUTER_EXEC}.\n"
                    f"Please build the project first:\n"
                    f"  mkdir -p build\n"
                    f"  cd build\n"
                    f"  cmake ../cpp\n"
                    f"  make\n"
                )
        
        cmd = [router_exec, "-r", rtable_path]
        self.router_process = subprocess.Popen(
            cmd,
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        time.sleep(2) # Wait for router to connect

    def stop_all(self):
        print("Stopping all components...")
        if self.router_process:
            os.killpg(os.getpgid(self.router_process.pid), signal.SIGTERM)
            self.router_process.wait()
        
        if self.net:
            stophttp()
            self.net.stop()
            
        if self.pox_process:
            os.killpg(os.getpgid(self.pox_process.pid), signal.SIGTERM)
            self.pox_process.wait()
            
        # Cleanup mininet
        subprocess.run(["mn", "-c"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def run_command(host, command):
    """Run a command on a mininet host and return output"""
    return host.cmd(command)

