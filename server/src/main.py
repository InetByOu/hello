#!/usr/bin/env python3
"""
UDTUN Server Main Entry Point
"""

import sys
import os
import signal
import time

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config, save_config
from tunnel import UDTTunnel

class UDTUNServer:
    """Main server class"""
    
    def __init__(self):
        self.config = None
        self.tunnel = None
        self.running = False
    
    def handle_signals(self):
        """Setup signal handlers"""
        def signal_handler(sig, frame):
            print(f"\nReceived signal {sig}, shutting down...")
            self.running = False
            if self.tunnel:
                self.tunnel.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def run(self, config_path: str = None):
        """Run the server"""
        print("=" * 60)
        print("UDTUN - Blind UDP Tunneling Server")
        print("=" * 60)
        
        # Setup signal handlers
        self.handle_signals()
        
        # Load configuration
        try:
            if config_path:
                self.config = load_config(config_path)
            else:
                self.config = load_config()
            
            print(f"Configuration loaded")
            print(f"UDP Port Range: {self.config.udp_port_range}")
            print(f"Listening Port: {self.config.listen_port}")
            print(f"TUN Interface: {self.config.tun_name}")
            print(f"TUN Network: {self.config.tun_ip}/{self.config.tun_netmask}")
            
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return 1
        
        # Create and start tunnel
        try:
            self.tunnel = UDTTunnel(self.config)
            
            if not self.tunnel.start():
                print("Failed to start tunnel")
                return 1
            
            self.running = True
            
            # Main loop
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nShutdown requested...")
        except Exception as e:
            print(f"Fatal error: {e}")
            import traceback
            traceback.print_exc()
            return 1
        finally:
            if self.tunnel:
                self.tunnel.stop()
        
        return 0

def main():
    """Main entry point"""
    # Parse command line arguments
    config_path = None
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    # Run server
    server = UDTUNServer()
    return server.run(config_path)

if __name__ == "__main__":
    sys.exit(main())
