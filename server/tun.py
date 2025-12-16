#!/usr/bin/env python3
"""
TUN Device Management - WHISPER Tunnel Server
"""

import os
import sys
import fcntl
import struct
import subprocess
from typing import Optional, Tuple, List
import select

# Linux TUN/TAP constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

class TUNDevice:
    """TUN device manager"""
    
    def __init__(self, name: str = "whispertun0", mtu: int = 1300):
        self.name = name
        self.mtu = mtu
        self.fd = None
        self.ip_address = ""
        
    def create(self) -> bool:
        """Create TUN device"""
        try:
            # Open /dev/net/tun
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # Prepare ifr structure
            ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
            
            # Set TUN device mode
            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
            
            # Set non-blocking
            flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Set MTU
            self.set_mtu(self.mtu)
            
            return True
            
        except Exception as e:
            print(f"Failed to create TUN device: {e}")
            if self.fd:
                os.close(self.fd)
            return False
    
    def set_mtu(self, mtu: int):
        """Set MTU for TUN device"""
        try:
            subprocess.run(["ip", "link", "set", "dev", self.name, "mtu", str(mtu)], 
                         check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to set MTU: {e}")
    
    def configure(self, ip: str, netmask: str = "255.255.255.0"):
        """Configure TUN device IP address"""
        try:
            self.ip_address = ip
            
            # Bring interface up
            subprocess.run(["ip", "link", "set", "dev", self.name, "up"], 
                         check=True, capture_output=True)
            
            # Set IP address
            subprocess.run(["ip", "addr", "add", f"{ip}/{netmask}", "dev", self.name],
                         check=True, capture_output=True)
            
            # Enable IP forwarding on this interface
            subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{self.name}.forwarding=1"],
                         check=True, capture_output=True)
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to configure TUN: {e}")
            return False
    
    def read_packets(self, max_packets: int = 32) -> List[bytes]:
        """Read IP packets from TUN device"""
        packets = []
        
        if not self.fd:
            return packets
        
        try:
            for _ in range(max_packets):
                # Read with maximum MTU size
                packet = os.read(self.fd, self.mtu + 100)
                if packet:
                    packets.append(packet)
                else:
                    break
        except BlockingIOError:
            pass  # No more data
        except Exception as e:
            print(f"Error reading from TUN: {e}")
        
        return packets
    
    def write_packet(self, packet: bytes) -> bool:
        """Write IP packet to TUN device"""
        if not self.fd:
            return False
        
        try:
            os.write(self.fd, packet)
            return True
        except Exception as e:
            print(f"Error writing to TUN: {e}")
            return False
    
    def write_packets(self, packets: List[bytes]) -> int:
        """Write multiple packets to TUN"""
        count = 0
        for packet in packets:
            if self.write_packet(packet):
                count += 1
        return count
    
    def destroy(self):
        """Destroy TUN device"""
        if self.fd:
            os.close(self.fd)
            self.fd = None
        
        # Remove interface
        try:
            subprocess.run(["ip", "link", "delete", self.name], 
                         capture_output=True)
        except:
            pass
