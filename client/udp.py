#!/usr/bin/env python3
"""
Client UDP manager with blind probing
"""

import socket
import struct
import time
import select
import random
from typing import Optional, Tuple

from .config import config

class UDPClient:
    """UDP client with blind port probing"""
    
    def __init__(self):
        self.socket: Optional[socket.socket] = None
        self.server_addr: Optional[Tuple[str, int]] = None
        self.running = False
        self.receive_handler: Optional[Callable] = None
        self.connected = False
        self.last_receive_time = 0
        self.sequence_out = 0
    
    def create_socket(self) -> bool:
        """Create UDP socket"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, config.udp_buffer_size)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, config.udp_buffer_size)
            self.socket.bind((config.udp_bind_ip, config.udp_bind_port))
            self.socket.setblocking(False)
            return True
        except Exception as e:
            print(f"Error creating socket: {e}")
            return False
    
    def probe_server(self) -> bool:
        """Probe server to find open port"""
        if not self.socket:
            if not self.create_socket():
                return False
        
        start_port, end_port = config.udp_port_range
        ports = list(range(start_port, end_port + 1))
        random.shuffle(ports)  # Randomize probing order
        
        probe_data = b"UDTUN_PROBE"
        
        for attempt in range(config.max_probe_attempts):
            for port in ports:
                try:
                    # Send probe
                    self.socket.sendto(probe_data, (config.server_ip, port))
                    
                    # Wait for response
                    ready, _, _ = select.select([self.socket], [], [], config.probe_timeout)
                    if ready:
                        response, addr = self.socket.recvfrom(1024)
                        if response == b"UDTUN_ACK":
                            self.server_addr = (config.server_ip, port)
                            print(f"Found open port: {port}")
                            return True
                
                except (BlockingIOError, socket.timeout):
                    continue
                except Exception as e:
                    print(f"Error probing port {port}: {e}")
            
            print(f"Probe attempt {attempt + 1} failed, retrying...")
            time.sleep(1)
        
        return False
    
    def start(self):
        """Start UDP client"""
        if not self.probe_server():
            raise RuntimeError("Failed to find open server port")
        
        self.running = True
        self.connected = True
        self.last_receive_time = time.time()
        
        # Send connection established packet
        self.send_keepalive()
    
    def stop(self):
        """Stop UDP client"""
        self.running = False
        self.connected = False
        
        if self.socket:
            self.socket.close()
            self.socket = None
    
    def send_keepalive(self):
        """Send keepalive packet"""
        if self.connected and self.server_addr:
            keepalive = struct.pack('!BI', 0x02, 0)  # Type 2 = keepalive
            self.send_packet(keepalive)
    
    def send_packet(self, packet: bytes):
        """Send packet to server"""
        if self.connected and self.socket and self.server_addr:
            try:
                self.socket.sendto(packet, self.server_addr)
            except Exception as e:
                print(f"Error sending packet: {e}")
                self.connected = False
    
    def receive_loop(self):
        """Receive packets from server"""
        while self.running:
            try:
                ready, _, _ = select.select([self.socket], [], [], config.read_timeout)
                if ready:
                    packet, addr = self.socket.recvfrom(config.max_packet_size)
                    
                    if addr == self.server_addr:
                        self.last_receive_time = time.time()
                        
                        if self.receive_handler:
                            self.receive_handler(packet)
                    
                    # Check keepalive
                    if packet and len(packet) >= 5:
                        if packet[0] == 0x02:  # Keepalive response
                            continue
                
                # Check connection timeout
                if time.time() - self.last_receive_time > config.connection_timeout:
                    print("Connection timeout, reconnecting...")
                    self.connected = False
                    self.reconnect()
                
                # Send keepalive periodically
                if time.time() - self.last_receive_time > config.keepalive_interval:
                    self.send_keepalive()
                
            except (BlockingIOError, socket.timeout):
                continue
            except Exception as e:
                print(f"Error in receive loop: {e}")
                time.sleep(1)
    
    def reconnect(self):
        """Reconnect to server"""
        self.connected = False
        time.sleep(config.reconnect_interval)
        
        if self.probe_server():
            self.connected = True
            self.last_receive_time = time.time()
            print("Reconnected to server")
    
    def encode_packet(self, ip_packet: bytes) -> bytes:
        """Encode IP packet for UDP transport"""
        self.sequence_out += 1
        return struct.pack('!BI', 0x01, self.sequence_out) + ip_packet
    
    def decode_packet(self, udp_packet: bytes) -> bytes:
        """Decode UDP packet to IP packet"""
        if len(udp_packet) < 5:
            return b""
        
        version = udp_packet[0]
        if version != 0x01:
            return b""
        
        return udp_packet[5:]
