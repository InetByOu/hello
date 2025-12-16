#!/usr/bin/env python3
"""
UDTUN Server Tunnel Core
"""

import os
import fcntl
import struct
import socket
import select
import time
import threading
import queue
from typing import Dict, Tuple, Optional, Set
from collections import deque

from .config import ServerConfig, get_external_interface
from .utils import validate_ipv4_packet, get_ip_address, setup_logging

# Linux TUN/TAP constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

class UDTTunnel:
    """Main tunnel class for server"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.logger = setup_logging(config.log_file, config.log_level)
        
        # Network components
        self.tun_fd: Optional[int] = None
        self.udp_socket: Optional[socket.socket] = None
        
        # State management
        self.running = False
        self.stats_lock = threading.Lock()
        
        # Session management
        self.sessions: Dict[Tuple[str, int], dict] = {}
        self.session_lock = threading.Lock()
        self.client_ips: Dict[Tuple[str, int], str] = {}
        self.next_client_ip = 2  # Start from 10.9.0.2
        
        # Rate limiting
        self.client_packets: Dict[Tuple[str, int], deque] = {}
        
        # Statistics
        self.stats = {
            'total_packets_in': 0,
            'total_packets_out': 0,
            'total_bytes_in': 0,
            'total_bytes_out': 0,
            'active_clients': 0,
            'total_clients': 0,
            'errors': 0
        }
        
        # Threads
        self.udp_thread: Optional[threading.Thread] = None
        self.tun_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None
        
        # Queues for inter-thread communication
        self.udp_to_tun_queue = queue.Queue(maxsize=1000)
        self.tun_to_udp_queue = queue.Queue(maxsize=1000)
    
    def setup_tun_interface(self) -> bool:
        """Setup TUN interface"""
        try:
            self.logger.info("Setting up TUN interface...")
            
            # Open TUN device
            self.tun_fd = os.open('/dev/net/tun', os.O_RDWR)
            
            # Configure TUN
            ifname = self.config.tun_name.encode()
            ifr = struct.pack('16sH', ifname, IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
            
            # Set non-blocking
            flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Configure network settings
            os.system(f"ip link set {self.config.tun_name} mtu {self.config.tun_mtu}")
            os.system(f"ip addr add {self.config.tun_ip}/{self.config.tun_netmask} dev {self.config.tun_name}")
            os.system(f"ip link set {self.config.tun_name} up")
            
            self.logger.info(f"TUN interface {self.config.tun_name} created: {self.config.tun_ip}/{self.config.tun_netmask}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create TUN interface: {e}")
            return False
    
    def setup_udp_socket(self) -> bool:
        """Setup UDP socket"""
        try:
            self.logger.info("Setting up UDP socket...")
            
            # Create UDP socket
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase buffer sizes
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.udp_buffer_size)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.udp_buffer_size)
            
            # Bind to port
            self.udp_socket.bind((self.config.bind_ip, self.config.listen_port))
            self.udp_socket.setblocking(False)
            
            self.logger.info(f"UDP socket bound to {self.config.bind_ip}:{self.config.listen_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create UDP socket: {e}")
            return False
    
    def setup_iptables(self):
        """Setup iptables rules"""
        try:
            self.logger.info("Setting up iptables rules...")
            
            # Get external interface
            ext_if = get_external_interface()
            
            # Clean up old rules first
            self.cleanup_iptables()
            
            # Enable IP forwarding
            os.system("sysctl -w net.ipv4.ip_forward=1")
            
            # Allow UDP port range
            start_port, end_port = self.config.udp_port_range
            os.system(f"iptables -A INPUT -p udp --dport {start_port}:{end_port} -j ACCEPT")
            
            # DNAT: Redirect all ports to our listening port
            os.system(f"iptables -t nat -A PREROUTING -p udp --dport {start_port}:{end_port} "
                     f"-j DNAT --to-destination :{self.config.listen_port}")
            
            # Allow listening port
            os.system(f"iptables -A INPUT -p udp --dport {self.config.listen_port} -j ACCEPT")
            
            # NAT for TUN interface
            os.system(f"iptables -t nat -A POSTROUTING -o {ext_if} -j MASQUERADE")
            
            # Forwarding rules
            os.system(f"iptables -A FORWARD -i {self.config.tun_name} -o {ext_if} -j ACCEPT")
            os.system(f"iptables -A FORWARD -i {ext_if} -o {self.config.tun_name} "
                     f"-m state --state ESTABLISHED,RELATED -j ACCEPT")
            
            # Save rules
            os.system("iptables-save > /etc/iptables/rules.v4 2>/dev/null || true")
            
            self.logger.info("iptables rules configured successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to setup iptables: {e}")
    
    def cleanup_iptables(self):
        """Cleanup iptables rules"""
        try:
            start_port, end_port = self.config.udp_port_range
            ext_if = get_external_interface()
            
            # Remove INPUT rules
            os.system(f"iptables -D INPUT -p udp --dport {start_port}:{end_port} -j ACCEPT 2>/dev/null || true")
            os.system(f"iptables -D INPUT -p udp --dport {self.config.listen_port} -j ACCEPT 2>/dev/null || true")
            
            # Remove DNAT rule
            os.system(f"iptables -t nat -D PREROUTING -p udp --dport {start_port}:{end_port} "
                     f"-j DNAT --to-destination :{self.config.listen_port} 2>/dev/null || true")
            
            # Remove NAT rules
            os.system(f"iptables -t nat -D POSTROUTING -o {ext_if} -j MASQUERADE 2>/dev/null || true")
            
            # Remove FORWARD rules
            os.system(f"iptables -D FORWARD -i {self.config.tun_name} -o {ext_if} -j ACCEPT 2>/dev/null || true")
            os.system(f"iptables -D FORWARD -i {ext_if} -o {self.config.tun_name} "
                     f"-m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up iptables: {e}")
    
    def assign_client_ip(self, client_addr: Tuple[str, int]) -> str:
        """Assign IP address to client"""
        with self.session_lock:
            # Check if client already has IP
            if client_addr in self.client_ips:
                return self.client_ips[client_addr]
            
            # Assign new IP
            tun_ip = f"10.9.0.{self.next_client_ip}"
            self.next_client_ip += 1
            
            # Reset counter if we reach limit
            if self.next_client_ip > 254:
                self.next_client_ip = 2
            
            # Create session
            self.client_ips[client_addr] = tun_ip
            self.sessions[client_addr] = {
                'tun_ip': tun_ip,
                'last_seen': time.time(),
                'created': time.time(),
                'packets_in': 0,
                'packets_out': 0,
                'bytes_in': 0,
                'bytes_out': 0
            }
            
            # Update statistics
            with self.stats_lock:
                self.stats['total_clients'] += 1
            
            self.logger.info(f"New client {client_addr[0]}:{client_addr[1]} -> {tun_ip}")
            return tun_ip
    
    def update_client_session(self, client_addr: Tuple[str, int]):
        """Update client session timestamp"""
        with self.session_lock:
            if client_addr in self.sessions:
                self.sessions[client_addr]['last_seen'] = time.time()
    
    def check_rate_limit(self, client_addr: Tuple[str, int]) -> bool:
        """Check rate limit for client"""
        if not self.config.enable_rate_limit:
            return True
        
        now = time.time()
        window = 1.0  # 1 second window
        
        with self.session_lock:
            if client_addr not in self.client_packets:
                self.client_packets[client_addr] = deque(maxlen=self.config.rate_limit_per_client)
            
            timestamps = self.client_packets[client_addr]
            
            # Remove old timestamps
            while timestamps and now - timestamps[0] > window:
                timestamps.popleft()
            
            # Check if limit exceeded
            if len(timestamps) >= self.config.rate_limit_per_client:
                return False
            
            # Add current timestamp
            timestamps.append(now)
            return True
    
    def cleanup_expired_sessions(self):
        """Cleanup expired client sessions"""
        with self.session_lock:
            expired = []
            now = time.time()
            
            for client_addr, session in self.sessions.items():
                if now - session['last_seen'] > self.config.session_timeout:
                    expired.append(client_addr)
            
            for client_addr in expired:
                if client_addr in self.client_ips:
                    del self.client_ips[client_addr]
                if client_addr in self.client_packets:
                    del self.client_packets[client_addr]
                del self.sessions[client_addr]
                
                self.logger.info(f"Client {client_addr[0]}:{client_addr[1]} session expired")
            
            return len(expired)
    
    def udp_receive_loop(self):
        """UDP receive loop"""
        self.logger.info("Starting UDP receive loop...")
        
        while self.running:
            try:
                # Check for incoming UDP packets
                ready, _, _ = select.select([self.udp_socket], [], [], self.config.read_timeout)
                
                if ready:
                    data, addr = self.udp_socket.recvfrom(self.config.max_packet_size)
                    
                    if not data:
                        continue
                    
                    # Update client session
                    self.update_client_session(addr)
                    
                    # Check rate limit
                    if not self.check_rate_limit(addr):
                        self.logger.warning(f"Rate limit exceeded for {addr}")
                        continue
                    
                    # Handle probe packets
                    if data == b'UDTUN_PROBE' or data[:11] == b'UDTUN_PROBE':
                        tun_ip = self.assign_client_ip(addr)
                        response = f"UDTUN_ACK:{tun_ip}".encode()
                        self.udp_socket.sendto(response, addr)
                        continue
                    
                    # Handle keepalive packets
                    if len(data) == 1 and data[0] == 0x02:  # Keepalive
                        self.udp_socket.sendto(b'\x02', addr)  # Acknowledge
                        continue
                    
                    # Handle data packets (format: 0x01 + 4-byte seq + data)
                    if len(data) >= 5 and data[0] == 0x01:
                        ip_packet = data[5:]
                        
                        if validate_ipv4_packet(ip_packet):
                            # Queue for TUN
                            self.udp_to_tun_queue.put((ip_packet, addr))
                            
                            # Update statistics
                            with self.stats_lock:
                                self.stats['total_packets_in'] += 1
                                self.stats['total_bytes_in'] += len(data)
                            
                            with self.session_lock:
                                if addr in self.sessions:
                                    self.sessions[addr]['packets_in'] += 1
                                    self.sessions[addr]['bytes_in'] += len(data)
                
            except (BlockingIOError, InterruptedError):
                pass
            except Exception as e:
                self.logger.error(f"UDP receive error: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1
                time.sleep(0.1)
    
    def tun_receive_loop(self):
        """TUN receive loop"""
        self.logger.info("Starting TUN receive loop...")
        
        while self.running:
            try:
                # Read from TUN
                ready, _, _ = select.select([self.tun_fd], [], [], self.config.read_timeout)
                
                if ready:
                    packet = os.read(self.tun_fd, self.config.max_packet_size)
                    
                    if packet and validate_ipv4_packet(packet):
                        # Queue for UDP
                        self.tun_to_udp_queue.put(packet)
                
            except (BlockingIOError, InterruptedError):
                pass
            except Exception as e:
                self.logger.error(f"TUN receive error: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1
                time.sleep(0.1)
    
    def process_udp_to_tun(self):
        """Process packets from UDP to TUN"""
        while self.running:
            try:
                packet, addr = self.udp_to_tun_queue.get(timeout=0.1)
                
                # Write to TUN
                if self.tun_fd and packet:
                    os.write(self.tun_fd, packet)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error writing to TUN: {e}")
    
    def process_tun_to_udp(self):
        """Process packets from TUN to UDP"""
        while self.running:
            try:
                packet = self.tun_to_udp_queue.get(timeout=0.1)
                
                # Extract destination IP
                src_ip, dst_ip = get_ip_address(packet)
                
                if not dst_ip:
                    continue
                
                # Find which client this packet belongs to
                target_addr = None
                with self.session_lock:
                    for addr, tun_ip in self.client_ips.items():
                        if tun_ip == dst_ip:
                            target_addr = addr
                            break
                
                if target_addr and self.udp_socket:
                    # Encode packet (0x01 + sequence + data)
                    seq = int(time.time() * 1000) & 0xFFFFFFFF
                    header = struct.pack('!BI', 0x01, seq)
                    encoded = header + packet
                    
                    # Send via UDP
                    self.udp_socket.sendto(encoded, target_addr)
                    
                    # Update statistics
                    with self.stats_lock:
                        self.stats['total_packets_out'] += 1
                        self.stats['total_bytes_out'] += len(encoded)
                    
                    with self.session_lock:
                        if target_addr in self.sessions:
                            self.sessions[target_addr]['packets_out'] += 1
                            self.sessions[target_addr]['bytes_out'] += len(encoded)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error sending to UDP: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1
    
    def cleanup_loop(self):
        """Periodic cleanup loop"""
        while self.running:
            time.sleep(30)  # Run every 30 seconds
            
            try:
                # Cleanup expired sessions
                expired = self.cleanup_expired_sessions()
                if expired:
                    self.logger.info(f"Cleaned up {expired} expired sessions")
                
                # Update active clients count
                with self.session_lock:
                    active = len(self.sessions)
                
                with self.stats_lock:
                    self.stats['active_clients'] = active
                
                # Log statistics periodically
                self.log_stats()
                
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")
    
    def log_stats(self):
        """Log server statistics"""
        with self.stats_lock:
            self.logger.info(
                f"Stats: Clients={self.stats['active_clients']}/"
                f"{self.stats['total_clients']} | "
                f"In={self.stats['total_packets_in']}/"
                f"{self.stats['total_bytes_in'] >> 10}KB | "
                f"Out={self.stats['total_packets_out']}/"
                f"{self.stats['total_bytes_out'] >> 10}KB | "
                f"Errors={self.stats['errors']}"
            )
    
    def start(self):
        """Start the tunnel server"""
        self.logger.info("=" * 60)
        self.logger.info("Starting UDTUN Server")
        self.logger.info("=" * 60)
        
        # Setup network components
        if not self.setup_tun_interface():
            return False
        
        if not self.setup_udp_socket():
            return False
        
        # Setup iptables
        self.setup_iptables()
        
        # Set running flag
        self.running = True
        
        # Start threads
        self.udp_thread = threading.Thread(target=self.udp_receive_loop, daemon=True)
        self.tun_thread = threading.Thread(target=self.tun_receive_loop, daemon=True)
        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        
        # Processing threads
        udp_processor = threading.Thread(target=self.process_udp_to_tun, daemon=True)
        tun_processor = threading.Thread(target=self.process_tun_to_udp, daemon=True)
        
        # Start all threads
        self.udp_thread.start()
        self.tun_thread.start()
        self.cleanup_thread.start()
        udp_processor.start()
        tun_processor.start()
        
        self.logger.info(f"Server started successfully!")
        self.logger.info(f"UDP Port Range: {self.config.udp_port_range[0]}-{self.config.udp_port_range[1]}")
        self.logger.info(f"Listening Port: {self.config.listen_port}")
        self.logger.info(f"TUN Network: {self.config.tun_ip}/{self.config.tun_netmask}")
        
        return True
    
    def stop(self):
        """Stop the tunnel server"""
        self.logger.info("Shutting down UDTUN Server...")
        self.running = False
        
        # Wait for threads to finish
        if self.udp_thread:
            self.udp_thread.join(timeout=2)
        if self.tun_thread:
            self.tun_thread.join(timeout=2)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2)
        
        # Cleanup iptables
        self.cleanup_iptables()
        
        # Close TUN interface
        if self.tun_fd:
            os.close(self.tun_fd)
        
        # Remove TUN interface
        try:
            os.system(f"ip link delete {self.config.tun_name} 2>/dev/null")
        except:
            pass
        
        # Close UDP socket
        if self.udp_socket:
            self.udp_socket.close()
        
        self.logger.info("UDTUN Server stopped")
