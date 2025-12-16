#!/usr/bin/env python3
"""
Server Configuration - WHISPER Tunnel Server
"""

import os
import sys
from dataclasses import dataclass
from typing import Tuple

@dataclass
class ServerConfig:
    """Server configuration"""
    # Server bind address
    SERVER_IP: str = "0.0.0.0"
    
    # Internal listening port (after DNAT)
    INTERNAL_PORT: int = 5667
    
    # External port range for DNAT
    EXTERNAL_PORT_START: int = 6000
    EXTERNAL_PORT_END: int = 19999
    
    # TUN configuration
    TUN_NAME: str = "whispertun0"
    TUN_MTU: int = 1300
    TUN_IP: str = "10.99.0.1"
    TUN_NETMASK: str = "255.255.255.0"
    TUN_NETWORK: str = "10.99.0.0/24"
    
    # Session management
    SESSION_TIMEOUT: int = 30  # seconds
    KEEPALIVE_INTERVAL: int = 10  # seconds
    MAX_SESSIONS: int = 1000
    
    # UDP settings
    UDP_BUFFER_SIZE: int = 65536
    UDP_SOCKET_TIMEOUT: float = 0.5
    MAX_PACKET_SIZE: int = 1400  # MTU - overhead
    
    # Performance tuning
    BATCH_SIZE: int = 32  # packets per read/write batch
    RECV_BUFFER_SIZE: int = 2097152  # 2MB
    SEND_BUFFER_SIZE: int = 2097152  # 2MB
    
    # Security
    MIN_PACKET_SIZE: int = 4  # Minimum valid packet size
    MAX_RATE_PER_SESSION: int = 100  # packets per second
    
    # Debug
    DEBUG: bool = False
    LOG_PACKETS: bool = False

config = ServerConfig()
