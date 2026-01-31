"""
Network Scanner for discovering Klipper printers on the local network
Supports mDNS/Bonjour discovery and IP range scanning
"""

import asyncio
import socket
import struct
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
import aiohttp
import ipaddress


@dataclass
class DiscoveredPrinter:
    """Represents a discovered printer on the network"""
    name: str
    host: str
    port: int
    service_type: str  # 'moonraker', 'fluidd', 'mainsail'
    requires_auth: bool = False
    
    def __hash__(self):
        return hash((self.host, self.port))
    
    def __eq__(self, other):
        if isinstance(other, DiscoveredPrinter):
            return self.host == other.host and self.port == other.port
        return False


class NetworkScanner:
    """
    Scans the local network for Klipper printers running Moonraker
    """
    
    # Common ports for Moonraker/Fluidd/Mainsail
    MOONRAKER_PORTS = [7125]
    WEB_PORTS = [80, 443, 4408, 4409]  # Fluidd/Mainsail default ports
    
    def __init__(self):
        self._scanning = False
        self._cancel_scan = False
        self._discovered_printers: List[DiscoveredPrinter] = []
        
    def get_local_ip(self) -> Optional[str]:
        """Get the local IP address of this machine"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return None
    
    def get_network_range(self) -> Optional[ipaddress.IPv4Network]:
        """Get the local network range for scanning"""
        local_ip = self.get_local_ip()
        if not local_ip:
            return None
        
        # Assume /24 subnet (most common for home networks)
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return network
    
    async def check_moonraker(self, host: str, port: int = 7125, 
                               timeout: float = 2.0) -> Optional[DiscoveredPrinter]:
        """Check if a host is running Moonraker"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/printer/info"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'result' in data:
                            hostname = data.get('result', {}).get('hostname', host)
                            return DiscoveredPrinter(
                                name=hostname,
                                host=host,
                                port=port,
                                service_type='moonraker',
                                requires_auth=False
                            )
                    elif response.status == 401:
                        # Requires authentication
                        return DiscoveredPrinter(
                            name=host,
                            host=host,
                            port=port,
                            service_type='moonraker',
                            requires_auth=True
                        )
        except asyncio.TimeoutError:
            pass
        except aiohttp.ClientError:
            pass
        except Exception:
            pass
        return None
    
    async def check_web_interface(self, host: str, port: int,
                                   timeout: float = 2.0) -> Optional[str]:
        """Check if a host is running Fluidd or Mainsail web interface"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        text = await response.text()
                        if 'fluidd' in text.lower():
                            return 'fluidd'
                        elif 'mainsail' in text.lower():
                            return 'mainsail'
        except Exception:
            pass
        return None
    
    async def scan_host(self, host: str) -> List[DiscoveredPrinter]:
        """Scan a single host for Moonraker services"""
        results = []
        
        # Check Moonraker port
        for port in self.MOONRAKER_PORTS:
            printer = await self.check_moonraker(host, port)
            if printer:
                # Also check for web interface
                for web_port in self.WEB_PORTS:
                    interface = await self.check_web_interface(host, web_port)
                    if interface:
                        printer.service_type = interface
                        break
                results.append(printer)
                break
        
        return results
    
    async def scan_network(self, 
                           progress_callback: Optional[Callable[[int, int, str], None]] = None,
                           max_concurrent: int = 50) -> List[DiscoveredPrinter]:
        """
        Scan the local network for Klipper printers
        
        Args:
            progress_callback: Called with (current, total, message) during scan
            max_concurrent: Maximum number of concurrent connections
            
        Returns:
            List of discovered printers
        """
        self._scanning = True
        self._cancel_scan = False
        self._discovered_printers = []
        
        network = self.get_network_range()
        if not network:
            self._scanning = False
            return []
        
        hosts = list(network.hosts())
        total = len(hosts)
        
        if progress_callback:
            progress_callback(0, total, "Starting network scan...")
        
        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(host: str, index: int):
            if self._cancel_scan:
                return []
            async with semaphore:
                if progress_callback:
                    progress_callback(index, total, f"Scanning {host}...")
                return await self.scan_host(str(host))
        
        # Create tasks for all hosts
        tasks = [scan_with_semaphore(str(host), i) for i, host in enumerate(hosts)]
        
        # Run all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results
        for result in results:
            if isinstance(result, list):
                self._discovered_printers.extend(result)
        
        # Remove duplicates
        self._discovered_printers = list(set(self._discovered_printers))
        
        if progress_callback:
            progress_callback(total, total, f"Found {len(self._discovered_printers)} printer(s)")
        
        self._scanning = False
        return self._discovered_printers
    
    async def scan_specific_hosts(self, hosts: List[str]) -> List[DiscoveredPrinter]:
        """Scan specific hosts for Moonraker services"""
        self._discovered_printers = []
        
        tasks = [self.scan_host(host) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                self._discovered_printers.extend(result)
        
        return self._discovered_printers
    
    def cancel_scan(self):
        """Cancel the current network scan"""
        self._cancel_scan = True
    
    @property
    def is_scanning(self) -> bool:
        """Check if a scan is in progress"""
        return self._scanning
    
    @property
    def discovered_printers(self) -> List[DiscoveredPrinter]:
        """Get the list of discovered printers"""
        return self._discovered_printers


class MDNSDiscovery:
    """
    mDNS/Bonjour discovery for Klipper printers
    Discovers services advertising _moonraker._tcp or _http._tcp
    """
    
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    
    def __init__(self):
        self._discovered: List[DiscoveredPrinter] = []
    
    async def discover(self, timeout: float = 5.0) -> List[DiscoveredPrinter]:
        """
        Discover printers using mDNS
        
        Note: This is a simplified implementation. For full mDNS support,
        consider using the zeroconf library.
        """
        # For now, we'll rely on the IP scanning method
        # Full mDNS implementation would require the zeroconf library
        return []


async def auto_discover_printers(
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> List[DiscoveredPrinter]:
    """
    Convenience function to auto-discover printers on the network
    
    Args:
        progress_callback: Called with (current, total, message) during scan
        
    Returns:
        List of discovered printers
    """
    scanner = NetworkScanner()
    return await scanner.scan_network(progress_callback)
