"""
Moonraker API Client for KlipperBuddy
Handles communication with Klipper printers via Moonraker API
Supports authentication for Fluidd/Mainsail
"""

import asyncio
import json
import logging
import base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, Dict

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class PrinterStatus:
    """Current printer status from Moonraker"""
    connected: bool = False
    state: str = "unknown"  # ready, startup, error, shutdown
    state_message: str = ""
    
    # Print job info
    filename: Optional[str] = None
    progress: float = 0.0
    print_duration: float = 0.0
    total_duration: float = 0.0
    filament_used: float = 0.0
    
    # Temperatures
    extruder_temp: float = 0.0
    extruder_target: float = 0.0
    bed_temp: float = 0.0
    bed_target: float = 0.0
    
    # Position
    position: list = field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0])
    
    # Speeds
    speed: float = 0.0
    speed_factor: float = 1.0
    
    # Fan
    fan_speed: float = 0.0
    
    # Firmware
    software_version: str = ""
    hostname: str = ""
    
    # Raw data for additional info
    raw_data: dict = field(default_factory=dict)


@dataclass
class PrintJob:
    """Print job history entry"""
    job_id: str
    filename: str
    status: str  # completed, cancelled, error, in_progress
    start_time: datetime
    end_time: Optional[datetime]
    print_duration: float
    total_duration: float
    filament_used: float
    metadata: dict = field(default_factory=dict)


class MoonrakerClient:
    """Async client for Moonraker API with authentication support"""
    
    def __init__(self, host: str, port: int = 7125, 
                 api_key: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.username = username
        self.password = password
        self.base_url = f"http://{host}:{port}"
        self._session: Optional[aiohttp.ClientSession] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._ws_callbacks: list[Callable] = []
        self._connected = False
        self._auth_token: Optional[str] = None
        self._requires_auth = False
        
    @property
    def is_connected(self) -> bool:
        return self._connected
    
    @property
    def requires_auth(self) -> bool:
        return self._requires_auth
    
    def set_credentials(self, username: Optional[str] = None, 
                        password: Optional[str] = None,
                        api_key: Optional[str] = None):
        """Update authentication credentials"""
        self.username = username
        self.password = password
        self.api_key = api_key
        self._auth_token = None  # Reset token when credentials change
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests"""
        headers = {}
        
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        elif self.api_key:
            headers["X-Api-Key"] = self.api_key
        elif self.username and self.password:
            auth_str = f"{self.username}:{self.password}"
            auth_bytes = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            headers["Authorization"] = f"Basic {auth_bytes}"
        
        return headers
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = self._get_auth_headers()
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session
    
    async def _recreate_session(self):
        """Recreate session with updated headers"""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        return await self._get_session()
        
    async def close(self):
        """Close all connections"""
        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._session and not self._session.closed:
            await self._session.close()
        self._connected = False
            
    async def _request(self, method: str, endpoint: str, **kwargs) -> Optional[dict]:
        """Make HTTP request to Moonraker"""
        session = await self._get_session()
        url = f"{self.base_url}{endpoint}"
        
        # Add auth headers to this specific request
        headers = kwargs.pop('headers', {})
        headers.update(self._get_auth_headers())
        
        try:
            async with session.request(method, url, headers=headers, **kwargs) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("result", data)
                elif response.status == 401:
                    self._requires_auth = True
                    logger.warning(f"Authentication required for {self.host}:{self.port}")
                    return None
                elif response.status == 403:
                    logger.error(f"Access forbidden: {await response.text()}")
                    return None
                else:
                    logger.error(f"Request failed: {response.status} - {await response.text()}")
                    return None
        except aiohttp.ClientError as e:
            logger.error(f"Connection error: {e}")
            self._connected = False
            return None
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None
    
    async def login(self) -> bool:
        """
        Login to Moonraker using username/password
        Returns True if login successful or not required
        """
        if not self.username or not self.password:
            return True  # No credentials provided, might not need auth
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/access/login"
                payload = {
                    "username": self.username,
                    "password": self.password
                }
                async with session.post(url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._auth_token = data.get('result', {}).get('token')
                        if self._auth_token:
                            # Recreate session with new token
                            await self._recreate_session()
                            logger.info(f"Successfully logged in to {self.host}:{self.port}")
                            return True
                    elif response.status == 401:
                        logger.error("Invalid username or password")
                    else:
                        logger.error(f"Login failed: {response.status}")
        except Exception as e:
            logger.error(f"Login error: {e}")
        
        return False
    
    async def check_auth_required(self) -> bool:
        """Check if authentication is required"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/printer/info"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3.0)) as response:
                    if response.status == 401:
                        self._requires_auth = True
                        return True
                    elif response.status == 200:
                        self._requires_auth = False
                        return False
        except Exception:
            pass
        return False
            
    async def connect(self) -> bool:
        """Test connection to Moonraker"""
        try:
            # First check if auth is required
            await self.check_auth_required()
            
            # If auth required and we have credentials, login first
            if self._requires_auth and (self.username and self.password):
                if not await self.login():
                    return False
            
            result = await self._request("GET", "/printer/info")
            if result:
                self._connected = True
                logger.info(f"Connected to Moonraker at {self.host}:{self.port}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
            
    async def get_printer_info(self) -> Optional[dict]:
        """Get Klippy host information"""
        return await self._request("GET", "/printer/info")
        
    async def get_printer_status(self) -> PrinterStatus:
        """Get comprehensive printer status"""
        status = PrinterStatus()
        
        # Get printer info
        info = await self.get_printer_info()
        if info:
            status.connected = True
            status.state = info.get("state", "unknown")
            status.state_message = info.get("state_message", "")
            status.software_version = info.get("software_version", "")
            status.hostname = info.get("hostname", "")
        else:
            return status
            
        # Query printer objects
        objects = {
            "print_stats": None,
            "extruder": None,
            "heater_bed": None,
            "toolhead": None,
            "gcode_move": None,
            "fan": None,
            "virtual_sdcard": None
        }
        
        result = await self._request(
            "POST", 
            "/printer/objects/query",
            json={"objects": objects}
        )
        
        if result and "status" in result:
            data = result["status"]
            status.raw_data = data
            
            # Print stats
            if "print_stats" in data:
                ps = data["print_stats"]
                status.filename = ps.get("filename")
                status.print_duration = ps.get("print_duration", 0.0)
                status.total_duration = ps.get("total_duration", 0.0)
                status.filament_used = ps.get("filament_used", 0.0)
                
            # Virtual SD card for progress
            if "virtual_sdcard" in data:
                vsd = data["virtual_sdcard"]
                status.progress = vsd.get("progress", 0.0) * 100
                
            # Extruder
            if "extruder" in data:
                ext = data["extruder"]
                status.extruder_temp = ext.get("temperature", 0.0)
                status.extruder_target = ext.get("target", 0.0)
                
            # Heater bed
            if "heater_bed" in data:
                bed = data["heater_bed"]
                status.bed_temp = bed.get("temperature", 0.0)
                status.bed_target = bed.get("target", 0.0)
                
            # Toolhead
            if "toolhead" in data:
                th = data["toolhead"]
                status.position = th.get("position", [0, 0, 0, 0])
                
            # GCode move
            if "gcode_move" in data:
                gm = data["gcode_move"]
                status.speed = gm.get("speed", 0.0)
                status.speed_factor = gm.get("speed_factor", 1.0)
                
            # Fan
            if "fan" in data:
                fan = data["fan"]
                status.fan_speed = fan.get("speed", 0.0) * 100
                
        return status
        
    async def get_job_history(self, limit: int = 50, start: int = 0) -> list[PrintJob]:
        """Get print job history"""
        result = await self._request(
            "GET",
            f"/server/history/list?limit={limit}&start={start}"
        )
        
        jobs = []
        if result and "jobs" in result:
            for job_data in result["jobs"]:
                job = PrintJob(
                    job_id=job_data.get("job_id", ""),
                    filename=job_data.get("filename", ""),
                    status=job_data.get("status", "unknown"),
                    start_time=datetime.fromtimestamp(job_data.get("start_time", 0)),
                    end_time=datetime.fromtimestamp(job_data["end_time"]) if job_data.get("end_time") else None,
                    print_duration=job_data.get("print_duration", 0.0),
                    total_duration=job_data.get("total_duration", 0.0),
                    filament_used=job_data.get("filament_used", 0.0),
                    metadata=job_data.get("metadata", {})
                )
                jobs.append(job)
                
        return jobs
        
    async def get_job_totals(self) -> Optional[dict]:
        """Get job totals statistics"""
        return await self._request("GET", "/server/history/totals")
        
    async def get_files(self, root: str = "gcodes") -> list[dict]:
        """Get list of files"""
        result = await self._request("GET", f"/server/files/list?root={root}")
        return result if result else []
        
    async def get_file_metadata(self, filename: str) -> Optional[dict]:
        """Get metadata for a specific file"""
        return await self._request("GET", f"/server/files/metadata?filename={filename}")
        
    # Printer Control
    async def emergency_stop(self) -> bool:
        """Emergency stop the printer"""
        result = await self._request("POST", "/printer/emergency_stop")
        return result == "ok"
        
    async def restart(self) -> bool:
        """Restart Klippy"""
        result = await self._request("POST", "/printer/restart")
        return result == "ok"
        
    async def firmware_restart(self) -> bool:
        """Firmware restart"""
        result = await self._request("POST", "/printer/firmware_restart")
        return result == "ok"
        
    # Print Job Control
    async def start_print(self, filename: str) -> bool:
        """Start a print job"""
        result = await self._request("POST", f"/printer/print/start?filename={filename}")
        return result == "ok"
        
    async def pause_print(self) -> bool:
        """Pause current print"""
        result = await self._request("POST", "/printer/print/pause")
        return result == "ok"
        
    async def resume_print(self) -> bool:
        """Resume paused print"""
        result = await self._request("POST", "/printer/print/resume")
        return result == "ok"
        
    async def cancel_print(self) -> bool:
        """Cancel current print"""
        result = await self._request("POST", "/printer/print/cancel")
        return result == "ok"
        
    # GCode
    async def run_gcode(self, script: str) -> bool:
        """Run a GCode command"""
        result = await self._request(
            "POST",
            "/printer/gcode/script",
            json={"script": script}
        )
        return result == "ok"
        
    # Temperature Control
    async def set_extruder_temp(self, temp: float) -> bool:
        """Set extruder temperature"""
        return await self.run_gcode(f"SET_HEATER_TEMPERATURE HEATER=extruder TARGET={temp}")
        
    async def set_bed_temp(self, temp: float) -> bool:
        """Set bed temperature"""
        return await self.run_gcode(f"SET_HEATER_TEMPERATURE HEATER=heater_bed TARGET={temp}")
        
    # Webcam
    async def get_webcam_info(self) -> Optional[dict]:
        """Get webcam configuration"""
        return await self._request("GET", "/server/webcams/list")
        
    async def get_webcam_snapshot(self, cam_name: str = "webcam") -> Optional[bytes]:
        """Get webcam snapshot"""
        session = await self._get_session()
        try:
            async with session.get(f"{self.base_url}/webcam/?action=snapshot") as response:
                if response.status == 200:
                    return await response.read()
        except Exception as e:
            logger.error(f"Failed to get webcam snapshot: {e}")
        return None
    
    # Access Control
    async def get_user_info(self) -> Optional[dict]:
        """Get current user information"""
        return await self._request("GET", "/access/user")
    
    async def logout(self) -> bool:
        """Logout from Moonraker"""
        result = await self._request("POST", "/access/logout")
        if result:
            self._auth_token = None
            await self._recreate_session()
            return True
        return False
    
    async def refresh_token(self) -> bool:
        """Refresh the authentication token"""
        result = await self._request("POST", "/access/refresh_jwt")
        if result and 'token' in result:
            self._auth_token = result['token']
            await self._recreate_session()
            return True
        return False
