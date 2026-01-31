"""
Authentication Manager for Fluidd/Mainsail/Moonraker
Handles user authentication and credential storage
"""

import json
import os
import base64
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp


@dataclass
class AuthCredentials:
    """Authentication credentials for a printer"""
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    auth_type: str = 'none'  # 'none', 'basic', 'api_key', 'bearer'
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthCredentials':
        return cls(**data)


class AuthManager:
    """
    Manages authentication for Moonraker/Fluidd/Mainsail
    Supports:
    - Basic authentication (username/password)
    - API key authentication
    - Bearer token authentication
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            # Default to user's config directory
            if os.name == 'nt':  # Windows
                config_dir = os.path.join(os.environ.get('APPDATA', ''), 'KlipperBuddy')
            else:  # Linux/Mac
                config_dir = os.path.join(os.path.expanduser('~'), '.config', 'klipperbuddy')
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = self.config_dir / 'credentials.json'
        self._credentials: Dict[str, AuthCredentials] = {}
        self._load_credentials()
    
    def _get_key(self, host: str, port: int) -> str:
        """Generate a unique key for host:port combination"""
        return f"{host}:{port}"
    
    def _load_credentials(self):
        """Load saved credentials from file"""
        if self.credentials_file.exists():
            try:
                with open(self.credentials_file, 'r') as f:
                    data = json.load(f)
                    for key, cred_data in data.items():
                        # Decode password if present
                        if cred_data.get('password'):
                            try:
                                cred_data['password'] = base64.b64decode(
                                    cred_data['password']
                                ).decode('utf-8')
                            except Exception:
                                pass
                        self._credentials[key] = AuthCredentials.from_dict(cred_data)
            except Exception as e:
                print(f"Error loading credentials: {e}")
    
    def _save_credentials(self):
        """Save credentials to file"""
        try:
            data = {}
            for key, cred in self._credentials.items():
                cred_dict = cred.to_dict()
                # Encode password for storage
                if cred_dict.get('password'):
                    cred_dict['password'] = base64.b64encode(
                        cred_dict['password'].encode('utf-8')
                    ).decode('utf-8')
                data[key] = cred_dict
            
            with open(self.credentials_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving credentials: {e}")
    
    def set_credentials(self, host: str, port: int, 
                        username: Optional[str] = None,
                        password: Optional[str] = None,
                        api_key: Optional[str] = None) -> AuthCredentials:
        """Set credentials for a printer"""
        key = self._get_key(host, port)
        
        # Determine auth type
        if api_key:
            auth_type = 'api_key'
        elif username and password:
            auth_type = 'basic'
        else:
            auth_type = 'none'
        
        cred = AuthCredentials(
            host=host,
            port=port,
            username=username,
            password=password,
            api_key=api_key,
            auth_type=auth_type
        )
        
        self._credentials[key] = cred
        self._save_credentials()
        return cred
    
    def get_credentials(self, host: str, port: int) -> Optional[AuthCredentials]:
        """Get credentials for a printer"""
        key = self._get_key(host, port)
        return self._credentials.get(key)
    
    def remove_credentials(self, host: str, port: int):
        """Remove credentials for a printer"""
        key = self._get_key(host, port)
        if key in self._credentials:
            del self._credentials[key]
            self._save_credentials()
    
    def get_auth_headers(self, host: str, port: int) -> Dict[str, str]:
        """Get authentication headers for HTTP requests"""
        cred = self.get_credentials(host, port)
        headers = {}
        
        if cred:
            if cred.auth_type == 'api_key' and cred.api_key:
                headers['X-Api-Key'] = cred.api_key
            elif cred.auth_type == 'basic' and cred.username and cred.password:
                auth_str = f"{cred.username}:{cred.password}"
                auth_bytes = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                headers['Authorization'] = f'Basic {auth_bytes}'
            elif cred.auth_type == 'bearer' and cred.api_key:
                headers['Authorization'] = f'Bearer {cred.api_key}'
        
        return headers
    
    async def test_authentication(self, host: str, port: int,
                                   username: Optional[str] = None,
                                   password: Optional[str] = None,
                                   api_key: Optional[str] = None) -> tuple[bool, str]:
        """
        Test authentication credentials against a Moonraker server
        
        Returns:
            Tuple of (success, message)
        """
        headers = {}
        
        if api_key:
            headers['X-Api-Key'] = api_key
        elif username and password:
            auth_str = f"{username}:{password}"
            auth_bytes = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            headers['Authorization'] = f'Basic {auth_bytes}'
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/printer/info"
                async with session.get(url, headers=headers, 
                                       timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                    if response.status == 200:
                        return True, "Authentication successful"
                    elif response.status == 401:
                        return False, "Invalid credentials"
                    elif response.status == 403:
                        return False, "Access forbidden"
                    else:
                        return False, f"Unexpected response: {response.status}"
        except aiohttp.ClientError as e:
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    async def login_moonraker(self, host: str, port: int,
                               username: str, password: str) -> tuple[bool, Optional[str]]:
        """
        Login to Moonraker and get an access token
        
        Returns:
            Tuple of (success, token or error message)
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/access/login"
                payload = {
                    "username": username,
                    "password": password
                }
                async with session.post(url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                    if response.status == 200:
                        data = await response.json()
                        token = data.get('result', {}).get('token')
                        if token:
                            # Save as bearer token
                            self.set_credentials(host, port, api_key=token)
                            return True, token
                        return False, "No token in response"
                    elif response.status == 401:
                        return False, "Invalid username or password"
                    else:
                        return False, f"Login failed: {response.status}"
        except Exception as e:
            return False, str(e)
    
    async def get_oneshot_token(self, host: str, port: int) -> Optional[str]:
        """Get a one-shot token for authentication"""
        headers = self.get_auth_headers(host, port)
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/access/oneshot_token"
                async with session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=5.0)) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('result')
        except Exception:
            pass
        return None
    
    def list_saved_printers(self) -> list[tuple[str, int]]:
        """List all printers with saved credentials"""
        return [(cred.host, cred.port) for cred in self._credentials.values()]
