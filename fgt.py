#!/usr/bin/env python3

import os
import sys
import json
import requests
from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize FastMCP server
mcp = FastMCP("FortiOS Firewall")

# Load environment variables
load_dotenv()

class FortiOSREST:
    """FortiOS REST API client based on the provided library."""
    
    def __init__(self):
        self._debug = False
        self._http_debug = False
        self._https = True
        self._session = requests.session()
        self._auth_token = None
        self._url_prefix = None
        self.log_session_id = None

    def jprint(self, json_obj):
        return json.dumps(json_obj, indent=2, sort_keys=True)

    def dprint(self, response):
        if self._debug:
            method = response.request.method
            url = response.request.url
            body = response.request.body

            print(f"\nREQUEST:\n{method}: {url}", file=sys.stderr)
            
            if self._http_debug:
                headers = response.request.headers
                for key, value in headers.items():
                    print(f"{key}: {value}", file=sys.stderr)

            if body is not None and body != 'null':
                try:
                    j = json.loads(body)
                    print(f"\n{json.dumps(j, indent=2, sort_keys=True)}", file=sys.stderr)
                except (ValueError, TypeError):
                    print(f"\n{body}", file=sys.stderr)

            print(f"\nRESPONSE:\n{response.status_code} {response.reason}", file=sys.stderr)
            
            if self._http_debug:
                headers = response.headers
                for key, value in headers.items():
                    print(f"{key}: {value}", file=sys.stderr)

            if response.content:
                try:
                    j = json.loads(response.content)
                    print(f"\n{json.dumps(j, indent=2, sort_keys=True)}", file=sys.stderr)
                except (ValueError, TypeError):
                    print(f"\n{response.content.decode()}", file=sys.stderr)

    def debug(self, status):
        self._debug = (status == 'on')

    def http_debug(self, status):
        self._http_debug = (status == 'on')

    def https(self, status):
        self._https = (status == 'on')

    def update_csrf(self):
        """Retrieve server csrf and update session's headers."""
        for cookie in self._session.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1]  # token stored as a list
                self._session.headers.update({'X-CSRFTOKEN': csrftoken})

    def url_prefix(self, host):
        if self._https:
            self._url_prefix = f'https://{host}'
        else:
            self._url_prefix = f'http://{host}'

    def login_token(self, host, token):
        """Login using API token."""
        self._auth_token = token
        self._session.headers.update({'Authorization': f'Bearer {token}'})
        self._session.verify = False
        self.url_prefix(host)

    def login(self, host, username, password, timeout=None, path='/logincheck'):
        """Login using username and password."""
        self.url_prefix(host)
        self._session.verify = False
        url = self._url_prefix + path
        
        data = f'username={username}&secretkey={password}'
        res = self._session.post(url, data=data, timeout=timeout)
        self.dprint(res)
        
        # Update session's csrftoken
        self.update_csrf()
        return res

    def logout(self, path='/logout'):
        """Logout from FortiGate."""
        url = self._url_prefix + path
        res = self._session.post(url)
        self.dprint(res)
        return res

    api_get_path = '/api/v2/'
    valid_apis = {'monitor', 'cmdb', 'log'}

    def get_url(self, api, path, name, action=None, mkey=None):
        """Construct API URL."""
        if api not in self.valid_apis:
            raise ValueError(f'Unknown API {api}. Valid APIs: {self.valid_apis}')

        url_postfix = self.api_get_path + api + '/' + path + '/' + name
        if action:
            url_postfix += '/' + action
        if mkey:
            url_postfix = url_postfix + '/' + str(mkey)
        url = self._url_prefix + url_postfix
        return url

    def get(self, api, path, name, action=None, mkey=None, parameters=None):
        """GET request to FortiGate API."""
        url = self.get_url(api, path, name, action, mkey)
        res = self._session.get(url, params=parameters)
        self.dprint(res)
        return res

    def post(self, api, path, name, action=None, mkey=None, parameters=None, data=None):
        """POST request to FortiGate API."""
        url = self.get_url(api, path, name, action, mkey)
        headers = {'Content-Type': 'application/json'}
        res = self._session.post(url, params=parameters, data=json.dumps(data), headers=headers)
        self.dprint(res)
        return res

    def put(self, api, path, name, action=None, mkey=None, parameters=None, data=None):
        """PUT request to FortiGate API."""
        url = self.get_url(api, path, name, action, mkey)
        headers = {'Content-Type': 'application/json'}
        res = self._session.put(url, params=parameters, data=json.dumps(data), headers=headers)
        self.dprint(res)
        return res

    def delete(self, api, path, name, action=None, mkey=None, parameters=None):
        """DELETE request to FortiGate API."""
        url = self.get_url(api, path, name, action, mkey)
        res = self._session.delete(url, params=parameters)
        self.dprint(res)
        return res


# Configuration from environment variables
def load_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    config = {
        'host_ip': os.getenv('FORTIOS_HOST_IP', ''),
        'host_port': os.getenv('FORTIOS_HOST_PORT', '443'),
        'username': os.getenv('FORTIOS_USERNAME', 'admin'),
        'password': os.getenv('FORTIOS_PASSWORD', ''),
        'api_token': os.getenv('FORTIOS_API_TOKEN', ''),
        'timeout': int(os.getenv('FORTIOS_TIMEOUT', '30'))
    }
    
    print("FortiOS Configuration loaded:", file=sys.stderr)
    print(f"  Host: {config['host_ip']}:{config['host_port']}", file=sys.stderr)
    print(f"  Username: {config['username']}", file=sys.stderr)
    print(f"  Password: {'Set' if config['password'] else 'NOT SET'}", file=sys.stderr)
    print(f"  API Token: {'Set' if config['api_token'] else 'NOT SET'}", file=sys.stderr)
    print(f"  Timeout: {config['timeout']}s", file=sys.stderr)
    
    return config

# Load configuration
CONFIG = load_config()

# Global FortiOS client instance
fortigate = FortiOSREST()

# Global state
session_data = {
    'authenticated': False,
    'auth_method': None,
    'connection_status': 'Not tested',
    'host': f"{CONFIG['host_ip']}:{CONFIG['host_port']}"
}

def format_response(response: requests.Response) -> Dict[str, Any]:
    """Format API response for display."""
    try:
        data = response.json() if response.content else {}
    except json.JSONDecodeError:
        data = {'raw_content': response.content.decode() if response.content else ''}
    
    return {
        'status_code': response.status_code,
        'success': response.status_code < 400,
        'data': data,
        'headers': dict(response.headers),
        'url': response.url
    }

def format_output(response_data: Dict[str, Any], title: str = "API Response") -> str:
    """Format response data for user display."""
    status_icon = "✅" if response_data['success'] else "❌"
    
    result = f"{status_icon} {title}\n"
    result += f"HTTP Status: {response_data['status_code']}\n"
    result += f"URL: {response_data['url']}\n\n"
    
    if 'data' in response_data and response_data['data']:
        result += "Response Data:\n"
        result += json.dumps(response_data['data'], indent=2)
    
    return result

@mcp.tool()
async def test_connection() -> str:
    """Test basic connectivity to the FortiGate firewall."""
    if not CONFIG['host_ip']:
        return "❌ No host IP configured. Set FORTIOS_HOST_IP environment variable."
    
    try:
        host = f"{CONFIG['host_ip']}:{CONFIG['host_port']}"
        
        # Test multiple endpoints to better diagnose issues
        test_urls = [
            f"https://{host}/api/v2/cmdb/system/global",
            f"https://{host}/api/v2/monitor/system/status",
            f"https://{host}/"  # Basic web interface
        ]
        
        results = []
        for url in test_urls:
            try:
                response = requests.get(url, verify=False, timeout=10)
                results.append(f"✅ {url} - HTTP {response.status_code}")
            except requests.ConnectionError:
                results.append(f"❌ {url} - Connection refused")
            except requests.Timeout:
                results.append(f"⏱️ {url} - Timeout")
            except Exception as e:
                results.append(f"⚠️ {url} - {str(e)}")
        
        if any("✅" in result for result in results):
            session_data['connection_status'] = "✅ Partially reachable"
            return f"""
🔗 Connection Test Results:
Host: {CONFIG['host_ip']}:{CONFIG['host_port']}

Results:
""" + "\n".join(f"   {result}" for result in results) + """

✅ At least one endpoint is reachable. Try authentication.
"""
        else:
            session_data['connection_status'] = "❌ All endpoints failed"
            return f"""
🔗 Connection Test Results:
❌ FortiGate IP: {CONFIG['host_ip']}
❌ Port: {CONFIG['host_port']}

All test endpoints failed:
""" + "\n".join(f"   {result}" for result in results) + """

Troubleshooting:
1. Verify the IP address is correct
2. Check if the FortiGate is powered on
3. Ensure network connectivity (try ping)
4. Verify HTTPS admin access is enabled
5. Check firewall rules allowing your IP
"""
            
    except Exception as e:
        session_data['connection_status'] = f"❌ Error: {str(e)}"
        return f"❌ Connection test failed: {str(e)}"

@mcp.tool()
async def get_status() -> str:
    """Get current connection and authentication status."""
    auth_status = "✅ Authenticated" if session_data['authenticated'] else "❌ Not authenticated"
    password_status = "✅ Set" if CONFIG['password'] else "❌ Not set"
    token_status = "✅ Set" if CONFIG['api_token'] else "❌ Not set"
    
    return f"""
📊 FortiOS Firewall Status
🔗 Connection:
   • Host: {CONFIG['host_ip']}:{CONFIG['host_port']}
   • Status: {session_data['connection_status']}
   • Timeout: {CONFIG['timeout']}s

🔐 Authentication:
   • Username: {CONFIG['username']}
   • Password: {password_status}
   • API Token: {token_status}
   • Status: {auth_status}
   • Method: {session_data['auth_method'] or 'None'}

⚙️ Environment Variables:
   Set these before running:
   • FORTIOS_HOST_IP={CONFIG['host_ip']}
   • FORTIOS_HOST_PORT={CONFIG['host_port']}
   • FORTIOS_USERNAME={CONFIG['username']}
   • FORTIOS_PASSWORD={'***' if CONFIG['password'] else 'NOT SET'}
   • FORTIOS_API_TOKEN={'***' if CONFIG['api_token'] else 'NOT SET'}
   • FORTIOS_TIMEOUT={CONFIG['timeout']}

💡 Quick Start:
   1. test_connection() - Test connectivity
   2. authenticate() - Log in (uses token if available, otherwise username/password)
   3. Use other tools once authenticated
"""



@mcp.tool()
async def authenticate() -> str:
    """Authenticate with the FortiGate firewall."""
    host = f"{CONFIG['host_ip']}:{CONFIG['host_port']}"
    
    # Try API token authentication first if available
    if CONFIG['api_token']:
        try:
            fortigate.login_token(host, CONFIG['api_token'])
            
            # Test the authentication
            response = fortigate.get('monitor', 'system', 'status')
            response_data = format_response(response)
            
            if response_data['success']:
                session_data['authenticated'] = True
                session_data['auth_method'] = 'API Token'
                session_data['connection_status'] = "✅ Authenticated via API Token"
                
                return f"""
🔐 Authentication Results:
✅ Successfully authenticated using API Token
🔑 Method: API Token
🌐 Connection: {session_data['connection_status']}

{format_output(response_data, "Authentication Test")}
"""
            else:
                return f"""
🔐 API Token Authentication Failed:
❌ Token authentication failed
{format_output(response_data, "Authentication Error")}
"""
                
        except Exception as e:
            return f"❌ API Token authentication failed: {str(e)}"
    
    # Fall back to username/password authentication
    elif CONFIG['password']:
        try:
            response = fortigate.login(host, CONFIG['username'], CONFIG['password'], 
                                     timeout=CONFIG['timeout'])
            response_data = format_response(response)
            
            if response_data['success']:
                session_data['authenticated'] = True
                session_data['auth_method'] = 'Username/Password'
                session_data['connection_status'] = "✅ Authenticated via Username/Password"
                
                return f"""
🔐 Authentication Results:
✅ Successfully authenticated as {CONFIG['username']}
🔑 Method: Username/Password
🌐 Connection: {session_data['connection_status']}

{format_output(response_data, "Login Response")}
"""
            else:
                session_data['authenticated'] = False
                return f"""
🔐 Authentication Failed:
❌ Could not authenticate as {CONFIG['username']}
{format_output(response_data, "Login Error")}

Troubleshooting:
1. Verify username and password
2. Check admin account is enabled
3. Ensure your IP is allowed in admin access settings
"""
                
        except Exception as e:
            session_data['authenticated'] = False
            return f"❌ Username/Password authentication failed: {str(e)}"
    
    else:
        return """
❌ No authentication credentials configured.
Set either:
• FORTIOS_API_TOKEN environment variable (recommended), or
• FORTIOS_PASSWORD environment variable for username/password auth
"""

@mcp.tool()
async def logout() -> str:
    """Logout from the FortiGate firewall."""
    if not session_data['authenticated']:
        return "❌ Not currently authenticated"
    
    try:
        if session_data['auth_method'] == 'Username/Password':
            response = fortigate.logout()
            response_data = format_response(response)
            
            session_data['authenticated'] = False
            session_data['auth_method'] = None
            session_data['connection_status'] = "Logged out"
            
            return f"""
🔐 Logout Results:
✅ Successfully logged out
{format_output(response_data, "Logout Response")}
"""
        else:
            # For API token, just clear the session
            session_data['authenticated'] = False
            session_data['auth_method'] = None
            session_data['connection_status'] = "Logged out"
            
            return "✅ API token session cleared"
            
    except Exception as e:
        return f"❌ Logout failed: {str(e)}"

@mcp.tool()
async def get_system_status() -> str:
    """Get FortiGate system status information."""
    if not session_data['authenticated']:
        return "❌ Not authenticated. Run authenticate() first."
    
    try:
        response = fortigate.get('monitor', 'system', 'status')
        response_data = format_response(response)
        
        return format_output(response_data, "System Status")
        
    except Exception as e:
        return f"❌ Failed to get system status: {str(e)}"

@mcp.tool()
async def get_config(api: str, path: str, name: str, action: str = None, mkey: str = None, 
                    parameters: Dict[str, Any] = None) -> str:
    """Get configuration from FortiGate.
    
    Args:
        api: API type ('monitor', 'cmdb', 'log')
        path: API path (e.g., 'system', 'firewall')
        name: Configuration name (e.g., 'global', 'policy')
        action: Optional action
        mkey: Optional key for specific object
        parameters: Optional query parameters
    """
    if not session_data['authenticated']:
        return "❌ Not authenticated. Run authenticate() first."
    
    try:
        response = fortigate.get(api, path, name, action=action, mkey=mkey, parameters=parameters)
        response_data = format_response(response)
        
        return format_output(response_data, f"Get {api}/{path}/{name} Configuration")
        
    except Exception as e:
        return f"❌ Failed to get configuration: {str(e)}"

@mcp.tool()
async def set_config(api: str, path: str, name: str, data: Dict[str, Any], 
                    action: str = None, mkey: str = None, parameters: Dict[str, Any] = None) -> str:
    """Set configuration on FortiGate.
    
    Args:
        api: API type ('cmdb' for configuration changes)
        path: API path (e.g., 'system', 'firewall')
        name: Configuration name (e.g., 'global', 'policy')
        data: Configuration data to set
        action: Optional action
        mkey: Optional key for specific object
        parameters: Optional query parameters
    """
    if not session_data['authenticated']:
        return "❌ Not authenticated. Run authenticate() first."
    
    try:
        response = fortigate.put(api, path, name, action=action, mkey=mkey, 
                               parameters=parameters, data=data)
        response_data = format_response(response)
        
        return format_output(response_data, f"Set {api}/{path}/{name} Configuration")
        
    except Exception as e:
        return f"❌ Failed to set configuration: {str(e)}"

@mcp.tool()
async def create_config(api: str, path: str, name: str, data: Dict[str, Any], 
                       parameters: Dict[str, Any] = None) -> str:
    """Create new configuration object on FortiGate.
    
    Args:
        api: API type ('cmdb' for configuration changes)
        path: API path (e.g., 'system', 'firewall')
        name: Configuration name (e.g., 'policy', 'address')
        data: Configuration data for new object
        parameters: Optional query parameters
    """
    if not session_data['authenticated']:
        return "❌ Not authenticated. Run authenticate() first."
    
    try:
        response = fortigate.post(api, path, name, parameters=parameters, data=data)
        response_data = format_response(response)
        
        return format_output(response_data, f"Create {api}/{path}/{name} Object")
        
    except Exception as e:
        return f"❌ Failed to create configuration: {str(e)}"

@mcp.tool()
async def delete_config(api: str, path: str, name: str, mkey: str, 
                       parameters: Dict[str, Any] = None) -> str:
    """Delete configuration object from FortiGate.
    
    Args:
        api: API type ('cmdb' for configuration changes)
        path: API path (e.g., 'system', 'firewall')
        name: Configuration name (e.g., 'policy', 'address')
        mkey: Key of the object to delete
        parameters: Optional query parameters
    """
    if not session_data['authenticated']:
        return "❌ Not authenticated. Run authenticate() first."
    
    try:
        response = fortigate.delete(api, path, name, mkey=mkey, parameters=parameters)
        response_data = format_response(response)
        
        return format_output(response_data, f"Delete {api}/{path}/{name}/{mkey}")
        
    except Exception as e:
        return f"❌ Failed to delete configuration: {str(e)}"

@mcp.tool()
async def get_firewall_policies() -> str:
    """Get all firewall policies."""
    return await get_config('cmdb', 'firewall', 'policy')

@mcp.tool()
async def get_firewall_addresses() -> str:
    """Get all firewall address objects."""
    return await get_config('cmdb', 'firewall', 'address')

@mcp.tool()
async def get_interface_info() -> str:
    """Get interface information."""
    return await get_config('cmdb', 'system', 'interface')

@mcp.tool()
async def get_routing_table() -> str:
    """Get routing table information."""
    return await get_config('monitor', 'router', 'routing-table')

@mcp.tool()
async def update_credentials(host_ip: str = None, host_port: str = None, 
                           username: str = None, password: str = None, 
                           api_token: str = None, timeout: int = None) -> str:
    """Update connection credentials at runtime.
    
    Args:
        host_ip: New FortiGate IP
        host_port: New FortiGate port
        username: New username
        password: New password
        api_token: New API token
        timeout: New timeout value
    """
    global CONFIG
    
    changes = []
    if host_ip:
        CONFIG['host_ip'] = host_ip
        changes.append(f"Host IP: {host_ip}")
    if host_port:
        CONFIG['host_port'] = host_port
        changes.append(f"Host Port: {host_port}")
    if username:
        CONFIG['username'] = username
        changes.append(f"Username: {username}")
    if password:
        CONFIG['password'] = password
        changes.append("Password: Updated")
    if api_token:
        CONFIG['api_token'] = api_token
        changes.append("API Token: Updated")
    if timeout:
        CONFIG['timeout'] = timeout
        changes.append(f"Timeout: {timeout}s")
    
    # Reset auth status
    session_data['authenticated'] = False
    session_data['auth_method'] = None
    session_data['connection_status'] = "Credentials updated - not tested"
    session_data['host'] = f"{CONFIG['host_ip']}:{CONFIG['host_port']}"
    
    if changes:
        return "✅ Updated:\n" + "\n".join(f"   • {change}" for change in changes) + "\n\n⚠️ Run authenticate() to log in with new credentials"
    else:
        return "No changes made - no parameters provided"

@mcp.tool()
async def enable_debug(http_debug: bool = False) -> str:
    """Enable debug logging for API requests.
    
    Args:
        http_debug: Enable detailed HTTP debug logging
    """
    fortigate.debug('on')
    if http_debug:
        fortigate.http_debug('on')
    
    debug_status = "✅ Debug logging enabled"
    if http_debug:
        debug_status += " (including HTTP details)"
    
    return debug_status

@mcp.tool()
async def disable_debug() -> str:
    """Disable debug logging for API requests."""
    fortigate.debug('off')
    fortigate.http_debug('off')
    
    return "✅ Debug logging disabled"

if __name__ == "__main__":
    print("🚀 Starting FortiOS MCP Server...", file=sys.stderr)
    print(f"📡 Host: {CONFIG['host_ip']}:{CONFIG['host_port']}", file=sys.stderr)
    print(f"👤 Username: {CONFIG['username']}", file=sys.stderr)
    print(f"🔑 Password: {'Configured' if CONFIG['password'] else 'NOT SET'}", file=sys.stderr)
    print(f"🎫 API Token: {'Configured' if CONFIG['api_token'] else 'NOT SET'}", file=sys.stderr)
    print(f"⏱️  Timeout: {CONFIG['timeout']}s", file=sys.stderr)
    print("", file=sys.stderr)
    
    mcp.run(transport='stdio')