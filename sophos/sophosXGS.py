import os
import sys
import httpx
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

# Initialise FastMCP server
mcp = FastMCP("Sophos XGS Firewall")

# Initialise Environment Vars
load_dotenv() 

# Configuration from environment variables
def load_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    config = {
        'host_ip': os.getenv('SOPHOS_HOST_IP', '192.168.1.1'),
        'host_port': os.getenv('SOPHOS_HOST_PORT', '4444'),
        'username': os.getenv('SOPHOS_USERNAME', 'admin'),
        'password': os.getenv('SOPHOS_PASSWORD', '')
    }
    
    print(f"Sophos XGS Configuration loaded:", file=sys.stderr)
    print(f"  Host: {config['host_ip']}:{config['host_port']}", file=sys.stderr)
    print(f"  Username: {config['username']}", file=sys.stderr)
    print(f"  Password: {'Set' if config['password'] else 'NOT SET'}", file=sys.stderr)
    
    return config

# Load configuration
CONFIG = load_config()
API_BASE_URL = f"https://{CONFIG['host_ip']}:{CONFIG['host_port']}/webconsole/APIController"

# Global state
session_data = {
    'authenticated': False,
    'session_token': None,
    'connection_status': 'Not tested'
}

def create_login_xml() -> str:
    """Create XML for authentication request."""
    return f"""<Request APIVersion="2000.2">
    <Login>
        <Username>{CONFIG['username']}</Username>
        <Password>{CONFIG['password']}</Password>
    </Login>
</Request>"""

def create_live_user_login_xml(username: str, password: str, ip_address: str, mac_address: str = "") -> str:
    """Create XML for live user login."""
    return f"""<Request APIVersion="2000.2">
    <LiveUserLogin>
        <UserName>{username}</UserName>
        <Password>{password}</Password>
        <IPAddress>{ip_address}</IPAddress>
        <MacAddress>{mac_address}</MacAddress>
    </LiveUserLogin>
</Request>"""

def create_live_user_logout_xml(username: str) -> str:
    """Create XML for live user logout."""
    return f"""<Request APIVersion="2000.2">
    <LiveUserLogout>
        <Admin>
            <UserName>{CONFIG['username']}</UserName>
            <Password>{CONFIG['password']}</Password>
        </Admin>
        <UserName>{username}</UserName>
    </LiveUserLogout>
</Request>"""

def create_get_config_xml(entity_type: str) -> str:
    """Create XML for getting configuration."""
    return f"""<Request APIVersion="2000.2">
    <Get>
        <{entity_type}/>
    </Get>
</Request>"""

def create_set_config_xml(config_xml: str) -> str:
    """Create XML for setting configuration."""
    return f"""<Request APIVersion="2000.2">
    <Set>
        {config_xml}
    </Set>
</Request>"""

def parse_xml_response(xml_text: str) -> Dict[str, Any]:
    """Parse XML response and extract information."""
    result = {
        'success': False,
        'message': 'Unknown response',
        'session_token': None,
        'xml': xml_text
    }
    
    try:
        # Check for common success patterns in text
        lower_xml = xml_text.lower()
        if 'authentication successful' in lower_xml:
            result['success'] = True
            result['message'] = 'Authentication successful'
        elif 'login successful' in lower_xml:
            result['success'] = True
            result['message'] = 'Login successful'
        elif 'error' in lower_xml or 'failed' in lower_xml:
            result['success'] = False
            result['message'] = 'Request failed - see XML response'
        else:
            # Try to parse as XML
            root = ET.fromstring(xml_text)
            
            # Look for status elements
            for elem in root.iter():
                if 'status' in elem.tag.lower() and elem.text:
                    if 'success' in elem.text.lower():
                        result['success'] = True
                        result['message'] = elem.text
                    else:
                        result['message'] = elem.text
                
                # Look for session tokens
                if 'token' in elem.tag.lower() or 'session' in elem.tag.lower():
                    result['session_token'] = elem.text
            
            # If we got valid XML but no clear status, assume success
            if result['message'] == 'Unknown response':
                result['success'] = True
                result['message'] = 'Request completed successfully'
                
    except ET.ParseError:
        # If XML parsing fails, check for text indicators
        if 'success' in xml_text.lower():
            result['success'] = True
            result['message'] = 'Operation completed'
        else:
            result['success'] = False
            result['message'] = 'Invalid XML response'
    
    return result

async def send_api_request(xml_payload: str) -> Dict[str, Any]:
    """Send request to Sophos API."""
    headers = {
        "User-Agent": "sophos-mcp/1.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {"reqxml": xml_payload}
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.post(API_BASE_URL, headers=headers, data=data)
            response.raise_for_status()
            
            session_data['connection_status'] = f"Connected - HTTP {response.status_code}"
            
            parsed = parse_xml_response(response.text)
            
            return {
                'status': 'success',
                'http_code': response.status_code,
                'response_text': response.text,
                'parsed': parsed
            }
            
    except httpx.ConnectError as e:
        session_data['connection_status'] = f"Connection failed: {str(e)}"
        return {
            'status': 'connection_error',
            'error': f"Cannot connect to firewall: {str(e)}",
            'response_text': None
        }
    except httpx.HTTPStatusError as e:
        session_data['connection_status'] = f"HTTP {e.response.status_code}"
        return {
            'status': 'http_error', 
            'error': f"HTTP {e.response.status_code}: {e.response.text}",
            'response_text': e.response.text
        }
    except httpx.TimeoutException:
        session_data['connection_status'] = "Timeout"
        return {
            'status': 'timeout',
            'error': "Request timed out",
            'response_text': None
        }
    except Exception as e:
        session_data['connection_status'] = f"Error: {str(e)}"
        return {
            'status': 'error',
            'error': f"Unexpected error: {str(e)}",
            'response_text': None
        }

def format_response(response: Dict[str, Any]) -> str:
    """Format API response for display."""
    if response['status'] != 'success':
        return f"❌ {response['error']}\nConnection Status: {session_data['connection_status']}"
    
    parsed = response['parsed']
    status_icon = "✅" if parsed['success'] else "❌"
    
    result = f"{status_icon} {parsed['message']}\n"
    result += f"HTTP Status: {response['http_code']}\n"
    
    if parsed['session_token']:
        result += f"Session Token: {parsed['session_token']}\n"
        session_data['session_token'] = parsed['session_token']
    
    result += f"\nXML Response:\n{response['response_text']}"
    
    return result

@mcp.tool()
async def get_status() -> str:
    """Get current connection and authentication status."""
    auth_status = "✅ Authenticated" if session_data['authenticated'] else "❌ Not authenticated"
    password_status = "✅ Set" if CONFIG['password'] else "❌ Not set"
    
    return f"""
📊 Sophos XGS Firewall Status

🔗 Connection:
   • Host: {CONFIG['host_ip']}:{CONFIG['host_port']}
   • API Endpoint: {API_BASE_URL}
   • Status: {session_data['connection_status']}

🔐 Authentication:
   • Username: {CONFIG['username']}
   • Password: {password_status}
   • Status: {auth_status}
   • Session Token: {session_data['session_token'] or 'None'}

⚙️ Environment Variables:
   Set these before running:
   • SOPHOS_HOST_IP={CONFIG['host_ip']}
   • SOPHOS_HOST_PORT={CONFIG['host_port']}
   • SOPHOS_USERNAME={CONFIG['username']}
   • SOPHOS_PASSWORD={'***' if CONFIG['password'] else 'NOT SET'}

💡 Quick Start:
   1. test_connection() - Test connectivity
   2. authenticate() - Log in
   3. Use other tools once authenticated
"""

@mcp.tool()
async def test_connection() -> str:
    """Test basic connectivity to the Sophos firewall."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.get(f"https://{CONFIG['host_ip']}:{CONFIG['host_port']}/")
            session_data['connection_status'] = f"✅ Reachable - HTTP {response.status_code}"
            
            return f"""
🔗 Connection Test Results:
✅ Firewall IP: {CONFIG['host_ip']}
✅ Port: {CONFIG['host_port']}
✅ HTTPS Endpoint: Reachable
📊 HTTP Status: {response.status_code}
🌐 Response Size: {len(response.content)} bytes

Status: Ready for API authentication
Next: Run authenticate() to log in
"""
    except httpx.ConnectError as e:
        session_data['connection_status'] = f"❌ Connection failed"
        return f"""
🔗 Connection Test Results:
❌ Firewall IP: {CONFIG['host_ip']}
❌ Port: {CONFIG['host_port']}
🚫 Error: {str(e)}

Troubleshooting:
1. Verify firewall IP and port
2. Check network connectivity  
3. Ensure web admin is enabled
4. Add your IP to allowed API addresses
"""
    except Exception as e:
        session_data['connection_status'] = f"❌ Error: {str(e)}"
        return f"❌ Connection test failed: {str(e)}"

@mcp.tool() 
async def authenticate() -> str:
    """Authenticate with the Sophos firewall."""
    if not CONFIG['password']:
        return "❌ Password not configured. Set SOPHOS_PASSWORD environment variable."
    
    xml_request = create_login_xml()
    response = await send_api_request(xml_request)
    
    if response['status'] == 'success' and response['parsed']['success']:
        session_data['authenticated'] = True
        if response['parsed']['session_token']:
            session_data['session_token'] = response['parsed']['session_token']
        
        return f"""
🔐 Authentication Results:
✅ Successfully authenticated as {CONFIG['username']}
🔑 Session Token: {session_data['session_token'] or 'Not provided'}
🌐 Connection: {session_data['connection_status']}

{format_response(response)}
"""
    else:
        session_data['authenticated'] = False
        return f"""
🔐 Authentication Failed:
❌ Could not authenticate as {CONFIG['username']}

{format_response(response)}

Troubleshooting:
1. Verify username and password
2. Check admin account is enabled
3. Ensure IP is in allowed API addresses
"""

@mcp.tool()
async def live_user_login(username: str, password: str, ip_address: str, mac_address: str = "") -> str:
    """Sign in a live user through the API.
    
    Args:
        username: Username for the live user
        password: Password for the live user
        ip_address: IP address of the user
        mac_address: MAC address (optional)
    """
    xml_request = create_live_user_login_xml(username, password, ip_address, mac_address)
    response = await send_api_request(xml_request)
    
    if response['status'] == 'success' and response['parsed']['success']:
        return f"✅ Live user '{username}' logged in successfully\n\n{format_response(response)}"
    else:
        return f"❌ Live user login failed for '{username}'\n\n{format_response(response)}"

@mcp.tool()
async def live_user_logout(username: str) -> str:
    """Sign out a live user through the API.
    
    Args:
        username: Username to sign out
    """
    xml_request = create_live_user_logout_xml(username)
    response = await send_api_request(xml_request)
    
    if response['status'] == 'success' and response['parsed']['success']:
        return f"✅ Live user '{username}' logged out successfully\n\n{format_response(response)}"
    else:
        return f"❌ Live user logout failed for '{username}'\n\n{format_response(response)}"

@mcp.tool()
async def get_config(entity_type: str = "FirewallRule") -> str:
    """Get firewall configuration.
    
    Args:
        entity_type: Configuration type (e.g., FirewallRule, User, Policy)
    """
    xml_request = create_get_config_xml(entity_type)
    response = await send_api_request(xml_request)
    
    return f"📊 Configuration for {entity_type}:\n\n{format_response(response)}"

@mcp.tool()
async def set_config(config_xml: str) -> str:
    """Set firewall configuration.
    
    Args:
        config_xml: XML configuration (without outer Request tags)
    """
    xml_request = create_set_config_xml(config_xml)
    response = await send_api_request(xml_request)
    
    if response['status'] == 'success' and response['parsed']['success']:
        return f"✅ Configuration updated successfully\n\n{format_response(response)}"
    else:
        return f"❌ Configuration update failed\n\n{format_response(response)}"

@mcp.tool()
async def send_custom_xml(xml_content: str) -> str:
    """Send custom XML request to Sophos API.
    
    Args:
        xml_content: Custom XML (will be wrapped in Request tags)
    """
    xml_request = f'<Request APIVersion="2000.2">{xml_content}</Request>'
    response = await send_api_request(xml_request)
    
    return f"📤 Custom request results:\n\n{format_response(response)}"

@mcp.tool()
async def update_credentials(host_ip: str = None, host_port: str = None, 
                           username: str = None, password: str = None) -> str:
    """Update connection credentials at runtime.
    
    Args:
        host_ip: New firewall IP
        host_port: New firewall port
        username: New username
        password: New password
    """
    global CONFIG, API_BASE_URL
    
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
    
    if host_ip or host_port:
        API_BASE_URL = f"https://{CONFIG['host_ip']}:{CONFIG['host_port']}/webconsole/APIController"
        changes.append(f"API URL: {API_BASE_URL}")
    
    # Reset auth status
    session_data['authenticated'] = False
    session_data['session_token'] = None
    session_data['connection_status'] = "Credentials updated - not tested"
    
    if changes:
        return f"✅ Updated:\n" + "\n".join(f"   • {change}" for change in changes) + "\n\n⚠️ Run authenticate() to log in with new credentials"
    else:
        return "No changes made - no parameters provided"

if __name__ == "__main__":
    print("🚀 Starting Sophos XGS MCP Server...", file=sys.stderr)
    print(f"📡 API Endpoint: {API_BASE_URL}", file=sys.stderr)
    print(f"👤 Username: {CONFIG['username']}", file=sys.stderr)
    print(f"🔑 Password: {'Configured' if CONFIG['password'] else 'NOT SET - Set SOPHOS_PASSWORD env var'}", file=sys.stderr)
    print("", file=sys.stderr)
    
    mcp.run(transport='stdio')