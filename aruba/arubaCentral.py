#!/usr/bin/env python3

import os
import sys
import json
import time
import requests
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize FastMCP server
mcp = FastMCP("Aruba Central API")

# Load environment variables
load_dotenv()

class ArubaTokenManager:
    """Aruba Central API token manager with automatic refresh."""
    
    def __init__(self):
        self._debug = False
        self._session = requests.session()
        self._base_url = None
        self._client_id = None
        self._client_secret = None
        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = None
        self._refresh_expires_at = None
        self._token_file = os.path.expanduser("~/.aruba_central_tokens.json")
        
    def jprint(self, json_obj):
        """Pretty print JSON object."""
        return json.dumps(json_obj, indent=2, sort_keys=True)

    def dprint(self, response):
        """Debug print API response."""
        if self._debug:
            method = response.request.method
            url = response.request.url
            body = response.request.body

            print(f"\nREQUEST:\n{method}: {url}", file=sys.stderr)
            
            if body is not None and body != 'null':
                try:
                    j = json.loads(body)
                    print(f"\n{json.dumps(j, indent=2, sort_keys=True)}", file=sys.stderr)
                except (ValueError, TypeError):
                    print(f"\n{body}", file=sys.stderr)

            print(f"\nRESPONSE:\n{response.status_code} {response.reason}", file=sys.stderr)
            
            if response.content:
                try:
                    j = json.loads(response.content)
                    print(f"\n{json.dumps(j, indent=2, sort_keys=True)}", file=sys.stderr)
                except (ValueError, TypeError):
                    print(f"\n{response.content.decode()}", file=sys.stderr)

    def debug(self, status):
        """Enable/disable debug mode."""
        self._debug = (status == 'on')

    def configure(self, base_url, client_id, client_secret):
        """Configure API connection parameters."""
        self._base_url = base_url.rstrip('/')
        self._client_id = client_id
        self._client_secret = client_secret
        self._session.verify = True  # Aruba Central uses valid SSL certs

    def save_tokens(self):
        """Save tokens to persistent storage."""
        if not self._access_token:
            return
            
        token_data = {
            'access_token': self._access_token,
            'refresh_token': self._refresh_token,
            'expires_at': self._token_expires_at.isoformat() if self._token_expires_at else None,
            'refresh_expires_at': self._refresh_expires_at.isoformat() if self._refresh_expires_at else None,
            'client_id': self._client_id,
            'base_url': self._base_url
        }
        
        try:
            with open(self._token_file, 'w') as f:
                json.dump(token_data, f, indent=2)
            os.chmod(self._token_file, 0o600)  # Restrict file permissions
            if self._debug:
                print(f"Tokens saved to {self._token_file}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not save tokens: {e}", file=sys.stderr)

    def load_tokens(self):
        """Load tokens from persistent storage."""
        if not os.path.exists(self._token_file):
            return False
            
        try:
            with open(self._token_file, 'r') as f:
                token_data = json.load(f)
            
            self._access_token = token_data.get('access_token')
            self._refresh_token = token_data.get('refresh_token')
            
            # Parse expiration times
            if token_data.get('expires_at'):
                self._token_expires_at = datetime.fromisoformat(token_data['expires_at'])
            if token_data.get('refresh_expires_at'):
                self._refresh_expires_at = datetime.fromisoformat(token_data['refresh_expires_at'])
                
            # Restore configuration if available
            if token_data.get('client_id') and token_data.get('base_url'):
                self._client_id = token_data['client_id']
                self._base_url = token_data['base_url']
            
            if self._debug:
                print(f"Tokens loaded from {self._token_file}", file=sys.stderr)
            return True
            
        except Exception as e:
            print(f"Warning: Could not load tokens: {e}", file=sys.stderr)
            return False

    def is_token_expired(self):
        """Check if access token is expired or will expire soon."""
        if not self._token_expires_at:
            return True
        # Consider token expired if it expires within 5 minutes
        return datetime.now() >= (self._token_expires_at - timedelta(minutes=5))

    def is_refresh_token_expired(self):
        """Check if refresh token is expired."""
        if not self._refresh_expires_at:
            return True
        return datetime.now() >= self._refresh_expires_at

    def set_initial_tokens(self, access_token, refresh_token):
        """Set initial tokens (from manual generation)."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        # Access tokens are valid for 2 hours
        self._token_expires_at = datetime.now() + timedelta(hours=2)
        # Refresh tokens are valid for 15 days
        self._refresh_expires_at = datetime.now() + timedelta(days=15)
        
        # Update session headers
        self._session.headers.update({'Authorization': f'Bearer {access_token}'})
        self.save_tokens()

    def refresh_access_token(self):
        """Refresh the access token using refresh token."""
        if not self._refresh_token:
            raise Exception("No refresh token available")
            
        if self.is_refresh_token_expired():
            raise Exception("Refresh token has expired. Manual token generation required.")

        if not all([self._base_url, self._client_id, self._client_secret]):
            raise Exception("Missing API configuration (base_url, client_id, client_secret)")

        url = f"{self._base_url}/oauth2/token"
        params = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': self._refresh_token
        }
        
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = self._session.post(url, params=params, headers=headers, timeout=30)
            self.dprint(response)
            
            if response.status_code == 200:
                token_data = response.json()
                
                # Update tokens
                self._access_token = token_data['access_token']
                self._refresh_token = token_data['refresh_token']
                
                # Update expiration times
                expires_in = token_data.get('expires_in', 7200)  # Default 2 hours
                self._token_expires_at = datetime.now() + timedelta(seconds=expires_in)
                self._refresh_expires_at = datetime.now() + timedelta(days=15)
                
                # Update session headers
                self._session.headers.update({'Authorization': f'Bearer {self._access_token}'})
                
                # Save to persistent storage
                self.save_tokens()
                
                return True
            else:
                raise Exception(f"Token refresh failed: HTTP {response.status_code} - {response.text}")
                
        except requests.RequestException as e:
            raise Exception(f"Token refresh request failed: {str(e)}")

    def get_valid_token(self):
        """Get a valid access token, refreshing if necessary."""
        if not self._access_token:
            raise Exception("No access token available. Set initial tokens first.")
            
        if self.is_token_expired():
            if self._debug:
                print("Access token expired, attempting refresh...", file=sys.stderr)
            self.refresh_access_token()
            
        return self._access_token

    def api_request(self, method, endpoint, **kwargs):
        """Make authenticated API request to Aruba Central."""
        token = self.get_valid_token()
        
        # Ensure endpoint starts with /
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
            
        url = f"{self._base_url}{endpoint}"
        
        # Ensure Authorization header is set
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {token}'
        kwargs['headers'] = headers
        
        response = self._session.request(method, url, **kwargs)
        self.dprint(response)
        return response

    def get_token_status(self):
        """Get current token status information."""
        status = {
            'has_access_token': bool(self._access_token),
            'has_refresh_token': bool(self._refresh_token),
            'access_token_expired': self.is_token_expired(),
            'refresh_token_expired': self.is_refresh_token_expired(),
            'expires_at': self._token_expires_at.isoformat() if self._token_expires_at else None,
            'refresh_expires_at': self._refresh_expires_at.isoformat() if self._refresh_expires_at else None,
            'configured': bool(self._base_url and self._client_id and self._client_secret)
        }
        
        if self._token_expires_at:
            status['time_until_expiry'] = str(self._token_expires_at - datetime.now())
        if self._refresh_expires_at:
            status['time_until_refresh_expiry'] = str(self._refresh_expires_at - datetime.now())
            
        return status


# Configuration from environment variables
def load_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    config = {
        'base_url': os.getenv('ARUBA_CENTRAL_BASE_URL', 'https://app1-apigw.central.arubanetworks.com'),
        'client_id': os.getenv('ARUBA_CENTRAL_CLIENT_ID', ''),
        'client_secret': os.getenv('ARUBA_CENTRAL_CLIENT_SECRET', ''),
        'access_token': os.getenv('ARUBA_CENTRAL_ACCESS_TOKEN', ''),
        'refresh_token': os.getenv('ARUBA_CENTRAL_REFRESH_TOKEN', ''),
        'timeout': int(os.getenv('ARUBA_CENTRAL_TIMEOUT', '30'))
    }
    
    print("Aruba Central Configuration loaded:", file=sys.stderr)
    print(f"  Base URL: {config['base_url']}", file=sys.stderr)
    print(f"  Client ID: {'Set' if config['client_id'] else 'NOT SET'}", file=sys.stderr)
    print(f"  Client Secret: {'Set' if config['client_secret'] else 'NOT SET'}", file=sys.stderr)
    print(f"  Access Token: {'Set' if config['access_token'] else 'NOT SET'}", file=sys.stderr)
    print(f"  Refresh Token: {'Set' if config['refresh_token'] else 'NOT SET'}", file=sys.stderr)
    print(f"  Timeout: {config['timeout']}s", file=sys.stderr)
    
    return config

# Load configuration
CONFIG = load_config()

# Global Aruba Central client instance
aruba = ArubaTokenManager()

# Global state
session_data = {
    'token_status': 'Not initialized',
    'last_refresh': None,
    'auto_refresh_enabled': True
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
async def get_status() -> str:
    """Get current Aruba Central API client status and configuration."""
    # Get token status
    token_status = aruba.get_token_status()
    
    # Configuration status
    config_status = "✅ Complete" if (CONFIG['client_id'] and CONFIG['client_secret'] and CONFIG['base_url']) else "❌ Incomplete"
    
    # Token file status
    token_file_exists = os.path.exists(aruba._token_file)
    
    return f"""
📊 Aruba Central API Status

🔗 Configuration:
   • Base URL: {CONFIG['base_url']}
   • Client ID: {'✅ Set' if CONFIG['client_id'] else '❌ Not set'}
   • Client Secret: {'✅ Set' if CONFIG['client_secret'] else '❌ Not set'}
   • Config Status: {config_status}
   • Timeout: {CONFIG['timeout']}s

🎫 Token Status:
   • Access Token: {'✅ Available' if token_status['has_access_token'] else '❌ Not available'}
   • Refresh Token: {'✅ Available' if token_status['has_refresh_token'] else '❌ Not available'}
   • Access Token Valid: {'✅ Valid' if not token_status['access_token_expired'] else '❌ Expired'}
   • Refresh Token Valid: {'✅ Valid' if not token_status['refresh_token_expired'] else '❌ Expired'}
   • Token File: {'✅ Exists' if token_file_exists else '❌ Not found'} ({aruba._token_file})
   
⏰ Expiration Info:
   • Access Expires: {token_status.get('expires_at', 'Unknown')}
   • Refresh Expires: {token_status.get('refresh_expires_at', 'Unknown')}
   • Time Until Expiry: {token_status.get('time_until_expiry', 'Unknown')}

🔄 Auto-Refresh: {'✅ Enabled' if session_data['auto_refresh_enabled'] else '❌ Disabled'}
   • Last Refresh: {session_data['last_refresh'] or 'Never'}

⚙️ Environment Variables:
   Set these for automatic configuration:
   • ARUBA_CENTRAL_BASE_URL={CONFIG['base_url']}
   • ARUBA_CENTRAL_CLIENT_ID={'***' if CONFIG['client_id'] else 'NOT SET'}
   • ARUBA_CENTRAL_CLIENT_SECRET={'***' if CONFIG['client_secret'] else 'NOT SET'}
   • ARUBA_CENTRAL_ACCESS_TOKEN={'***' if CONFIG['access_token'] else 'NOT SET'}
   • ARUBA_CENTRAL_REFRESH_TOKEN={'***' if CONFIG['refresh_token'] else 'NOT SET'}
   • ARUBA_CENTRAL_TIMEOUT={CONFIG['timeout']}

💡 Quick Start:
   1. Set environment variables with your API credentials
   2. initialize_tokens() - Set up initial tokens
   3. Use api_request() for making authenticated API calls
   4. Tokens will auto-refresh when needed
"""

@mcp.tool()
async def get_insights(days_back: int = 7, insight_type: str = None) -> str:
    """Get AI Ops insights from Aruba Central.
    
    Args:
        days_back: Number of days to look back (default: 7)
        insight_type: Filter by insight type (optional)
    """
    try:
        # Calculate epoch milliseconds for the time range
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days_back)
        
        from_epoch = int(start_time.timestamp() * 1000)
        to_epoch = int(end_time.timestamp() * 1000)
        
        params = {
            'from': from_epoch,
            'to': to_epoch
        }
        
        if insight_type:
            params['insight_type'] = insight_type
            
        response = aruba.api_request('GET', '/aiops/v2/insights/global/list', params=params)
        response_data = format_response(response)
        
        if response_data['success'] and response_data['data']:
            insight_count = len(response_data['data'].get('insights', []))
            return format_output(response_data, f"AI Ops Insights (Last {days_back} days) - {insight_count} insights found")
        else:
            return f"✅ No AI Ops insights found for the last {days_back} days (this is good - no issues detected!)"
            
    except Exception as e:
        return f"❌ Failed to get insights: {str(e)}"

@mcp.tool()
async def get_group_details(group_name: str = None) -> str:
    """Get detailed information about a specific group or all groups.
    
    Args:
        group_name: Specific group name to get details for (optional)
    """
    try:
        if group_name:
            # Get specific group details
            response = aruba.api_request('GET', f'/configuration/v2/groups/{group_name}')
        else:
            # Get all groups with details
            response = aruba.api_request('GET', '/configuration/v2/groups', params={'limit': 100, 'offset': 0})
        
        response_data = format_response(response)
        title = f"Group Details: {group_name}" if group_name else "All Groups"
        
        return format_output(response_data, title)
        
    except Exception as e:
        return f"❌ Failed to get group details: {str(e)}"

@mcp.tool()
async def get_site_details(site_id: int = None) -> str:
    """Get detailed information about a specific site.
    
    Args:
        site_id: Site ID to get details for (optional, shows all if not provided)
    """
    try:
        if site_id:
            response = aruba.api_request('GET', f'/central/v2/sites/{site_id}')
        else:
            response = aruba.api_request('GET', '/central/v2/sites')
        
        response_data = format_response(response)
        title = f"Site Details: {site_id}" if site_id else "All Sites"
        
        return format_output(response_data, title)
        
    except Exception as e:
        return f"❌ Failed to get site details: {str(e)}"

@mcp.tool()
async def get_network_health() -> str:
    """Get network health and status information."""
    try:
        # Try multiple potential health/status endpoints
        endpoints_to_try = [
            '/aiops/v2/insights/network/health',
            '/monitoring/v2/network/health', 
            '/central/v2/network/status',
            '/aiops/v1/network/health'
        ]
        
        results = []
        for endpoint in endpoints_to_try:
            try:
                response = aruba.api_request('GET', endpoint)
                if response.status_code == 200:
                    response_data = format_response(response)
                    results.append(format_output(response_data, f"Network Health ({endpoint})"))
                    break
            except:
                continue
        
        if results:
            return results[0]
        else:
            return "ℹ️ Network health endpoints not available on this instance. Use get_insights() for AI-driven health information."
            
    except Exception as e:
        return f"❌ Failed to get network health: {str(e)}"

@mcp.tool()
async def search_configuration(search_term: str, config_type: str = None) -> str:
    """Search through configuration items.
    
    Args:
        search_term: Term to search for
        config_type: Type of config (groups, sites, devices, etc.)
    """
    try:
        results = []
        
        # Search in groups
        if not config_type or config_type == 'groups':
            response = aruba.api_request('GET', '/configuration/v2/groups', 
                                       params={'limit': 100, 'offset': 0})
            if response.status_code == 200:
                data = response.json()
                matching_groups = [group for group in data.get('data', []) 
                                 if search_term.lower() in str(group).lower()]
                if matching_groups:
                    results.append(f"🔍 Groups matching '{search_term}': {matching_groups}")
        
        # Search in sites
        if not config_type or config_type == 'sites':
            response = aruba.api_request('GET', '/central/v2/sites')
            if response.status_code == 200:
                data = response.json()
                matching_sites = [site for site in data.get('sites', []) 
                                if search_term.lower() in str(site).lower()]
                if matching_sites:
                    results.append(f"🔍 Sites matching '{search_term}': {len(matching_sites)} found")
        
        if results:
            return "\n\n".join(results)
        else:
            return f"❌ No configuration items found matching '{search_term}'"
            
    except Exception as e:
        return f"❌ Search failed: {str(e)}"

@mcp.tool()
async def get_api_endpoints() -> str:
    """Discover available API endpoints by testing common paths."""
    endpoints_to_test = {
        'Configuration': [
            '/configuration/v1/groups',
            '/configuration/v2/groups', 
            '/configuration/v1/devices',
            '/configuration/v2/devices'
        ],
        'Monitoring': [
            '/monitoring/v1/devices',
            '/monitoring/v2/devices',
            '/monitoring/v1/clients',
            '/monitoring/v1/alerts'
        ],
        'AI Ops': [
            '/aiops/v1/insights/global/list',
            '/aiops/v2/insights/global/list',
            '/aiops/v1/network/health'
        ],
        'Platform': [
            '/platform/device_inventory/v1/devices',
            '/central/v2/sites',
            '/central/v1/sites'
        ]
    }
    
    results = []
    working_endpoints = []
    
    for category, endpoints in endpoints_to_test.items():
        category_results = []
        for endpoint in endpoints:
            try:
                # Use HEAD request to avoid data transfer
                response = aruba.api_request('HEAD', endpoint)
                status = "✅" if response.status_code < 400 else "❌"
                category_results.append(f"   {status} {endpoint} ({response.status_code})")
                if response.status_code < 400:
                    working_endpoints.append(endpoint)
            except Exception as e:
                category_results.append(f"   ❌ {endpoint} (Error)")
        
        results.append(f"📂 {category}:\n" + "\n".join(category_results))
    
    summary = f"\n\n📊 Summary: {len(working_endpoints)} working endpoints found"
    if working_endpoints:
        summary += f"\n\n🎯 Working endpoints:\n" + "\n".join(f"   • {ep}" for ep in working_endpoints)
    
    return "\n\n".join(results) + summary

# Helper function to convert datetime to epoch milliseconds
def datetime_to_epoch_ms(dt: datetime) -> int:
    """Convert datetime to epoch milliseconds for Aruba Central APIs."""
    return int(dt.timestamp() * 1000)

# Helper function to get current time range
def get_time_range(days_back: int = 7):
    """Get from/to epoch milliseconds for time range queries."""
    end_time = datetime.now()
    start_time = end_time - timedelta(days=days_back)
    return datetime_to_epoch_ms(start_time), datetime_to_epoch_ms(end_time)

# Update the get_api_info function to include the new insights endpoint
@mcp.tool()
async def get_api_info() -> str:
    """Get information about the Aruba Central API endpoints and usage."""
    return """
📚 Aruba Central API Information

🔗 Working Endpoints (Confirmed):
   • Groups: /configuration/v2/groups
   • Sites: /central/v2/sites
   • AI Ops Insights: /aiops/v2/insights/global/list
   
🔗 Common Endpoints (May vary by license/region):
   • Devices: /monitoring/v1/devices
   • Networks: /configuration/v1/networks  
   • Applications: /monitoring/v1/applications
   • Alerts: /monitoring/v1/alerts
   • Clients: /monitoring/v1/clients
   • Access Points: /monitoring/v1/aps
   • Switches: /monitoring/v1/switches
   
🎫 Token Management:
   • Access tokens expire every 2 hours
   • Refresh tokens expire after 15 days
   • Auto-refresh happens automatically before expiration
   • Rate limit: 1 new token per 30 minutes per client_id

📖 Documentation:
   • Developer Hub: https://developer.arubanetworks.com/
   • API Reference: Available in Central UI under API Gateway
   
🔧 New Functions Available:
   • get_insights(days_back) - Get AI Ops insights
   • get_group_details(group_name) - Detailed group info
   • get_site_details(site_id) - Detailed site info  
   • get_network_health() - Network health status
   • search_configuration(term) - Search config items
   • get_api_endpoints() - Discover available endpoints

📝 Example:
   get_insights(7)  # Get insights from last 7 days
   get_group_details("ARY-IAP-Group")  # Get specific group details
"""

@mcp.tool()
async def initialize_tokens() -> str:
    """Initialize the token manager with configuration and tokens."""
    try:
        # Configure the client
        if not all([CONFIG['base_url'], CONFIG['client_id'], CONFIG['client_secret']]):
            return """
❌ Missing required configuration:
   • ARUBA_CENTRAL_BASE_URL
   • ARUBA_CENTRAL_CLIENT_ID  
   • ARUBA_CENTRAL_CLIENT_SECRET

Set these environment variables first.
"""

        aruba.configure(CONFIG['base_url'], CONFIG['client_id'], CONFIG['client_secret'])
        
        # Try to load existing tokens first
        if aruba.load_tokens():
            # Test if loaded tokens are still valid
            try:
                token_status = aruba.get_token_status()
                if not token_status['access_token_expired']:
                    session_data['token_status'] = 'Loaded from file'
                    return """
✅ Tokens loaded from persistent storage
🎫 Access token is still valid
🔄 Auto-refresh is configured
"""
                elif not token_status['refresh_token_expired']:
                    # Try to refresh
                    aruba.refresh_access_token()
                    session_data['token_status'] = 'Refreshed from file'
                    session_data['last_refresh'] = datetime.now().isoformat()
                    return """
✅ Tokens loaded from persistent storage
🔄 Access token refreshed successfully
🎫 Ready for API calls
"""
            except Exception as e:
                print(f"Token validation failed: {e}", file=sys.stderr)

        # Use tokens from environment variables if available
        if CONFIG['access_token'] and CONFIG['refresh_token']:
            aruba.set_initial_tokens(CONFIG['access_token'], CONFIG['refresh_token'])
            session_data['token_status'] = 'Set from environment'
            return """
✅ Tokens initialized from environment variables
🎫 Access token set and saved
🔄 Auto-refresh configured
💾 Tokens saved to persistent storage
"""
        
        # No tokens available
        return """
❌ No tokens available. You need to either:

1. Set environment variables:
   • ARUBA_CENTRAL_ACCESS_TOKEN
   • ARUBA_CENTRAL_REFRESH_TOKEN

2. Or use set_manual_tokens() with tokens from the Aruba Central UI

To get tokens from the UI:
1. Go to Aruba Central API Gateway
2. Create/select your application
3. Generate new tokens
4. Copy the access_token and refresh_token values
"""
        
    except Exception as e:
        return f"❌ Initialization failed: {str(e)}"

@mcp.tool()
async def set_manual_tokens(access_token: str, refresh_token: str) -> str:
    """Set tokens manually (from UI generation).
    
    Args:
        access_token: Access token from Aruba Central UI
        refresh_token: Refresh token from Aruba Central UI
    """
    try:
        if not all([CONFIG['base_url'], CONFIG['client_id'], CONFIG['client_secret']]):
            return """
❌ Missing API configuration. Set these environment variables:
   • ARUBA_CENTRAL_BASE_URL
   • ARUBA_CENTRAL_CLIENT_ID  
   • ARUBA_CENTRAL_CLIENT_SECRET
"""

        aruba.configure(CONFIG['base_url'], CONFIG['client_id'], CONFIG['client_secret'])
        aruba.set_initial_tokens(access_token, refresh_token)
        
        session_data['token_status'] = 'Set manually'
        
        return """
✅ Tokens set successfully
🎫 Access token active
🔄 Auto-refresh configured  
💾 Tokens saved to persistent storage
🚀 Ready for API calls
"""
        
    except Exception as e:
        return f"❌ Failed to set tokens: {str(e)}"

@mcp.tool()
async def refresh_token() -> str:
    """Manually refresh the access token."""
    try:
        if not aruba._refresh_token:
            return "❌ No refresh token available. Initialize tokens first."
            
        aruba.refresh_access_token()
        session_data['last_refresh'] = datetime.now().isoformat()
        
        return """
✅ Token refreshed successfully
🎫 New access token active
💾 Updated tokens saved
⏰ Valid for 2 more hours
"""
        
    except Exception as e:
        return f"❌ Token refresh failed: {str(e)}"

@mcp.tool()
async def api_request(method: str, endpoint: str, data: Dict[str, Any] = None, 
                     params: Dict[str, Any] = None, headers: Dict[str, Any] = None) -> str:
    """Make authenticated API request to Aruba Central.
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: API endpoint (e.g., '/monitoring/v1/devices')
        data: Request body data (for POST/PUT)
        params: Query parameters
        headers: Additional headers
    """
    try:
        # Prepare request arguments
        kwargs = {}
        if data:
            kwargs['json'] = data
        if params:
            kwargs['params'] = params
        if headers:
            kwargs['headers'] = headers
        
        response = aruba.api_request(method.upper(), endpoint, **kwargs)
        response_data = format_response(response)
        
        return format_output(response_data, f"{method.upper()} {endpoint}")
        
    except Exception as e:
        return f"❌ API request failed: {str(e)}"

@mcp.tool()
async def get_switches() -> str:
    """Get list of switches from Aruba Central."""
    return await api_request('GET', '/monitoring/v2/aps')

@mcp.tool()
async def get_waps() -> str:
    """Get list of Access Points from Aruba Central."""
    return await api_request('GET', '/monitoring/v1/switches')

@mcp.tool()
async def get_networks() -> str:
    """Get list of networks from Aruba Central."""
    return await api_request('GET', '/configuration/v1/networks')

@mcp.tool()
async def get_sites() -> str:
    """Get list of sites from Aruba Central."""
    return await api_request('GET', '/central/v2/sites')

@mcp.tool()
async def get_applications() -> str:
    """Get list of applications from Aruba Central."""
    return await api_request('GET', '/monitoring/v1/applications')

@mcp.tool()
async def update_config(base_url: str = None, client_id: str = None, 
                       client_secret: str = None, timeout: int = None) -> str:
    """Update Aruba Central API configuration at runtime.
    
    Args:
        base_url: New base URL
        client_id: New client ID
        client_secret: New client secret
        timeout: New timeout value
    """
    global CONFIG
    
    changes = []
    if base_url:
        CONFIG['base_url'] = base_url
        changes.append(f"Base URL: {base_url}")
    if client_id:
        CONFIG['client_id'] = client_id
        changes.append(f"Client ID: {client_id}")
    if client_secret:
        CONFIG['client_secret'] = client_secret
        changes.append("Client Secret: Updated")
    if timeout:
        CONFIG['timeout'] = timeout
        changes.append(f"Timeout: {timeout}s")
    
    # Reset token status
    session_data['token_status'] = "Configuration updated - tokens need re-initialization"
    
    if changes:
        return "✅ Updated:\n" + "\n".join(f"   • {change}" for change in changes) + "\n\n⚠️ Run initialize_tokens() to apply new configuration"
    else:
        return "No changes made - no parameters provided"

@mcp.tool()
async def enable_debug() -> str:
    """Enable debug logging for API requests."""
    aruba.debug('on')
    return "✅ Debug logging enabled - API requests will be logged to stderr"

@mcp.tool()
async def disable_debug() -> str:
    """Disable debug logging for API requests."""
    aruba.debug('off')
    return "✅ Debug logging disabled"

@mcp.tool()
async def clear_tokens() -> str:
    """Clear all stored tokens and reset the client."""
    try:
        # Clear in-memory tokens
        aruba._access_token = None
        aruba._refresh_token = None
        aruba._token_expires_at = None
        aruba._refresh_expires_at = None
        
        # Remove token file
        if os.path.exists(aruba._token_file):
            os.remove(aruba._token_file)
            
        # Clear session headers
        if 'Authorization' in aruba._session.headers:
            del aruba._session.headers['Authorization']
            
        session_data['token_status'] = 'Cleared'
        session_data['last_refresh'] = None
        
        return """
✅ All tokens cleared
🗑️ Token file removed
🔄 Session reset
💡 Use initialize_tokens() or set_manual_tokens() to set new tokens
"""
        
    except Exception as e:
        return f"❌ Failed to clear tokens: {str(e)}"



if __name__ == "__main__":
    print("🚀 Starting Aruba Central MCP Server...", file=sys.stderr)
    print(f"🌐 Base URL: {CONFIG['base_url']}", file=sys.stderr)
    print(f"🆔 Client ID: {'Configured' if CONFIG['client_id'] else 'NOT SET'}", file=sys.stderr)
    print(f"🔐 Client Secret: {'Configured' if CONFIG['client_secret'] else 'NOT SET'}", file=sys.stderr)
    print(f"🎫 Access Token: {'Configured' if CONFIG['access_token'] else 'NOT SET'}", file=sys.stderr)
    print(f"🔄 Refresh Token: {'Configured' if CONFIG['refresh_token'] else 'NOT SET'}", file=sys.stderr)
    print(f"⏱️  Timeout: {CONFIG['timeout']}s", file=sys.stderr)
    print(f"💾 Token File: {aruba._token_file}", file=sys.stderr)
    print("", file=sys.stderr)
    
    # Auto-initialize if configuration is available
    if all([CONFIG['base_url'], CONFIG['client_id'], CONFIG['client_secret']]):
        try:
            aruba.configure(CONFIG['base_url'], CONFIG['client_id'], CONFIG['client_secret'])
            if aruba.load_tokens():
                print("✅ Tokens auto-loaded from persistent storage", file=sys.stderr)
            elif CONFIG['access_token'] and CONFIG['refresh_token']:
                aruba.set_initial_tokens(CONFIG['access_token'], CONFIG['refresh_token'])
                print("✅ Tokens auto-initialized from environment", file=sys.stderr)
        except Exception as e:
            print(f"⚠️ Auto-initialization failed: {e}", file=sys.stderr)
    
    mcp.run(transport='stdio')