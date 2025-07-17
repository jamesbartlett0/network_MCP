#!/usr/bin/env python3

import os
import sys
import json
import requests
import hashlib
import time
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

# Initialize FastMCP server
mcp = FastMCP("VirusTotal Security")

# Load environment variables
load_dotenv()

class VirusTotalAPI:
    """VirusTotal API v3 client."""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self._debug = False
        
        if self.api_key:
            self.session.headers.update({
                'x-apikey': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })

    def set_debug(self, debug: bool):
        """Enable or disable debug logging."""
        self._debug = debug

    def _log_request(self, method: str, url: str, **kwargs):
        """Log request details if debug is enabled."""
        if self._debug:
            print(f"\n🔍 REQUEST: {method.upper()} {url}", file=sys.stderr)
            if 'params' in kwargs and kwargs['params']:
                print(f"   Params: {kwargs['params']}", file=sys.stderr)
            if 'data' in kwargs and kwargs['data']:
                print(f"   Data: {kwargs['data']}", file=sys.stderr)

    def _log_response(self, response: requests.Response):
        """Log response details if debug is enabled."""
        if self._debug:
            print(f"\n📡 RESPONSE: {response.status_code} {response.reason}", file=sys.stderr)
            print(f"   URL: {response.url}", file=sys.stderr)
            if response.content:
                try:
                    content = response.json()
                    print(f"   Content: {json.dumps(content, indent=2)[:500]}...", file=sys.stderr)
                except:
                    print(f"   Raw Content: {response.content.decode()[:200]}...", file=sys.stderr)

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request to VirusTotal API."""
        url = f"{self.base_url}/{endpoint}"
        self._log_request(method, url, **kwargs)
        
        response = self.session.request(method, url, **kwargs)
        self._log_response(response)
        
        return response

    def get_file_report(self, file_hash: str) -> requests.Response:
        """Get file analysis report by hash (MD5, SHA1, SHA256)."""
        return self._make_request('GET', f'files/{file_hash}')

    def upload_file(self, file_path: str) -> requests.Response:
        """Upload file for analysis."""
        # First get upload URL
        upload_url_response = self._make_request('GET', 'files/upload_url')
        
        if upload_url_response.status_code != 200:
            return upload_url_response
            
        upload_url = upload_url_response.json()['data']
        
        # Upload file to the received URL
        with open(file_path, 'rb') as f:
            files = {'file': f}
            # Remove API key header for upload request
            headers = {'x-apikey': self.api_key}
            response = requests.post(upload_url, files=files, headers=headers)
            
        return response

    def upload_file_from_url(self, url: str) -> requests.Response:
        """Upload file from URL for analysis."""
        data = {'url': url}
        return self._make_request('POST', 'files/upload_url', json=data)

    def scan_url(self, url: str) -> requests.Response:
        """Submit URL for analysis."""
        data = {'url': url}
        return self._make_request('POST', 'urls', json=data)

    def get_url_report(self, url: str) -> requests.Response:
        """Get URL analysis report."""
        # URLs need to be base64 encoded for the API
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        return self._make_request('GET', f'urls/{url_id}')

    def get_domain_report(self, domain: str) -> requests.Response:
        """Get domain analysis report."""
        return self._make_request('GET', f'domains/{domain}')

    def get_ip_report(self, ip_address: str) -> requests.Response:
        """Get IP address analysis report."""
        return self._make_request('GET', f'ip_addresses/{ip_address}')

    def get_analysis(self, analysis_id: str) -> requests.Response:
        """Get analysis report by ID."""
        return self._make_request('GET', f'analyses/{analysis_id}')

    def search(self, query: str, limit: int = 10) -> requests.Response:
        """Search VirusTotal using intelligence search."""
        params = {'query': query, 'limit': limit}
        return self._make_request('GET', 'intelligence/search', params=params)

    def get_comments(self, resource_type: str, resource_id: str) -> requests.Response:
        """Get comments for a resource (file, URL, domain, IP)."""
        return self._make_request('GET', f'{resource_type}/{resource_id}/comments')

    def add_comment(self, resource_type: str, resource_id: str, comment: str) -> requests.Response:
        """Add comment to a resource."""
        data = {'data': {'type': 'comment', 'attributes': {'text': comment}}}
        return self._make_request('POST', f'{resource_type}/{resource_id}/comments', json=data)


# Configuration from environment variables
def load_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    config = {
        'api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
        'timeout': int(os.getenv('VIRUSTOTAL_TIMEOUT', '30')),
        'default_limit': int(os.getenv('VIRUSTOTAL_DEFAULT_LIMIT', '10'))
    }
    
    print("VirusTotal Configuration loaded:", file=sys.stderr)
    print(f"  API Key: {'Set (' + config['api_key'][:8] + '...)' if config['api_key'] else 'NOT SET'}", file=sys.stderr)
    print(f"  Timeout: {config['timeout']}s", file=sys.stderr)
    print(f"  Default Limit: {config['default_limit']}", file=sys.stderr)
    
    return config

# Load configuration
CONFIG = load_config()

# Global VirusTotal client instance
vt_client = VirusTotalAPI(CONFIG['api_key'])

# Global state
session_data = {
    'api_key_valid': False,
    'last_check': None,
    'quota_info': {}
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

def format_output(response_data: Dict[str, Any], title: str = "VirusTotal Response") -> str:
    """Format response data for user display."""
    status_icon = "✅" if response_data['success'] else "❌"
    
    result = f"{status_icon} {title}\n"
    result += f"HTTP Status: {response_data['status_code']}\n"
    result += f"URL: {response_data['url']}\n\n"
    
    if 'data' in response_data and response_data['data']:
        # Special formatting for VirusTotal responses
        data = response_data['data']
        
        if 'error' in data:
            result += f"❌ Error: {data['error'].get('message', 'Unknown error')}\n"
            result += f"Code: {data['error'].get('code', 'N/A')}\n"
        elif 'data' in data:
            vt_data = data['data']
            if isinstance(vt_data, dict):
                result += f"🔍 Analysis Results:\n"
                if 'attributes' in vt_data:
                    attrs = vt_data['attributes']
                    
                    # File analysis formatting
                    if 'last_analysis_stats' in attrs:
                        stats = attrs['last_analysis_stats']
                        result += f"  🛡️  Detections: {stats.get('malicious', 0)}/{stats.get('malicious', 0) + stats.get('harmless', 0) + stats.get('undetected', 0)} engines\n"
                        result += f"  📊 Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Harmless: {stats.get('harmless', 0)}\n"
                    
                    # Basic info
                    if 'md5' in attrs:
                        result += f"  🔐 MD5: {attrs['md5']}\n"
                    if 'sha256' in attrs:
                        result += f"  🔐 SHA256: {attrs['sha256']}\n"
                    if 'meaningful_name' in attrs:
                        result += f"  📄 Name: {attrs['meaningful_name']}\n"
                    if 'size' in attrs:
                        result += f"  📏 Size: {attrs['size']} bytes\n"
                    if 'creation_date' in attrs:
                        result += f"  📅 First Seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(attrs['creation_date']))}\n"
                
                result += f"\n📋 Full Response:\n"
        
        result += json.dumps(data, indent=2)
    
    return result

def calculate_file_hash(file_path: str, hash_type: str = 'sha256') -> str:
    """Calculate hash of a file."""
    hash_obj = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

@mcp.tool()
async def get_status() -> str:
    """Get current VirusTotal API client status and configuration."""
    api_key_status = "✅ Set" if CONFIG['api_key'] else "❌ Not set"
    
    # Test API key if available
    if CONFIG['api_key'] and not session_data['api_key_valid']:
        try:
            # Test with a simple request
            response = vt_client.get_domain_report('google.com')
            if response.status_code in [200, 404]:  # 404 is OK, means API key works but domain not in VT
                session_data['api_key_valid'] = True
                session_data['last_check'] = time.time()
        except:
            pass
    
    validity_status = "✅ Valid" if session_data['api_key_valid'] else "❓ Unknown"
    
    return f"""
📊 VirusTotal API Status
🔑 Authentication:
   • API Key: {api_key_status}
   • Validity: {validity_status}
   • Last Check: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session_data['last_check'])) if session_data['last_check'] else 'Never'}

⚙️  Configuration:
   • Timeout: {CONFIG['timeout']}s
   • Default Limit: {CONFIG['default_limit']}

⚙️ Environment Variables:
   Set these before running:
   • VIRUSTOTAL_API_KEY={CONFIG['api_key'][:8] + '...' if CONFIG['api_key'] else 'NOT SET'}
   • VIRUSTOTAL_TIMEOUT={CONFIG['timeout']}
   • VIRUSTOTAL_DEFAULT_LIMIT={CONFIG['default_limit']}

💡 Quick Start:
   1. Set VIRUSTOTAL_API_KEY environment variable
   2. Use scan_url(), get_file_report(), etc.
   
🔗 Get API Key: https://www.virustotal.com/gui/join-us
"""

@mcp.tool()
async def scan_url(url: str) -> str:
    """Submit URL for analysis by VirusTotal.
    
    Args:
        url: URL to scan (must include http:// or https://)
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.scan_url(url)
        response_data = format_response(response)
        
        if response_data['success']:
            # Extract analysis ID for follow-up
            if 'data' in response_data['data'] and 'id' in response_data['data']['data']:
                analysis_id = response_data['data']['data']['id']
                return f"""
✅ URL Submitted for Analysis
🔗 URL: {url}
🆔 Analysis ID: {analysis_id}

💡 Use get_analysis('{analysis_id}') to check results
   Or wait a moment and use get_url_report('{url}')

{format_output(response_data, "URL Submission")}
"""
        
        return format_output(response_data, "URL Scan")
        
    except Exception as e:
        return f"❌ Failed to scan URL: {str(e)}"

@mcp.tool()
async def get_url_report(url: str) -> str:
    """Get analysis report for a URL.
    
    Args:
        url: URL to get report for
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.get_url_report(url)
        response_data = format_response(response)
        
        return format_output(response_data, f"URL Report: {url}")
        
    except Exception as e:
        return f"❌ Failed to get URL report: {str(e)}"

@mcp.tool()
async def get_file_report(file_hash: str) -> str:
    """Get file analysis report by hash (MD5, SHA1, or SHA256).
    
    Args:
        file_hash: File hash (MD5, SHA1, or SHA256)
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.get_file_report(file_hash)
        response_data = format_response(response)
        
        return format_output(response_data, f"File Report: {file_hash}")
        
    except Exception as e:
        return f"❌ Failed to get file report: {str(e)}"

@mcp.tool()
async def upload_file(file_path: str) -> str:
    """Upload a file for analysis.
    
    Args:
        file_path: Path to the file to upload
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    if not os.path.exists(file_path):
        return f"❌ File not found: {file_path}"
    
    try:
        # Calculate file hash for reference
        file_hash = calculate_file_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        response = vt_client.upload_file(file_path)
        response_data = format_response(response)
        
        if response_data['success']:
            # Extract analysis ID for follow-up
            if 'data' in response_data['data'] and 'id' in response_data['data']['data']:
                analysis_id = response_data['data']['data']['id']
                return f"""
✅ File Uploaded for Analysis
📄 File: {file_path}
📏 Size: {file_size} bytes
🔐 SHA256: {file_hash}
🆔 Analysis ID: {analysis_id}

💡 Use get_analysis('{analysis_id}') to check results
   Or wait a moment and use get_file_report('{file_hash}')

{format_output(response_data, "File Upload")}
"""
        
        return format_output(response_data, "File Upload")
        
    except Exception as e:
        return f"❌ Failed to upload file: {str(e)}"

@mcp.tool()
async def get_domain_report(domain: str) -> str:
    """Get domain analysis report.
    
    Args:
        domain: Domain name to analyze (e.g., example.com)
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.get_domain_report(domain)
        response_data = format_response(response)
        
        return format_output(response_data, f"Domain Report: {domain}")
        
    except Exception as e:
        return f"❌ Failed to get domain report: {str(e)}"

@mcp.tool()
async def get_ip_report(ip_address: str) -> str:
    """Get IP address analysis report.
    
    Args:
        ip_address: IP address to analyze
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.get_ip_report(ip_address)
        response_data = format_response(response)
        
        return format_output(response_data, f"IP Report: {ip_address}")
        
    except Exception as e:
        return f"❌ Failed to get IP report: {str(e)}"

@mcp.tool()
async def get_analysis(analysis_id: str) -> str:
    """Get analysis report by analysis ID.
    
    Args:
        analysis_id: Analysis ID returned from scan operations
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.get_analysis(analysis_id)
        response_data = format_response(response)
        
        return format_output(response_data, f"Analysis: {analysis_id}")
        
    except Exception as e:
        return f"❌ Failed to get analysis: {str(e)}"

@mcp.tool()
async def search_intelligence(query: str, limit: int = None) -> str:
    """Search VirusTotal intelligence using VT Query Language.
    
    Args:
        query: Search query using VT Intelligence syntax
        limit: Maximum number of results (default from config)
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    if limit is None:
        limit = CONFIG['default_limit']
    
    try:
        response = vt_client.search(query, limit)
        response_data = format_response(response)
        
        return format_output(response_data, f"Intelligence Search: {query}")
        
    except Exception as e:
        return f"❌ Failed to search intelligence: {str(e)}"

@mcp.tool()
async def get_comments(resource_type: str, resource_id: str) -> str:
    """Get comments for a resource (file, URL, domain, IP).
    
    Args:
        resource_type: Type of resource ('files', 'urls', 'domains', 'ip_addresses')
        resource_id: Resource identifier (hash, URL, domain, IP)
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.get_comments(resource_type, resource_id)
        response_data = format_response(response)
        
        return format_output(response_data, f"Comments: {resource_type}/{resource_id}")
        
    except Exception as e:
        return f"❌ Failed to get comments: {str(e)}"

@mcp.tool()
async def add_comment(resource_type: str, resource_id: str, comment: str) -> str:
    """Add comment to a resource.
    
    Args:
        resource_type: Type of resource ('files', 'urls', 'domains', 'ip_addresses')
        resource_id: Resource identifier (hash, URL, domain, IP)
        comment: Comment text to add
    """
    if not CONFIG['api_key']:
        return "❌ No API key configured. Set VIRUSTOTAL_API_KEY environment variable."
    
    try:
        response = vt_client.add_comment(resource_type, resource_id, comment)
        response_data = format_response(response)
        
        return format_output(response_data, f"Add Comment: {resource_type}/{resource_id}")
        
    except Exception as e:
        return f"❌ Failed to add comment: {str(e)}"

@mcp.tool()
async def update_config(api_key: str = None, timeout: int = None, default_limit: int = None, debug: bool = None) -> str:
    """Update VirusTotal API configuration at runtime.
    
    Args:
        api_key: New API key
        timeout: New timeout value
        default_limit: New default results limit
        debug: Enable/disable debug mode
    """
    global CONFIG, vt_client
    
    changes = []
    if api_key:
        CONFIG['api_key'] = api_key
        vt_client = VirusTotalAPI(api_key)
        session_data['api_key_valid'] = False  # Reset validation
        changes.append("API Key: Updated")
    if timeout:
        CONFIG['timeout'] = timeout
        changes.append(f"Timeout: {timeout}s")
    if default_limit:
        CONFIG['default_limit'] = default_limit
        changes.append(f"Default Limit: {default_limit}")
    if debug is not None:
        vt_client.set_debug(debug)
        changes.append(f"Debug: {'Enabled' if debug else 'Disabled'}")
    
    if changes:
        return "✅ Updated:\n" + "\n".join(f"   • {change}" for change in changes)
    else:
        return "No changes made - no parameters provided"

@mcp.tool()
async def get_api_info() -> str:
    """Get information about the VirusTotal API endpoints and usage."""
    return """
📖 VirusTotal API v3 Information

🔗 Base URL: https://www.virustotal.com/api/v3

🔑 Authentication:
   • API Key required (x-apikey header)
   • Get API key: https://www.virustotal.com/gui/join-us

📊 Rate Limits:
   • Public API: 4 requests/minute
   • Premium API: Higher limits based on plan

🛠️ Available Endpoints:

📄 File Analysis:
   • POST /files - Upload file for analysis
   • GET /files/{hash} - Get file report by hash
   
🌐 URL Analysis:
   • POST /urls - Submit URL for analysis
   • GET /urls/{url_id} - Get URL analysis report
   
🌍 Domain Analysis:
   • GET /domains/{domain} - Get domain report
   
🖥️ IP Analysis:
   • GET /ip_addresses/{ip} - Get IP address report
   
🔍 Analysis Results:
   • GET /analyses/{id} - Get analysis by ID
   
🧠 Intelligence:
   • GET /intelligence/search - Search using VT Query Language
   
💬 Comments:
   • GET /{resource_type}/{id}/comments - Get comments
   • POST /{resource_type}/{id}/comments - Add comment

📚 Query Language Examples:
   • type:peexe size:500KB+ - PE files larger than 500KB
   • engines:5+ tag:trojan - Files detected by 5+ engines as trojan
   • domain:example.com - Files communicating with domain
   • ip:1.2.3.4 - Files communicating with IP

🔗 Documentation: https://developers.virustotal.com/reference/overview
"""

if __name__ == "__main__":
    print("🚀 Starting VirusTotal MCP Server...", file=sys.stderr)
    print(f"🔑 API Key: {'Configured' if CONFIG['api_key'] else 'NOT SET'}", file=sys.stderr)
    print(f"⏱️  Timeout: {CONFIG['timeout']}s", file=sys.stderr)
    print(f"📊 Default Limit: {CONFIG['default_limit']}", file=sys.stderr)
    print("", file=sys.stderr)
    
    if not CONFIG['api_key']:
        print("⚠️  WARNING: No API key configured!", file=sys.stderr)
        print("   Set VIRUSTOTAL_API_KEY environment variable", file=sys.stderr)
        print("   Get API key at: https://www.virustotal.com/gui/join-us", file=sys.stderr)
        print("", file=sys.stderr)
    
    mcp.run(transport='stdio')