#!/usr/bin/env python3

import os
import sys
import json
import requests
import time
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from urllib.parse import urlencode

# Initialize FastMCP server
mcp = FastMCP("NIST NVD Vulnerability Database")

# Load environment variables
load_dotenv()

class NVDAPI:
    """NIST NVD REST API client."""
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json"
        self.api_key = None
        self.session = requests.Session()
        self.rate_limit_delay = 6  # Default delay for no API key (10 requests per minute)
        self.last_request_time = 0
        self._debug = False
        
        # Set user agent as recommended by NIST
        self.session.headers.update({
            'User-Agent': 'NVD-MCP-Client/1.0'
        })

    def set_api_key(self, api_key: str):
        """Set API key for authentication."""
        self.api_key = api_key
        self.session.headers.update({'apiKey': api_key})
        self.rate_limit_delay = 0.6  # With API key: 100 requests per minute
        
    def debug(self, status: bool):
        """Enable/disable debug logging."""
        self._debug = status

    def _rate_limit(self):
        """Implement rate limiting."""
        if self.rate_limit_delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - elapsed
                if self._debug:
                    print(f"Rate limiting: sleeping {sleep_time:.2f}s", file=sys.stderr)
                time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> requests.Response:
        """Make API request with rate limiting."""
        self._rate_limit()
        
        url = f"{self.base_url}/{endpoint}"
        if self._debug:
            print(f"Making request to: {url}", file=sys.stderr)
            if params:
                print(f"Parameters: {params}", file=sys.stderr)
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            
            if self._debug:
                print(f"Response status: {response.status_code}", file=sys.stderr)
                print(f"Response headers: {dict(response.headers)}", file=sys.stderr)
            
            return response
        except requests.RequestException as e:
            if self._debug:
                print(f"Request failed: {str(e)}", file=sys.stderr)
            raise

    def search_cves(self, **kwargs) -> requests.Response:
        """Search CVE database."""
        return self._make_request("cves/2.0", params=kwargs)

    def get_cve(self, cve_id: str) -> requests.Response:
        """Get specific CVE by ID."""
        params = {'cveId': cve_id}
        return self._make_request("cves/2.0", params=params)

    def search_cpes(self, **kwargs) -> requests.Response:
        """Search CPE database."""
        return self._make_request("cpes/2.0", params=kwargs)

    def get_cpe(self, cpe_name: str) -> requests.Response:
        """Get specific CPE by name."""
        params = {'cpeName': cpe_name}
        return self._make_request("cpes/2.0", params=params)

    def get_cve_history(self, **kwargs) -> requests.Response:
        """Get CVE change history."""
        return self._make_request("cvehistory/2.0", params=kwargs)

    def search_products(self, **kwargs) -> requests.Response:
        """Search products database."""
        return self._make_request("products/2.0", params=kwargs)

    def get_sources(self, **kwargs) -> requests.Response:
        """Get vulnerability data sources."""
        return self._make_request("source/2.0", params=kwargs)


# Configuration from environment variables
def load_config() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    config = {
        'api_key': os.getenv('NVD_API_KEY', ''),
        'results_per_page': int(os.getenv('NVD_RESULTS_PER_PAGE', '20')),
        'timeout': int(os.getenv('NVD_TIMEOUT', '30')),
        'debug': os.getenv('NVD_DEBUG', 'false').lower() in ('true', '1', 'yes')
    }
    
    print("NIST NVD Configuration loaded:", file=sys.stderr)
    print(f"  API Key: {'Set (enables 100 req/min)' if config['api_key'] else 'NOT SET (10 req/min limit)'}", file=sys.stderr)
    print(f"  Results per page: {config['results_per_page']}", file=sys.stderr)
    print(f"  Timeout: {config['timeout']}s", file=sys.stderr)
    print(f"  Debug: {config['debug']}", file=sys.stderr)
    
    return config

# Load configuration
CONFIG = load_config()

# Global NVD client instance
nvd_client = NVDAPI()
if CONFIG['api_key']:
    nvd_client.set_api_key(CONFIG['api_key'])
if CONFIG['debug']:
    nvd_client.debug(True)

# Global state
session_data = {
    'requests_made': 0,
    'last_request_time': None,
    'rate_limit_status': f"{'100' if CONFIG['api_key'] else '10'} requests/minute"
}

def format_response(response: requests.Response) -> Dict[str, Any]:
    """Format API response for display."""
    session_data['requests_made'] += 1
    session_data['last_request_time'] = datetime.now().isoformat()
    
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

def format_vulnerability_summary(vuln_data: Dict[str, Any]) -> str:
    """Format vulnerability data for readable display."""
    cve = vuln_data.get('cve', {})
    cve_id = cve.get('id', 'Unknown')
    
    # Get description
    descriptions = cve.get('descriptions', [])
    description = "No description available"
    for desc in descriptions:
        if desc.get('lang') == 'en':
            description = desc.get('value', description)
            break
    
    # Get CVSS scores
    metrics = cve.get('metrics', {})
    cvss_info = []
    
    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if version in metrics and metrics[version]:
            metric = metrics[version][0]  # Take first metric
            cvss_data = metric.get('cvssData', {})
            score = cvss_data.get('baseScore')
            severity = cvss_data.get('baseSeverity', metric.get('baseSeverity', 'Unknown'))
            if score:
                cvss_info.append(f"CVSS {version[-2:]}: {score} ({severity})")
    
    # Get published/modified dates
    published = cve.get('published', 'Unknown')
    last_modified = cve.get('lastModified', 'Unknown')
    
    # Get references
    references = cve.get('references', [])
    ref_count = len(references)
    
    # Format configuration/affected products
    configurations = cve.get('configurations', [])
    affected_products = []
    for config in configurations:
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable', False):
                    criteria = cpe_match.get('criteria', '')
                    if criteria:
                        # Parse CPE to get readable product name
                        parts = criteria.split(':')
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5] if len(parts) > 5 and parts[5] != '*' else ''
                            product_str = f"{vendor} {product}"
                            if version:
                                product_str += f" {version}"
                            affected_products.append(product_str)
    
    result = f"""
🔍 {cve_id}
📝 Description: {description[:200]}{'...' if len(description) > 200 else ''}

📊 Severity:
""" + (f"   {chr(10).join(cvss_info)}" if cvss_info else "   No CVSS scores available") + f"""

📅 Timeline:
   Published: {published[:10] if 'T' in published else published}
   Modified: {last_modified[:10] if 'T' in last_modified else last_modified}

🔗 References: {ref_count} available
"""
    
    if affected_products:
        result += f"\n🎯 Affected Products (sample):\n"
        for product in affected_products[:5]:  # Show first 5
            result += f"   • {product}\n"
        if len(affected_products) > 5:
            result += f"   ... and {len(affected_products) - 5} more\n"
    
    return result

def format_output(response_data: Dict[str, Any], title: str = "NVD API Response") -> str:
    """Format response data for user display."""
    status_icon = "✅" if response_data['success'] else "❌"
    
    result = f"{status_icon} {title}\n"
    result += f"HTTP Status: {response_data['status_code']}\n"
    
    if response_data['success'] and 'data' in response_data:
        data = response_data['data']
        
        # Special formatting for vulnerabilities
        if 'vulnerabilities' in data:
            vulns = data['vulnerabilities']
            total_results = data.get('totalResults', len(vulns))
            results_per_page = data.get('resultsPerPage', len(vulns))
            start_index = data.get('startIndex', 0)
            
            result += f"📊 Results: {len(vulns)} of {total_results} total (starting at {start_index})\n"
            result += f"📄 Page size: {results_per_page}\n\n"
            
            if vulns:
                result += "🔍 Vulnerabilities Found:\n"
                for vuln in vulns:
                    result += format_vulnerability_summary(vuln)
                    result += "\n" + "="*50 + "\n"
            else:
                result += "No vulnerabilities found matching the criteria.\n"
        
        # Special formatting for CPEs
        elif 'products' in data:
            products = data['products']
            total_results = data.get('totalResults', len(products))
            
            result += f"📊 Products: {len(products)} of {total_results} total\n\n"
            
            if products:
                result += "🎯 Products Found:\n"
                for product in products:
                    cpe = product.get('cpe', {})
                    cpe_name = cpe.get('cpeName', 'Unknown')
                    titles = cpe.get('titles', [])
                    title_text = "No title"
                    for title_obj in titles:
                        if title_obj.get('lang') == 'en':
                            title_text = title_obj.get('title', title_text)
                            break
                    
                    result += f"   • {cpe_name}\n"
                    result += f"     Title: {title_text}\n\n"
        
        # Generic formatting for other data
        else:
            result += "\nResponse Data:\n"
            result += json.dumps(data, indent=2)
    
    elif not response_data['success']:
        result += f"❌ Error: {response_data.get('data', {}).get('message', 'Unknown error')}\n"
    
    result += f"\n🕒 Request made at: {session_data['last_request_time']}"
    result += f"\n📈 Total requests: {session_data['requests_made']}"
    result += f"\n⚡ Rate limit: {session_data['rate_limit_status']}"
    
    return result

@mcp.tool()
async def get_status() -> str:
    """Get current NVD API client status and configuration."""
    api_key_status = "✅ Set (100 req/min)" if CONFIG['api_key'] else "❌ Not set (10 req/min limit)"
    
    return f"""
📊 NIST NVD API Status

🔑 Authentication:
   • API Key: {api_key_status}
   • Rate Limit: {session_data['rate_limit_status']}

📈 Usage Statistics:
   • Requests Made: {session_data['requests_made']}
   • Last Request: {session_data['last_request_time'] or 'None'}

⚙️ Configuration:
   • Results per page: {CONFIG['results_per_page']}
   • Timeout: {CONFIG['timeout']}s
   • Debug mode: {CONFIG['debug']}

🌐 API Endpoints Available:
   • CVE Search: search_cves()
   • Specific CVE: get_cve()
   • CPE Search: search_cpes()
   • CVE History: get_cve_history()
   • Product Search: search_products()

⚙️ Environment Variables:
   Set these to customize behavior:
   • NVD_API_KEY={'***' if CONFIG['api_key'] else 'NOT SET'}
   • NVD_RESULTS_PER_PAGE={CONFIG['results_per_page']}
   • NVD_TIMEOUT={CONFIG['timeout']}
   • NVD_DEBUG={CONFIG['debug']}

💡 Quick Start:
   1. search_recent_cves() - See latest vulnerabilities
   2. search_cves_by_keyword() - Search by technology/vendor
   3. get_high_severity_cves() - Find critical vulnerabilities
"""

@mcp.tool()
async def search_cves_by_keyword(keyword: str, results_per_page: int = None, 
                                start_index: int = 0, days_back: int = None) -> str:
    """Search CVEs by keyword.
    
    Args:
        keyword: Search term (vendor, product, technology)
        results_per_page: Number of results per page (default from config)
        start_index: Starting index for pagination
        days_back: Only show CVEs from last N days
    """
    try:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': results_per_page or CONFIG['results_per_page'],
            'startIndex': start_index
        }
        
        if days_back:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            params['pubStartDate'] = start_date.strftime('%Y-%m-%dT00:00:00.000')
            params['pubEndDate'] = end_date.strftime('%Y-%m-%dT23:59:59.999')
        
        response = nvd_client.search_cves(**params)
        response_data = format_response(response)
        
        return format_output(response_data, f"CVE Search Results for '{keyword}'")
        
    except Exception as e:
        return f"❌ Failed to search CVEs: {str(e)}"

@mcp.tool()
async def get_cve(cve_id: str) -> str:
    """Get detailed information about a specific CVE.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
    """
    try:
        # Ensure CVE-ID format
        if not cve_id.upper().startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        
        response = nvd_client.get_cve(cve_id)
        response_data = format_response(response)
        
        return format_output(response_data, f"CVE Details for {cve_id}")
        
    except Exception as e:
        return f"❌ Failed to get CVE {cve_id}: {str(e)}"

@mcp.tool()
async def search_recent_cves(days_back: int = 7, results_per_page: int = None) -> str:
    """Search for recently published CVEs.
    
    Args:
        days_back: Number of days to look back (default: 7)
        results_per_page: Number of results per page
    """
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': results_per_page or CONFIG['results_per_page']
        }
        
        response = nvd_client.search_cves(**params)
        response_data = format_response(response)
        
        return format_output(response_data, f"Recent CVEs (Last {days_back} days)")
        
    except Exception as e:
        return f"❌ Failed to search recent CVEs: {str(e)}"

@mcp.tool()
async def get_high_severity_cves(days_back: int = 30, min_score: float = 9.0, 
                                results_per_page: int = None) -> str:
    """Get high severity CVEs from recent timeframe.
    
    Args:
        days_back: Number of days to look back (default: 30)
        min_score: Minimum CVSS score (default: 9.0 for critical)
        results_per_page: Number of results per page
    """
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'cvssV3Severity': 'CRITICAL' if min_score >= 9.0 else 'HIGH',
            'resultsPerPage': results_per_page or CONFIG['results_per_page']
        }
        
        response = nvd_client.search_cves(**params)
        response_data = format_response(response)
        
        severity_label = "CRITICAL" if min_score >= 9.0 else "HIGH"
        return format_output(response_data, f"{severity_label} Severity CVEs (Last {days_back} days)")
        
    except Exception as e:
        return f"❌ Failed to search high severity CVEs: {str(e)}"

@mcp.tool()
async def search_cves_by_vendor(vendor: str, product: str = None, days_back: int = None,
                               results_per_page: int = None) -> str:
    """Search CVEs affecting a specific vendor or product.
    
    Args:
        vendor: Vendor name (e.g., 'microsoft', 'apache', 'cisco')
        product: Specific product name (optional)
        days_back: Only show CVEs from last N days
        results_per_page: Number of results per page
    """
    try:
        # Build search keyword
        search_term = vendor
        if product:
            search_term += f" {product}"
            
        params = {
            'keywordSearch': search_term,
            'resultsPerPage': results_per_page or CONFIG['results_per_page']
        }
        
        if days_back:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            params['pubStartDate'] = start_date.strftime('%Y-%m-%dT00:00:00.000')
            params['pubEndDate'] = end_date.strftime('%Y-%m-%dT23:59:59.999')
        
        response = nvd_client.search_cves(**params)
        response_data = format_response(response)
        
        title = f"CVEs for {vendor}"
        if product:
            title += f" {product}"
        if days_back:
            title += f" (Last {days_back} days)"
            
        return format_output(response_data, title)
        
    except Exception as e:
        return f"❌ Failed to search CVEs for {vendor}: {str(e)}"

@mcp.tool()
async def search_cpes(keyword: str, results_per_page: int = None, 
                     start_index: int = 0) -> str:
    """Search Common Platform Enumeration (CPE) entries.
    
    Args:
        keyword: Search term for product/vendor
        results_per_page: Number of results per page
        start_index: Starting index for pagination
    """
    try:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': results_per_page or CONFIG['results_per_page'],
            'startIndex': start_index
        }
        
        response = nvd_client.search_cpes(**params)
        response_data = format_response(response)
        
        return format_output(response_data, f"CPE Search Results for '{keyword}'")
        
    except Exception as e:
        return f"❌ Failed to search CPEs: {str(e)}"

@mcp.tool()
async def get_cve_history(cve_id: str = None, change_start_date: str = None,
                         change_end_date: str = None, results_per_page: int = None) -> str:
    """Get CVE change history.
    
    Args:
        cve_id: Specific CVE ID to get history for
        change_start_date: Start date for changes (YYYY-MM-DD format)
        change_end_date: End date for changes (YYYY-MM-DD format)
        results_per_page: Number of results per page
    """
    try:
        params = {
            'resultsPerPage': results_per_page or CONFIG['results_per_page']
        }
        
        if cve_id:
            if not cve_id.upper().startswith('CVE-'):
                cve_id = f'CVE-{cve_id}'
            params['cveId'] = cve_id
            
        if change_start_date:
            params['changeStartDate'] = f"{change_start_date}T00:00:00.000"
        if change_end_date:
            params['changeEndDate'] = f"{change_end_date}T23:59:59.999"
        
        response = nvd_client.get_cve_history(**params)
        response_data = format_response(response)
        
        title = "CVE Change History"
        if cve_id:
            title += f" for {cve_id}"
            
        return format_output(response_data, title)
        
    except Exception as e:
        return f"❌ Failed to get CVE history: {str(e)}"

@mcp.tool()
async def update_config(api_key: str = None, results_per_page: int = None,
                       timeout: int = None, debug: bool = None) -> str:
    """Update NVD API configuration at runtime.
    
    Args:
        api_key: New API key
        results_per_page: New default results per page
        timeout: New timeout value
        debug: Enable/disable debug mode
    """
    global CONFIG
    
    changes = []
    
    if api_key is not None:
        CONFIG['api_key'] = api_key
        if api_key:
            nvd_client.set_api_key(api_key)
            session_data['rate_limit_status'] = "100 requests/minute"
            changes.append("API Key: Set (100 req/min enabled)")
        else:
            nvd_client.api_key = None
            if 'apiKey' in nvd_client.session.headers:
                del nvd_client.session.headers['apiKey']
            nvd_client.rate_limit_delay = 6
            session_data['rate_limit_status'] = "10 requests/minute"
            changes.append("API Key: Removed (10 req/min limit)")
    
    if results_per_page is not None:
        CONFIG['results_per_page'] = results_per_page
        changes.append(f"Results per page: {results_per_page}")
    
    if timeout is not None:
        CONFIG['timeout'] = timeout
        changes.append(f"Timeout: {timeout}s")
    
    if debug is not None:
        CONFIG['debug'] = debug
        nvd_client.debug(debug)
        changes.append(f"Debug mode: {'Enabled' if debug else 'Disabled'}")
    
    if changes:
        return "✅ Updated:\n" + "\n".join(f"   • {change}" for change in changes)
    else:
        return "No changes made - no parameters provided"

@mcp.tool()
async def get_api_info() -> str:
    """Get information about the NVD API endpoints and usage."""
    return """
📚 NIST NVD API Information

🔍 Available Search Methods:
   • search_cves_by_keyword() - Search CVEs by any keyword
   • get_cve() - Get specific CVE details
   • search_recent_cves() - Get recently published CVEs
   • get_high_severity_cves() - Find critical/high severity CVEs
   • search_cves_by_vendor() - Search by vendor/product
   • search_cpes() - Search Common Platform Enumeration
   • get_cve_history() - Get CVE change history

🔑 API Key Benefits:
   Without API Key: 10 requests per minute
   With API Key: 100 requests per minute
   Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key

📊 CVSS Severity Levels:
   • CRITICAL: 9.0-10.0
   • HIGH: 7.0-8.9
   • MEDIUM: 4.0-6.9
   • LOW: 0.1-3.9

🎯 CPE Format Example:
   cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

📅 Date Formats:
   • Simple: YYYY-MM-DD (e.g., 2024-01-01)
   • API Format: YYYY-MM-DDTHH:MM:SS.sss

🔗 Useful Links:
   • NVD API Documentation: https://nvd.nist.gov/developers/vulnerabilities
   • CVE Details: https://cve.mitre.org/
   • CVSS Calculator: https://www.first.org/cvss/calculator/
"""

if __name__ == "__main__":
    print("🚀 Starting NIST NVD MCP Server...", file=sys.stderr)
    print(f"🔑 API Key: {'Configured (100 req/min)' if CONFIG['api_key'] else 'NOT SET (10 req/min limit)'}", file=sys.stderr)
    print(f"📄 Results per page: {CONFIG['results_per_page']}", file=sys.stderr)
    print(f"⏱️  Timeout: {CONFIG['timeout']}s", file=sys.stderr)
    print(f"🐛 Debug: {CONFIG['debug']}", file=sys.stderr)
    print("", file=sys.stderr)
    print("💡 Get your free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key", file=sys.stderr)
    print("", file=sys.stderr)
    
    mcp.run(transport='stdio')