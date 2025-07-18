#!/usr/bin/env python3

import os
import sys
import json
import requests
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Load environment variables
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("n8n")

# Configuration from environment variables
N8N_HOST = os.getenv('N8N_HOST', 'localhost')
N8N_PORT = os.getenv('N8N_PORT', '5678')
N8N_API_KEY = os.getenv('N8N_API_KEY', '')
N8N_USE_HTTPS = os.getenv('N8N_USE_HTTPS', 'false').lower() == 'true'

class N8nAPI:
    """N8n API client with proper error handling and response formatting."""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = f"{'https' if N8N_USE_HTTPS else 'http'}://{N8N_HOST}:{N8N_PORT}/api/v1"
        self.headers = {
            'X-N8N-API-KEY': N8N_API_KEY,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.session.headers.update(self.headers)
        
        # Disable SSL verification for HTTPS if needed
        if N8N_USE_HTTPS:
            self.session.verify = False
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an API request and return formatted response."""
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))
        
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            
            # Parse JSON response if available
            try:
                data = response.json() if response.content else {}
            except json.JSONDecodeError:
                data = {'raw_content': response.text}
            
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'data': data,
                'url': url
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'status_code': 0,
                'data': {'error': str(e)},
                'url': url
            }
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """GET request."""
        return self._make_request('GET', endpoint, params=params)
    
    def post(self, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
        """POST request."""
        return self._make_request('POST', endpoint, json=data, params=params)
    
    def put(self, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
        """PUT request."""
        return self._make_request('PUT', endpoint, json=data, params=params)
    
    def delete(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """DELETE request."""
        return self._make_request('DELETE', endpoint, params=params)
    
    def patch(self, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
        """PATCH request."""
        return self._make_request('PATCH', endpoint, json=data, params=params)

# Initialize API client
api = N8nAPI()

# =============================================================================
# CONNECTION AND STATUS TOOLS
# =============================================================================

@mcp.tool()
def test_connection() -> str:
    """Test connectivity to the n8n instance."""
    if not N8N_API_KEY:
        return "❌ No API key configured. Set N8N_API_KEY environment variable."
    
    result = api.get('workflows', params={'limit': 1})
    
    if result['success']:
        return f"✅ Connected to n8n at {N8N_HOST}:{N8N_PORT}"
    elif result['status_code'] == 401:
        return "❌ Authentication failed. Check API key."
    elif result['status_code'] == 0:
        return f"❌ Connection failed: {result['data'].get('error', 'Unknown error')}"
    else:
        return f"❌ Connection failed. HTTP {result['status_code']}"

@mcp.tool()
def get_status() -> str:
    """Get current connection status and configuration."""
    api_key_status = "✅ Set" if N8N_API_KEY else "❌ Not set"
    protocol = "HTTPS" if N8N_USE_HTTPS else "HTTP"
    
    # Test connection
    connection_test = api.get('workflows', params={'limit': 1})
    connection_status = "✅ Connected" if connection_test['success'] else "❌ Not connected"
    
    return f"""📊 n8n MCP Server Status
• Host: {N8N_HOST}:{N8N_PORT}
• Protocol: {protocol}
• API Key: {api_key_status}
• Connection: {connection_status}

💡 Available Commands:
• Workflows: get_workflows, create_workflow_from_json, create_basic_workflow
• Management: activate_workflow, deactivate_workflow, delete_workflow
• Details: get_workflow_details, export_workflow
• Users: get_users, create_user, delete_user
• Executions: get_executions, get_execution_details
• Credentials: get_credentials, create_credential
• Variables: get_variables, create_variable, update_variable
"""

@mcp.tool()
def enable_debug() -> str:
    """Enable debug logging for API requests."""
    import logging
    logging.basicConfig(level=logging.DEBUG)
    return "✅ Debug logging enabled"

@mcp.tool()
def disable_debug() -> str:
    """Disable debug logging for API requests."""
    import logging
    logging.basicConfig(level=logging.INFO)
    return "✅ Debug logging disabled"

# =============================================================================
# WORKFLOW MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_workflows() -> str:
    """List all workflows."""
    result = api.get('workflows')
    
    if not result['success']:
        return f"❌ Failed to get workflows: HTTP {result['status_code']}"
    
    workflows = result['data'].get('data', [])
    
    if not workflows:
        return "📋 No workflows found."
    
    output = f"📋 Found {len(workflows)} workflows:\n\n"
    for wf in workflows:
        status = "🟢 Active" if wf.get('active') else "🔴 Inactive"
        name = wf.get('name', 'Unnamed')
        wf_id = wf.get('id')
        created = wf.get('createdAt', 'Unknown')
        
        output += f"• {name} (ID: {wf_id})\n"
        output += f"  Status: {status}\n"
        output += f"  Created: {created}\n\n"
    
    return output

@mcp.tool()
def create_workflow_from_json(workflow_json: str) -> str:
    """Create a workflow from JSON definition.
    
    Args:
        workflow_json: Complete workflow JSON as string
    """
    try:
        workflow_data = json.loads(workflow_json)
    except json.JSONDecodeError as e:
        return f"❌ Invalid JSON: {str(e)}"
    
    # Ensure required fields exist
    if 'name' not in workflow_data:
        workflow_data['name'] = 'Imported Workflow'
    if 'nodes' not in workflow_data:
        workflow_data['nodes'] = []
    if 'connections' not in workflow_data:
        workflow_data['connections'] = {}
    if 'settings' not in workflow_data:
        workflow_data['settings'] = {}
    
    result = api.post('workflows', data=workflow_data)
    
    if not result['success']:
        error_msg = result['data'].get('message', 'Unknown error')
        return f"❌ Failed to create workflow: {error_msg}"
    
    workflow = result['data']
    workflow_id = workflow.get('id')
    workflow_name = workflow.get('name')
    
    # Extract webhook URLs if present
    webhook_urls = []
    for node in workflow_data.get('nodes', []):
        if node.get('type') == 'n8n-nodes-base.webhook':
            webhook_path = node.get('parameters', {}).get('path')
            if webhook_path:
                base_url = f"{'https' if N8N_USE_HTTPS else 'http'}://{N8N_HOST}:{N8N_PORT}"
                webhook_urls.append(f"{base_url}/webhook/{webhook_path}")
    
    output = f"✅ Workflow '{workflow_name}' created successfully!\n"
    output += f"• ID: {workflow_id}\n"
    output += f"• Status: {'🟢 Active' if workflow.get('active') else '🔴 Inactive'}\n"
    output += f"• Nodes: {len(workflow_data.get('nodes', []))}\n"
    
    if webhook_urls:
        output += f"• Webhook URLs:\n"
        for url in webhook_urls:
            output += f"  - {url}\n"
    
    return output

@mcp.tool()
def create_basic_workflow(name: str, webhook_path: str, description: str = "Basic workflow") -> str:
    """Create a basic webhook workflow template.
    
    Args:
        name: Workflow name
        webhook_path: Webhook path (e.g., 'my-webhook')
        description: Workflow description
    """
    workflow_data = {
        "name": name,
        "active": False,
        "nodes": [
            {
                "id": "webhook-node",
                "name": "Webhook",
                "type": "n8n-nodes-base.webhook",
                "position": [240, 300],
                "parameters": {
                    "path": webhook_path,
                    "httpMethod": "POST",
                    "responseMode": "responseNode"
                },
                "typeVersion": 1
            },
            {
                "id": "set-node",
                "name": "Set",
                "type": "n8n-nodes-base.set",
                "position": [460, 300],
                "parameters": {
                    "assignments": {
                        "assignments": [
                            {
                                "id": "timestamp",
                                "name": "timestamp",
                                "type": "string",
                                "value": "={{ new Date().toISOString() }}"
                            },
                            {
                                "id": "workflow_name",
                                "name": "workflow_name",
                                "type": "string",
                                "value": name
                            }
                        ]
                    }
                },
                "typeVersion": 3
            },
            {
                "id": "respond-node",
                "name": "Respond to Webhook",
                "type": "n8n-nodes-base.respondToWebhook",
                "position": [680, 300],
                "parameters": {
                    "options": {}
                },
                "typeVersion": 1
            }
        ],
        "connections": {
            "Webhook": {
                "main": [
                    [
                        {
                            "node": "Set",
                            "type": "main",
                            "index": 0
                        }
                    ]
                ]
            },
            "Set": {
                "main": [
                    [
                        {
                            "node": "Respond to Webhook",
                            "type": "main",
                            "index": 0
                        }
                    ]
                ]
            }
        },
        "settings": {
            "executionOrder": "v1"
        }
    }
    
    result = api.post('workflows', data=workflow_data)
    
    if not result['success']:
        error_msg = result['data'].get('message', 'Unknown error')
        return f"❌ Failed to create basic workflow: {error_msg}"
    
    workflow = result['data']
    workflow_id = workflow.get('id')
    webhook_url = f"{'https' if N8N_USE_HTTPS else 'http'}://{N8N_HOST}:{N8N_PORT}/webhook/{webhook_path}"
    
    return f"""✅ Basic workflow '{name}' created successfully!
• ID: {workflow_id}
• Status: 🔴 Inactive
• Webhook URL: {webhook_url}

💡 Next steps:
1. Use activate_workflow('{workflow_id}') to activate
2. Test by sending POST request to webhook URL
"""

@mcp.tool()
def activate_workflow(workflow_id: str) -> str:
    """Activate a workflow.
    
    Args:
        workflow_id: The ID of the workflow to activate
    """
    result = api.post(f'workflows/{workflow_id}/activate')
    
    if result['success']:
        return f"✅ Workflow {workflow_id} activated successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to activate workflow: {error_msg}"

@mcp.tool()
def deactivate_workflow(workflow_id: str) -> str:
    """Deactivate a workflow.
    
    Args:
        workflow_id: The ID of the workflow to deactivate
    """
    result = api.post(f'workflows/{workflow_id}/deactivate')
    
    if result['success']:
        return f"✅ Workflow {workflow_id} deactivated successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to deactivate workflow: {error_msg}"

@mcp.tool()
def delete_workflow(workflow_id: str) -> str:
    """Delete a workflow.
    
    Args:
        workflow_id: The ID of the workflow to delete
    """
    result = api.delete(f'workflows/{workflow_id}')
    
    if result['success']:
        return f"✅ Workflow {workflow_id} deleted successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to delete workflow: {error_msg}"

@mcp.tool()
def get_workflow_details(workflow_id: str) -> str:
    """Get detailed information about a workflow.
    
    Args:
        workflow_id: The ID of the workflow to retrieve
    """
    result = api.get(f'workflows/{workflow_id}')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get workflow details: {error_msg}"
    
    workflow = result['data']
    
    # Extract webhook URLs
    webhook_urls = []
    for node in workflow.get('nodes', []):
        if node.get('type') == 'n8n-nodes-base.webhook':
            webhook_path = node.get('parameters', {}).get('path')
            if webhook_path:
                base_url = f"{'https' if N8N_USE_HTTPS else 'http'}://{N8N_HOST}:{N8N_PORT}"
                webhook_urls.append(f"{base_url}/webhook/{webhook_path}")
    
    output = f"📋 Workflow Details\n"
    output += f"• Name: {workflow.get('name', 'Unnamed')}\n"
    output += f"• ID: {workflow.get('id')}\n"
    output += f"• Status: {'🟢 Active' if workflow.get('active') else '🔴 Inactive'}\n"
    output += f"• Nodes: {len(workflow.get('nodes', []))}\n"
    output += f"• Created: {workflow.get('createdAt', 'Unknown')}\n"
    output += f"• Updated: {workflow.get('updatedAt', 'Unknown')}\n"
    
    if webhook_urls:
        output += f"• Webhook URLs:\n"
        for url in webhook_urls:
            output += f"  - {url}\n"
    
    # Show tags if present
    tags = workflow.get('tags', [])
    if tags:
        tag_names = [tag.get('name', 'Unnamed') for tag in tags]
        output += f"• Tags: {', '.join(tag_names)}\n"
    
    return output

@mcp.tool()
def export_workflow(workflow_id: str) -> str:
    """Export a workflow as JSON.
    
    Args:
        workflow_id: The ID of the workflow to export
    """
    result = api.get(f'workflows/{workflow_id}')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to export workflow: {error_msg}"
    
    workflow_data = result['data']
    
    # Clean up the data for export (remove server-specific fields)
    export_data = {
        'name': workflow_data.get('name'),
        'nodes': workflow_data.get('nodes', []),
        'connections': workflow_data.get('connections', {}),
        'settings': workflow_data.get('settings', {}),
        'staticData': workflow_data.get('staticData'),
        'tags': workflow_data.get('tags', []),
        'pinData': workflow_data.get('pinData', {}),
        'active': workflow_data.get('active', False)
    }
    
    return json.dumps(export_data, indent=2)

# =============================================================================
# EXECUTION MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_executions(workflow_id: Optional[str] = None, limit: int = 10, status: Optional[str] = None) -> str:
    """Retrieve executions.
    
    Args:
        workflow_id: Filter by workflow ID (optional)
        limit: Maximum number of executions to return (default: 10)
        status: Filter by status: 'success', 'error', or 'waiting' (optional)
    """
    params = {'limit': min(limit, 100)}
    
    if workflow_id:
        params['workflowId'] = workflow_id
    if status:
        params['status'] = status
    
    result = api.get('executions', params=params)
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get executions: {error_msg}"
    
    executions = result['data'].get('data', [])
    
    if not executions:
        return "📋 No executions found."
    
    output = f"📋 Found {len(executions)} executions:\n\n"
    
    for exec_data in executions:
        exec_id = exec_data.get('id')
        workflow_name = exec_data.get('workflowName', 'Unknown')
        started = exec_data.get('startedAt', 'Unknown')
        finished = exec_data.get('finished', False)
        mode = exec_data.get('mode', 'Unknown')
        
        status_icon = "✅" if finished else "⏳"
        output += f"• {status_icon} Execution {exec_id}\n"
        output += f"  Workflow: {workflow_name}\n"
        output += f"  Started: {started}\n"
        output += f"  Mode: {mode}\n"
        output += f"  Status: {'Finished' if finished else 'Running'}\n\n"
    
    return output

@mcp.tool()
def get_execution_details(execution_id: str) -> str:
    """Get detailed information about an execution.
    
    Args:
        execution_id: The ID of the execution to retrieve
    """
    result = api.get(f'executions/{execution_id}')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get execution details: {error_msg}"
    
    execution = result['data']
    
    output = f"📋 Execution Details\n"
    output += f"• ID: {execution.get('id')}\n"
    output += f"• Workflow ID: {execution.get('workflowId')}\n"
    output += f"• Status: {'✅ Finished' if execution.get('finished') else '⏳ Running'}\n"
    output += f"• Mode: {execution.get('mode', 'Unknown')}\n"
    output += f"• Started: {execution.get('startedAt', 'Unknown')}\n"
    output += f"• Stopped: {execution.get('stoppedAt', 'N/A')}\n"
    
    if execution.get('retryOf'):
        output += f"• Retry of: {execution.get('retryOf')}\n"
    
    return output

# =============================================================================
# USER MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_users() -> str:
    """List all users (instance owner only)."""
    result = api.get('users')
    
    if not result['success']:
        if result['status_code'] == 403:
            return "❌ Access denied. Only instance owners can list users."
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get users: {error_msg}"
    
    users = result['data'].get('data', [])
    
    if not users:
        return "📋 No users found."
    
    output = f"📋 Found {len(users)} users:\n\n"
    
    for user in users:
        email = user.get('email', 'Unknown')
        name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip()
        user_id = user.get('id')
        role = user.get('role', 'Unknown')
        pending = user.get('isPending', False)
        
        status_icon = "⏳" if pending else "✅"
        output += f"• {status_icon} {email}\n"
        if name:
            output += f"  Name: {name}\n"
        output += f"  ID: {user_id}\n"
        output += f"  Role: {role}\n"
        output += f"  Status: {'Pending' if pending else 'Active'}\n\n"
    
    return output

@mcp.tool()
def create_user(email: str, role: str = "global:member") -> str:
    """Create a new user.
    
    Args:
        email: User's email address
        role: User role, either 'global:admin' or 'global:member' (default: 'global:member')
    """
    if role not in ['global:admin', 'global:member']:
        return "❌ Invalid role. Must be 'global:admin' or 'global:member'."
    
    user_data = [{"email": email, "role": role}]
    result = api.post('users', data=user_data)
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to create user: {error_msg}"
    
    # The API returns an array of results
    results = result['data'] if isinstance(result['data'], list) else [result['data']]
    
    for user_result in results:
        if user_result.get('error'):
            return f"❌ Failed to create user: {user_result['error']}"
        
        user = user_result.get('user', {})
        invite_url = user.get('inviteAcceptUrl')
        
        output = f"✅ User created successfully!\n"
        output += f"• Email: {user.get('email')}\n"
        output += f"• Role: {role}\n"
        output += f"• ID: {user.get('id')}\n"
        
        if invite_url:
            output += f"• Invite URL: {invite_url}\n"
        
        return output
    
    return "❌ Unexpected response format."

@mcp.tool()
def delete_user(user_id: str) -> str:
    """Delete a user.
    
    Args:
        user_id: The ID or email of the user to delete
    """
    result = api.delete(f'users/{user_id}')
    
    if result['success']:
        return f"✅ User {user_id} deleted successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to delete user: {error_msg}"

# =============================================================================
# VARIABLES MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_variables() -> str:
    """List all variables."""
    result = api.get('variables')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get variables: {error_msg}"
    
    variables = result['data'].get('data', [])
    
    if not variables:
        return "📋 No variables found."
    
    output = f"📋 Found {len(variables)} variables:\n\n"
    
    for var in variables:
        var_id = var.get('id')
        key = var.get('key')
        value = var.get('value', '')
        
        # Truncate long values
        display_value = value[:50] + "..." if len(value) > 50 else value
        
        output += f"• {key}\n"
        output += f"  ID: {var_id}\n"
        output += f"  Value: {display_value}\n\n"
    
    return output

@mcp.tool()
def create_variable(key: str, value: str) -> str:
    """Create a new variable.
    
    Args:
        key: Variable key/name
        value: Variable value
    """
    variable_data = {"key": key, "value": value}
    result = api.post('variables', data=variable_data)
    
    if result['success']:
        return f"✅ Variable '{key}' created successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to create variable: {error_msg}"

@mcp.tool()
def update_variable(variable_id: str, key: str, value: str) -> str:
    """Update an existing variable.
    
    Args:
        variable_id: The ID of the variable to update
        key: Updated variable key/name
        value: Updated variable value
    """
    variable_data = {"key": key, "value": value}
    result = api.put(f'variables/{variable_id}', data=variable_data)
    
    if result['success']:
        return f"✅ Variable '{key}' updated successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to update variable: {error_msg}"

@mcp.tool()
def delete_variable(variable_id: str) -> str:
    """Delete a variable.
    
    Args:
        variable_id: The ID of the variable to delete
    """
    result = api.delete(f'variables/{variable_id}')
    
    if result['success']:
        return f"✅ Variable {variable_id} deleted successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to delete variable: {error_msg}"

# =============================================================================
# CREDENTIALS MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_credentials() -> str:
    """List all credentials (names and types only for security)."""
    result = api.get('credentials')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get credentials: {error_msg}"
    
    credentials = result['data'].get('data', [])
    
    if not credentials:
        return "📋 No credentials found."
    
    output = f"📋 Found {len(credentials)} credentials:\n\n"
    
    for cred in credentials:
        cred_id = cred.get('id')
        name = cred.get('name', 'Unnamed')
        cred_type = cred.get('type', 'Unknown')
        created = cred.get('createdAt', 'Unknown')
        
        output += f"• {name}\n"
        output += f"  ID: {cred_id}\n"
        output += f"  Type: {cred_type}\n"
        output += f"  Created: {created}\n\n"
    
    return output

@mcp.tool()
def create_credential(name: str, credential_type: str, data: str) -> str:
    """Create a new credential.
    
    Args:
        name: Credential name
        credential_type: Type of credential (e.g., 'httpBasicAuth', 'oauth2Api')
        data: Credential data as JSON string
    """
    try:
        cred_data = json.loads(data)
    except json.JSONDecodeError as e:
        return f"❌ Invalid JSON for credential data: {str(e)}"
    
    credential_payload = {
        "name": name,
        "type": credential_type,
        "data": cred_data
    }
    
    result = api.post('credentials', data=credential_payload)
    
    if result['success']:
        cred = result['data']
        return f"✅ Credential '{name}' created successfully (ID: {cred.get('id')})"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to create credential: {error_msg}"

@mcp.tool()
def delete_credential(credential_id: str) -> str:
    """Delete a credential.
    
    Args:
        credential_id: The ID of the credential to delete
    """
    result = api.delete(f'credentials/{credential_id}')
    
    if result['success']:
        return f"✅ Credential {credential_id} deleted successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to delete credential: {error_msg}"

# =============================================================================
# TAGS MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_tags() -> str:
    """List all tags."""
    result = api.get('tags')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get tags: {error_msg}"
    
    tags = result['data'].get('data', [])
    
    if not tags:
        return "📋 No tags found."
    
    output = f"📋 Found {len(tags)} tags:\n\n"
    
    for tag in tags:
        tag_id = tag.get('id')
        name = tag.get('name', 'Unnamed')
        created = tag.get('createdAt', 'Unknown')
        
        output += f"• {name}\n"
        output += f"  ID: {tag_id}\n"
        output += f"  Created: {created}\n\n"
    
    return output

@mcp.tool()
def create_tag(name: str) -> str:
    """Create a new tag.
    
    Args:
        name: Tag name
    """
    tag_data = {"name": name}
    result = api.post('tags', data=tag_data)
    
    if result['success']:
        tag = result['data']
        return f"✅ Tag '{name}' created successfully (ID: {tag.get('id')})"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to create tag: {error_msg}"

@mcp.tool()
def delete_tag(tag_id: str) -> str:
    """Delete a tag.
    
    Args:
        tag_id: The ID of the tag to delete
    """
    result = api.delete(f'tags/{tag_id}')
    
    if result['success']:
        return f"✅ Tag {tag_id} deleted successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to delete tag: {error_msg}"

# =============================================================================
# WORKFLOW TAGS MANAGEMENT
# =============================================================================

@mcp.tool()
def get_workflow_tags(workflow_id: str) -> str:
    """Get tags for a specific workflow.
    
    Args:
        workflow_id: The ID of the workflow
    """
    result = api.get(f'workflows/{workflow_id}/tags')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get workflow tags: {error_msg}"
    
    tags = result['data'] if isinstance(result['data'], list) else []
    
    if not tags:
        return f"📋 No tags found for workflow {workflow_id}."
    
    output = f"📋 Tags for workflow {workflow_id}:\n\n"
    
    for tag in tags:
        tag_id = tag.get('id')
        name = tag.get('name', 'Unnamed')
        
        output += f"• {name} (ID: {tag_id})\n"
    
    return output

@mcp.tool()
def update_workflow_tags(workflow_id: str, tag_ids: str) -> str:
    """Update tags for a workflow.
    
    Args:
        workflow_id: The ID of the workflow
        tag_ids: Comma-separated list of tag IDs to assign to the workflow
    """
    try:
        tag_id_list = [tag_id.strip() for tag_id in tag_ids.split(',') if tag_id.strip()]
        tags_data = [{"id": tag_id} for tag_id in tag_id_list]
    except Exception as e:
        return f"❌ Invalid tag IDs format: {str(e)}"
    
    result = api.put(f'workflows/{workflow_id}/tags', data=tags_data)
    
    if result['success']:
        updated_tags = result['data'] if isinstance(result['data'], list) else []
        tag_names = [tag.get('name', 'Unnamed') for tag in updated_tags]
        return f"✅ Workflow tags updated successfully: {', '.join(tag_names)}"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to update workflow tags: {error_msg}"

# =============================================================================
# PROJECTS MANAGEMENT TOOLS
# =============================================================================

@mcp.tool()
def get_projects() -> str:
    """List all projects."""
    result = api.get('projects')
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get projects: {error_msg}"
    
    projects = result['data'].get('data', [])
    
    if not projects:
        return "📋 No projects found."
    
    output = f"📋 Found {len(projects)} projects:\n\n"
    
    for project in projects:
        project_id = project.get('id')
        name = project.get('name', 'Unnamed')
        created = project.get('createdAt', 'Unknown')
        
        output += f"• {name}\n"
        output += f"  ID: {project_id}\n"
        output += f"  Created: {created}\n\n"
    
    return output

@mcp.tool()
def create_project(name: str) -> str:
    """Create a new project.
    
    Args:
        name: Project name
    """
    project_data = {"name": name}
    result = api.post('projects', data=project_data)
    
    if result['success']:
        project = result['data']
        return f"✅ Project '{name}' created successfully (ID: {project.get('id')})"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to create project: {error_msg}"

@mcp.tool()
def delete_project(project_id: str) -> str:
    """Delete a project.
    
    Args:
        project_id: The ID of the project to delete
    """
    result = api.delete(f'projects/{project_id}')
    
    if result['success']:
        return f"✅ Project {project_id} deleted successfully"
    else:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to delete project: {error_msg}"

# =============================================================================
# AUDIT TOOLS
# =============================================================================

@mcp.tool()
def generate_audit(days_abandoned_workflow: int = 90) -> str:
    """Generate a security audit for the n8n instance.
    
    Args:
        days_abandoned_workflow: Number of days to consider workflows abandoned (default: 90)
    """
    audit_data = {
        "additionalOptions": {
            "daysAbandonedWorkflow": days_abandoned_workflow
        }
    }
    
    result = api.post('audit', data=audit_data)
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to generate audit: {error_msg}"
    
    audit_report = result['data']
    
    output = "🔍 Security Audit Report\n\n"
    
    # Process each risk category
    for risk_name, risk_data in audit_report.items():
        if isinstance(risk_data, dict) and 'risk' in risk_data:
            risk_type = risk_data.get('risk', 'unknown')
            sections = risk_data.get('sections', [])
            
            output += f"📋 {risk_name}\n"
            output += f"• Risk Type: {risk_type}\n"
            output += f"• Issues Found: {len(sections)}\n"
            
            if sections:
                for section in sections[:3]:  # Show first 3 issues
                    title = section.get('title', 'Unknown Issue')
                    output += f"  - {title}\n"
                if len(sections) > 3:
                    output += f"  ... and {len(sections) - 3} more\n"
            else:
                output += "  ✅ No issues found\n"
            
            output += "\n"
    
    return output

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

@mcp.tool()
def search_workflows(name_filter: str = "", active_only: bool = False, limit: int = 20) -> str:
    """Search workflows by name and status.
    
    Args:
        name_filter: Filter workflows by name (partial match)
        active_only: Only show active workflows
        limit: Maximum number of workflows to return
    """
    params = {'limit': min(limit, 100)}
    
    if name_filter:
        params['name'] = name_filter
    if active_only:
        params['active'] = 'true'
    
    result = api.get('workflows', params=params)
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to search workflows: {error_msg}"
    
    workflows = result['data'].get('data', [])
    
    if not workflows:
        return "📋 No workflows found matching the criteria."
    
    output = f"📋 Found {len(workflows)} workflows:\n\n"
    
    for wf in workflows:
        name = wf.get('name', 'Unnamed')
        wf_id = wf.get('id')
        active = wf.get('active', False)
        status = "🟢 Active" if active else "🔴 Inactive"
        
        output += f"• {name} (ID: {wf_id}) - {status}\n"
    
    return output

@mcp.tool()
def get_workflow_execution_count(workflow_id: str) -> str:
    """Get execution count for a specific workflow.
    
    Args:
        workflow_id: The ID of the workflow
    """
    params = {'workflowId': workflow_id, 'limit': 1}
    result = api.get('executions', params=params)
    
    if not result['success']:
        error_msg = result['data'].get('message', f"HTTP {result['status_code']}")
        return f"❌ Failed to get execution count: {error_msg}"
    
    # Get workflow name
    wf_result = api.get(f'workflows/{workflow_id}')
    workflow_name = "Unknown"
    if wf_result['success']:
        workflow_name = wf_result['data'].get('name', 'Unnamed')
    
    # Count executions by status
    success_count = 0
    error_count = 0
    waiting_count = 0
    
    for status in ['success', 'error', 'waiting']:
        status_params = {'workflowId': workflow_id, 'status': status, 'limit': 100}
        status_result = api.get('executions', params=status_params)
        
        if status_result['success']:
            executions = status_result['data'].get('data', [])
            count = len(executions)
            
            if status == 'success':
                success_count = count
            elif status == 'error':
                error_count = count
            elif status == 'waiting':
                waiting_count = count
    
    total_count = success_count + error_count + waiting_count
    
    output = f"📊 Execution Statistics for '{workflow_name}' (ID: {workflow_id})\n\n"
    output += f"• Total Executions: {total_count}\n"
    output += f"• ✅ Successful: {success_count}\n"
    output += f"• ❌ Failed: {error_count}\n"
    output += f"• ⏳ Waiting: {waiting_count}\n"
    
    if total_count > 0:
        success_rate = (success_count / total_count) * 100
        output += f"• Success Rate: {success_rate:.1f}%\n"
    
    return output

# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    # Print startup information to stderr
    print("🚀 Starting n8n MCP Server...", file=sys.stderr)
    print(f"📡 Target: {N8N_HOST}:{N8N_PORT}", file=sys.stderr)
    print(f"🔑 API Key: {'✅ Configured' if N8N_API_KEY else '❌ NOT SET'}", file=sys.stderr)
    print(f"🔒 HTTPS: {'✅ Enabled' if N8N_USE_HTTPS else '❌ Disabled'}", file=sys.stderr)
    print("", file=sys.stderr)
    
    # Run the MCP server
    mcp.run(transport='stdio')