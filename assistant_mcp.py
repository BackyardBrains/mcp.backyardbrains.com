"""
MCP Digital Assistant - Google Drive, Gmail, Calendar Integration

A stateless assistant that uses Google Drive as persistent memory,
with Gmail triage and Calendar management capabilities.
"""

import os
import json
import logging
import base64
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from cryptography.fernet import Fernet

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from utils import MCP_PROTOCOL_VERSION, _rpc_result, _rpc_error, logger, safe_dumps
from auth import require_assistant_google_auth, create_assistant_token

# =============================================================================
# Configuration
# =============================================================================

router = APIRouter()

# Google OAuth Configuration
ASSISTANT_GOOGLE_CREDENTIALS_FILE = os.environ.get(
    "ASSISTANT_GOOGLE_CREDENTIALS_FILE", "assistant_google_credentials.json"
)
ASSISTANT_TOKEN_STORE_PATH = os.environ.get(
    "ASSISTANT_TOKEN_STORE_PATH", ".assistant_tokens.enc"
)
ASSISTANT_USERS_CONFIG_PATH = os.environ.get(
    "ASSISTANT_USERS_CONFIG_PATH", ".assistant_users.json"
)

# MCP Base URL for OAuth callbacks
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "https://mcp.backyardbrains.com")

# Google API Scopes (all-in-one OAuth)
ASSISTANT_GOOGLE_SCOPES = [
    # OpenID Connect - for user identity
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    # Drive - for assistant memory
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/documents',
    # Gmail - triage operations
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    # Calendar - full access
    'https://www.googleapis.com/auth/calendar',
]

# Encryption for token storage
TOKEN_ENC_KEY = os.environ.get("TOKEN_ENC_KEY")
if TOKEN_ENC_KEY:
    _fernet = Fernet(TOKEN_ENC_KEY.encode() if isinstance(TOKEN_ENC_KEY, str) else TOKEN_ENC_KEY)
else:
    _fernet = None
    logger.warning("TOKEN_ENC_KEY not set; Assistant tokens will not be encrypted!")

# Drive folder permissions (guardrails)
FOLDER_PERMISSIONS = {
    "rules": "read",
    "projects": "read_write",
    "priorities": "read",
    "resources": "read",
    "inbox": "read",
    "outbox": "write",
    "logs": "append",
    "sessions": "append",
}

MAX_CONTENT_SIZE = 200 * 1024  # 200KB limit for Drive docs

# =============================================================================
# Multi-User Configuration
# =============================================================================

def load_users_config() -> Dict[str, Any]:
    """Load the multi-user configuration file."""
    config_path = Path(ASSISTANT_USERS_CONFIG_PATH)
    if not config_path.exists():
        return {"users": {}, "default_behavior": "reject"}
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load users config: {e}")
        return {"users": {}, "default_behavior": "reject"}


def get_user_config(email: str) -> Optional[Dict[str, Any]]:
    """Get configuration for a specific user by email."""
    config = load_users_config()
    user = config.get("users", {}).get(email)
    if user and user.get("enabled", True):
        return user
    return None


def save_users_config(config: Dict[str, Any]):
    """Save the multi-user configuration file."""
    config_path = Path(ASSISTANT_USERS_CONFIG_PATH)
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save users config: {e}")


# =============================================================================
# Token Storage (Per-User, Encrypted)
# =============================================================================

def load_all_tokens() -> Dict[str, Dict[str, Any]]:
    """Load all encrypted tokens from storage."""
    if not os.path.exists(ASSISTANT_TOKEN_STORE_PATH):
        return {}
    try:
        with open(ASSISTANT_TOKEN_STORE_PATH, 'rb') as f:
            encrypted = f.read()
        if _fernet:
            decrypted = _fernet.decrypt(encrypted).decode()
        else:
            decrypted = encrypted.decode()
        return json.loads(decrypted)
    except Exception as e:
        logger.error(f"Failed to load assistant tokens: {e}")
        return {}


def save_all_tokens(tokens: Dict[str, Dict[str, Any]]):
    """Save all tokens to encrypted storage."""
    try:
        data = json.dumps(tokens).encode()
        if _fernet:
            data = _fernet.encrypt(data)
        with open(ASSISTANT_TOKEN_STORE_PATH, 'wb') as f:
            f.write(data)
    except Exception as e:
        logger.error(f"Failed to save assistant tokens: {e}")


def get_user_tokens(email: str) -> Optional[Dict[str, Any]]:
    """Get tokens for a specific user."""
    all_tokens = load_all_tokens()
    return all_tokens.get(email)


def save_user_tokens(email: str, tokens: Dict[str, Any]):
    """Save tokens for a specific user."""
    all_tokens = load_all_tokens()
    all_tokens[email] = tokens
    save_all_tokens(all_tokens)


def delete_user_tokens(email: str):
    """Delete tokens for a specific user."""
    all_tokens = load_all_tokens()
    if email in all_tokens:
        del all_tokens[email]
        save_all_tokens(all_tokens)


# =============================================================================
# Google Client
# =============================================================================

class AssistantGoogleClient:
    """Unified Google client for Drive, Gmail, and Calendar."""
    
    def __init__(self, email: str):
        self.email = email
        self.user_config = get_user_config(email)
        if not self.user_config:
            raise ValueError(f"User {email} not configured")
        
        self.root_folder_id = self.user_config.get("root_folder_id")
        if not self.root_folder_id:
            raise ValueError(f"No root_folder_id configured for {email}")
        
        self.creds = self._get_credentials()
        self._drive = None
        self._docs = None
        self._gmail = None
        self._calendar = None
        self._folder_cache = {}  # Cache folder IDs
    
    def _get_credentials(self) -> Credentials:
        """Get and refresh Google credentials for this user."""
        token_data = get_user_tokens(self.email)
        if not token_data:
            raise ValueError(f"No tokens found for {self.email}. Please authenticate.")
        
        # Load client config for refresh
        client_config = {}
        if os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
            with open(ASSISTANT_GOOGLE_CREDENTIALS_FILE, 'r') as f:
                creds_data = json.load(f)
            client_type = 'web' if 'web' in creds_data else ('installed' if 'installed' in creds_data else None)
            if client_type:
                client_config = creds_data[client_type]
        
        # Merge client config into token data for refresh
        if client_config:
            token_data['client_id'] = client_config.get('client_id')
            token_data['client_secret'] = client_config.get('client_secret')
            if 'token_uri' in client_config:
                token_data['token_uri'] = client_config['token_uri']
        
        creds = Credentials.from_authorized_user_info(token_data, ASSISTANT_GOOGLE_SCOPES)
        
        # Refresh if expired
        if creds and creds.expired and creds.refresh_token:
            logger.info(f"Refreshing Google token for {self.email}")
            creds.refresh(GoogleRequest())
            save_user_tokens(self.email, json.loads(creds.to_json()))
        
        return creds
    
    @property
    def drive(self):
        if not self._drive:
            self._drive = build('drive', 'v3', credentials=self.creds)
        return self._drive
    
    @property
    def docs(self):
        if not self._docs:
            self._docs = build('docs', 'v1', credentials=self.creds)
        return self._docs
    
    @property
    def gmail(self):
        if not self._gmail:
            self._gmail = build('gmail', 'v1', credentials=self.creds)
        return self._gmail
    
    @property
    def calendar(self):
        if not self._calendar:
            self._calendar = build('calendar', 'v3', credentials=self.creds)
        return self._calendar
    
    # -------------------------------------------------------------------------
    # Drive Operations
    # -------------------------------------------------------------------------
    
    def get_subfolder_id(self, folder_name: str) -> Optional[str]:
        """Get the ID of a subfolder within AssistantRoot."""
        if folder_name in self._folder_cache:
            return self._folder_cache[folder_name]
        
        query = f"'{self.root_folder_id}' in parents and name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        results = self.drive.files().list(q=query, fields="files(id, name)").execute()
        files = results.get('files', [])
        
        if files:
            folder_id = files[0]['id']
            self._folder_cache[folder_name] = folder_id
            return folder_id
        return None
    
    def list_docs_in_folder(self, folder_name: str) -> List[Dict[str, Any]]:
        """List all Google Docs in a subfolder."""
        folder_id = self.get_subfolder_id(folder_name)
        if not folder_id:
            return []
        
        query = f"'{folder_id}' in parents and mimeType = 'application/vnd.google-apps.document' and trashed = false"
        results = self.drive.files().list(
            q=query,
            fields="files(id, name, modifiedTime)",
            orderBy="modifiedTime desc"
        ).execute()
        
        return results.get('files', [])
    
    def list_files_in_folder(self, folder_name: str) -> List[Dict[str, Any]]:
        """List all files (any type) in a subfolder."""
        folder_id = self.get_subfolder_id(folder_name)
        if not folder_id:
            return []
        
        query = f"'{folder_id}' in parents and trashed = false"
        results = self.drive.files().list(
            q=query,
            fields="files(id, name, mimeType, modifiedTime)",
            orderBy="modifiedTime desc"
        ).execute()
        
        return results.get('files', [])
    
    def get_doc_by_name(self, folder_name: str, doc_name: str) -> Optional[str]:
        """Get the ID of a doc by name within a folder."""
        folder_id = self.get_subfolder_id(folder_name)
        if not folder_id:
            return None
        
        query = f"'{folder_id}' in parents and name = '{doc_name}' and mimeType = 'application/vnd.google-apps.document' and trashed = false"
        results = self.drive.files().list(q=query, fields="files(id)").execute()
        files = results.get('files', [])
        
        return files[0]['id'] if files else None
    
    def read_doc_content(self, doc_id: str) -> str:
        """Read the plain text content of a Google Doc."""
        doc = self.docs.documents().get(documentId=doc_id).execute()
        content = doc.get('body', {}).get('content', [])
        
        text_parts = []
        for element in content:
            if 'paragraph' in element:
                for text_run in element['paragraph'].get('elements', []):
                    if 'textRun' in text_run:
                        text_parts.append(text_run['textRun'].get('content', ''))
        
        return ''.join(text_parts)
    
    def write_doc_content(self, doc_id: str, content: str):
        """Replace the content of a Google Doc."""
        # First, get the document to find the end index
        doc = self.docs.documents().get(documentId=doc_id).execute()
        end_index = doc.get('body', {}).get('content', [{}])[-1].get('endIndex', 1)
        
        requests = []
        
        # Delete existing content (if any beyond the initial newline)
        if end_index > 1:
            requests.append({
                'deleteContentRange': {
                    'range': {
                        'startIndex': 1,
                        'endIndex': end_index - 1
                    }
                }
            })
        
        # Insert new content
        if content:
            requests.append({
                'insertText': {
                    'location': {'index': 1},
                    'text': content
                }
            })
        
        if requests:
            self.docs.documents().batchUpdate(
                documentId=doc_id,
                body={'requests': requests}
            ).execute()
    
    def append_to_doc(self, doc_id: str, text: str):
        """Append text to the end of a Google Doc."""
        doc = self.docs.documents().get(documentId=doc_id).execute()
        end_index = doc.get('body', {}).get('content', [{}])[-1].get('endIndex', 1)
        
        self.docs.documents().batchUpdate(
            documentId=doc_id,
            body={
                'requests': [{
                    'insertText': {
                        'location': {'index': end_index - 1},
                        'text': text
                    }
                }]
            }
        ).execute()
    
    def move_file(self, file_id: str, dest_folder_name: str) -> bool:
        """Move a file to a different folder."""
        dest_folder_id = self.get_subfolder_id(dest_folder_name)
        if not dest_folder_id:
            return False
        
        # Get current parents
        file = self.drive.files().get(fileId=file_id, fields='parents').execute()
        previous_parents = ",".join(file.get('parents', []))
        
        # Move the file
        self.drive.files().update(
            fileId=file_id,
            addParents=dest_folder_id,
            removeParents=previous_parents,
            fields='id, parents'
        ).execute()
        
        return True
    
    def read_file_content(self, file_id: str) -> str:
        """Read content from a file (handles Google Docs and other formats)."""
        file_meta = self.drive.files().get(fileId=file_id, fields='mimeType').execute()
        mime_type = file_meta.get('mimeType', '')
        
        if mime_type == 'application/vnd.google-apps.document':
            return self.read_doc_content(file_id)
        else:
            # Export as plain text for other Google formats, or download directly
            try:
                content = self.drive.files().get_media(fileId=file_id).execute()
                if isinstance(content, bytes):
                    return content.decode('utf-8', errors='replace')
                return str(content)
            except Exception:
                # Try exporting as plain text
                content = self.drive.files().export(
                    fileId=file_id, mimeType='text/plain'
                ).execute()
                if isinstance(content, bytes):
                    return content.decode('utf-8', errors='replace')
                return str(content)


# =============================================================================
# Client Factory
# =============================================================================

_client_cache: Dict[str, AssistantGoogleClient] = {}


def get_assistant_client(email: str) -> AssistantGoogleClient:
    """Get or create an AssistantGoogleClient for the given user."""
    global _client_cache
    
    if email not in _client_cache:
        _client_cache[email] = AssistantGoogleClient(email)
    
    return _client_cache[email]


def clear_client_cache(email: str = None):
    """Clear cached clients (e.g., after token refresh)."""
    global _client_cache
    if email:
        _client_cache.pop(email, None)
    else:
        _client_cache.clear()


# =============================================================================
# OAuth 2.0 Authorization Server (for Claude MCP discovery)
# =============================================================================

# Temporary storage for OAuth authorization codes (code -> {email, expires, code_challenge, redirect_uri})
_oauth_codes: Dict[str, Dict[str, Any]] = {}
# Pending OAuth requests (state -> {redirect_uri, state, code_challenge, code_challenge_method})
_pending_oauth: Dict[str, Dict[str, Any]] = {}

OAUTH_CODE_EXPIRY_SECONDS = 300  # 5 minutes


def _cleanup_expired_codes():
    """Remove expired authorization codes."""
    now = datetime.now(timezone.utc).timestamp()
    expired = [code for code, data in _oauth_codes.items() if data.get("expires", 0) < now]
    for code in expired:
        del _oauth_codes[code]
    expired_pending = [state for state, data in _pending_oauth.items() if data.get("expires", 0) < now]
    for state in expired_pending:
        del _pending_oauth[state]


@router.get("/oauth/authorize")
async def oauth_authorize(
    request: Request,
    client_id: str = None,
    redirect_uri: str = None,
    response_type: str = "code",
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
    scope: str = None,
):
    """
    OAuth 2.0 Authorization endpoint.
    Redirects to Google OAuth, then back to the client with an auth code.
    """
    _cleanup_expired_codes()
    
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")
    
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri is required")
    
    # Generate our own state to track this OAuth request
    internal_state = secrets.token_urlsafe(32)
    
    # Store the pending OAuth request
    _pending_oauth[internal_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "client_state": state,  # The client's state to return
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires": datetime.now(timezone.utc).timestamp() + OAUTH_CODE_EXPIRY_SECONDS,
    }
    
    # Store internal state in session for the Google callback
    request.session["oauth_internal_state"] = internal_state
    
    # Redirect to Google OAuth
    google_redirect_uri = f"{MCP_BASE_URL.rstrip('/')}/assistant/google/callback"
    
    if not os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
        raise HTTPException(
            status_code=500,
            detail=f"Google credentials file not found: {ASSISTANT_GOOGLE_CREDENTIALS_FILE}"
        )
    
    flow = Flow.from_client_secrets_file(
        ASSISTANT_GOOGLE_CREDENTIALS_FILE,
        scopes=ASSISTANT_GOOGLE_SCOPES,
        redirect_uri=google_redirect_uri
    )
    
    authorization_url, google_state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    # Store Google state in session
    request.session['oauth_state'] = google_state
    
    return RedirectResponse(url=authorization_url)


@router.post("/oauth/token")
async def oauth_token(request: Request):
    """
    OAuth 2.0 Token endpoint.
    Exchanges authorization code for access token (our JWT).
    """
    _cleanup_expired_codes()
    
    # Parse form data or JSON
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        form_data = await request.form()
        data = dict(form_data)
    elif "application/json" in content_type:
        data = await request.json()
    else:
        # Try form data first
        try:
            form_data = await request.form()
            data = dict(form_data)
        except:
            data = await request.json()
    
    grant_type = data.get("grant_type")
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    code_verifier = data.get("code_verifier")
    
    if grant_type != "authorization_code":
        return {"error": "unsupported_grant_type", "error_description": "Only authorization_code is supported"}
    
    if not code:
        return {"error": "invalid_request", "error_description": "code is required"}
    
    # Look up the authorization code
    code_data = _oauth_codes.get(code)
    if not code_data:
        return {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
    
    # Check expiration
    if code_data.get("expires", 0) < datetime.now(timezone.utc).timestamp():
        del _oauth_codes[code]
        return {"error": "invalid_grant", "error_description": "Authorization code expired"}
    
    # Verify PKCE if code_challenge was provided
    if code_data.get("code_challenge"):
        if not code_verifier:
            return {"error": "invalid_request", "error_description": "code_verifier is required"}
        
        # Verify code_verifier against code_challenge
        import hashlib
        import base64
        if code_data.get("code_challenge_method") == "S256":
            computed = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b'=').decode()
        else:
            computed = code_verifier
        
        if computed != code_data["code_challenge"]:
            return {"error": "invalid_grant", "error_description": "code_verifier mismatch"}
    
    # Delete the used code
    email = code_data["email"]
    del _oauth_codes[code]
    
    # Generate our JWT
    access_token = create_assistant_token(email)
    
    logger.info(f"OAuth token issued for {email}")
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 30 * 24 * 60 * 60,  # 30 days in seconds
    }


# =============================================================================
# Google OAuth Endpoints
# =============================================================================

@router.get("/")
@router.get("")
def assistant_index():
    """Basic index endpoint."""
    return {
        "service": "assistant-mcp",
        "status": "ok",
        "endpoints": {
            "health": "/assistant/healthz",
            "mcp": "/assistant/mcp",
            "google_login": "/assistant/google/login",
            "google_status": "/assistant/google/status",
        },
    }


@router.get("/healthz")
def assistant_healthz():
    return {"status": "ok", "service": "assistant"}


@router.get("/google/login")
async def assistant_google_login(request: Request):
    """Initiate Google OAuth flow for Drive, Gmail, and Calendar."""
    redirect_uri = f"{MCP_BASE_URL.rstrip('/')}/assistant/google/callback"
    
    if not os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
        raise HTTPException(
            status_code=500,
            detail=f"Google credentials file not found: {ASSISTANT_GOOGLE_CREDENTIALS_FILE}"
        )
    
    flow = Flow.from_client_secrets_file(
        ASSISTANT_GOOGLE_CREDENTIALS_FILE,
        scopes=ASSISTANT_GOOGLE_SCOPES,
        redirect_uri=redirect_uri
    )
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Force consent to get refresh token
    )
    
    # Store state in session (simple approach - in production use proper session management)
    request.session['oauth_state'] = state
    
    return RedirectResponse(url=authorization_url)


@router.get("/google/callback")
async def assistant_google_callback(request: Request, code: str, state: str = None):
    """Handle Google OAuth callback."""
    redirect_uri = f"{MCP_BASE_URL.rstrip('/')}/assistant/google/callback"
    
    flow = Flow.from_client_secrets_file(
        ASSISTANT_GOOGLE_CREDENTIALS_FILE,
        scopes=ASSISTANT_GOOGLE_SCOPES,
        redirect_uri=redirect_uri
    )
    
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        logger.error(f"Google OAuth token exchange failed: {e}")
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {e}")
    
    creds = flow.credentials
    
    # Get user email
    oauth2_service = build('oauth2', 'v2', credentials=creds)
    user_info = oauth2_service.userinfo().get().execute()
    email = user_info.get('email')
    
    if not email:
        raise HTTPException(status_code=400, detail="Could not retrieve email from Google")
    
    # Check if user is authorized
    user_config = get_user_config(email)
    if not user_config:
        config = load_users_config()
        if config.get("default_behavior") == "reject":
            logger.warning(f"Unauthorized user attempted login: {email}")
            return HTMLResponse(
                content=f"<h1>Access Denied</h1><p>User {email} is not authorized to use this assistant.</p>",
                status_code=403
            )
    
    # Save Google tokens
    token_data = json.loads(creds.to_json())
    save_user_tokens(email, token_data)
    clear_client_cache(email)
    
    logger.info(f"Google OAuth completed for {email}")
    
    # Check if this is part of an OAuth 2.0 flow (from Claude)
    internal_state = request.session.get("oauth_internal_state")
    if internal_state and internal_state in _pending_oauth:
        pending = _pending_oauth.pop(internal_state)
        request.session.pop("oauth_internal_state", None)
        
        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)
        _oauth_codes[auth_code] = {
            "email": email,
            "expires": datetime.now(timezone.utc).timestamp() + OAUTH_CODE_EXPIRY_SECONDS,
            "code_challenge": pending.get("code_challenge"),
            "code_challenge_method": pending.get("code_challenge_method"),
            "redirect_uri": pending.get("redirect_uri"),
        }
        
        # Redirect back to client with authorization code
        client_redirect = pending["redirect_uri"]
        params = {"code": auth_code}
        if pending.get("client_state"):
            params["state"] = pending["client_state"]
        
        redirect_url = f"{client_redirect}{'&' if '?' in client_redirect else '?'}{urlencode(params)}"
        logger.info(f"OAuth flow: redirecting to client with auth code for {email}")
        return RedirectResponse(url=redirect_url)
    
    # Direct login flow - show token page
    mcp_token = create_assistant_token(email)
    
    return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Assistant MCP - Authorization Complete</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; }}
                h1 {{ color: #1a73e8; }}
                .token-box {{ background: #f5f5f5; border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin: 20px 0; word-break: break-all; font-family: monospace; font-size: 12px; }}
                .copy-btn {{ background: #1a73e8; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-top: 10px; }}
                .copy-btn:hover {{ background: #1557b0; }}
                .success {{ color: #0d9488; font-weight: bold; display: none; margin-left: 10px; }}
                .instructions {{ background: #e8f4f8; border-radius: 8px; padding: 15px; margin: 20px 0; }}
                code {{ background: #eee; padding: 2px 6px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <h1>Authorization Complete!</h1>
            <p>Logged in as: <strong>{email}</strong></p>
            <p>Scopes authorized: Drive, Gmail, Calendar</p>
            
            <div class="instructions">
                <h3>Your MCP Bearer Token</h3>
                <p>Copy this token and add it to your Claude MCP configuration:</p>
            </div>
            
            <div class="token-box" id="token">{mcp_token}</div>
            <button class="copy-btn" onclick="copyToken()">Copy Token</button>
            <span class="success" id="copied">Copied!</span>
            
            <div class="instructions" style="margin-top: 30px;">
                <h3>Claude Configuration</h3>
                <p>Add this to your Claude MCP settings:</p>
                <pre style="background: #fff; padding: 10px; border-radius: 5px; overflow-x: auto;">
{{
  "mcpServers": {{
    "assistant": {{
      "url": "https://mcp.backyardbrains.com/assistant",
      "headers": {{
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }}
    }}
  }}
}}</pre>
            </div>
            
            <script>
                function copyToken() {{
                    const token = document.getElementById('token').innerText;
                    navigator.clipboard.writeText(token).then(() => {{
                        document.getElementById('copied').style.display = 'inline';
                        setTimeout(() => document.getElementById('copied').style.display = 'none', 2000);
                    }});
                }}
            </script>
        </body>
        </html>
    """)


@router.get("/google/status")
async def assistant_google_status(request: Request):
    """Check Google authentication status for all configured users."""
    config = load_users_config()
    all_tokens = load_all_tokens()
    
    status = []
    for email, user_config in config.get("users", {}).items():
        has_tokens = email in all_tokens
        status.append({
            "email": email,
            "name": user_config.get("name"),
            "enabled": user_config.get("enabled", True),
            "authenticated": has_tokens,
            "root_folder_id": user_config.get("root_folder_id", "")[:20] + "..." if user_config.get("root_folder_id") else None
        })
    
    return {"users": status}


@router.post("/google/logout")
async def assistant_google_logout(request: Request, email: str):
    """Clear stored tokens for a user."""
    delete_user_tokens(email)
    clear_client_cache(email)
    return {"status": "ok", "message": f"Tokens cleared for {email}"}


# =============================================================================
# MCP Tool Definitions
# =============================================================================

def _list_assistant_tools():
    """Return all assistant tool definitions."""
    return {
        "tools": [
            # -----------------------------------------------------------------
            # Drive Tools - Read
            # -----------------------------------------------------------------
            {
                "name": "assistant_get_rules",
                "description": "CRITICAL: Call this tool FIRST at the start of every session. Returns the assistant's operating rules and behavioral guidelines. These rules govern all subsequent behavior.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "assistant_get_priorities",
                "description": "[READ] Get current priorities. Call after assistant_get_rules to understand what matters most.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "assistant_get_resources",
                "description": "[READ] Get reference resources and materials.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "assistant_list_projects",
                "description": "[READ] List all projects. Returns project IDs and names for use with assistant_get_project.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "assistant_get_project",
                "description": "[READ] Get the full content of a specific project document.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "Project document ID from assistant_list_projects"}
                    },
                    "required": ["project_id"]
                }
            },
            # -----------------------------------------------------------------
            # Drive Tools - Inbox/Outbox
            # -----------------------------------------------------------------
            {
                "name": "assistant_list_inbox",
                "description": "[READ] List files in the inbox waiting to be processed.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "assistant_read_inbox_file",
                "description": "[READ] Read the content of a file in the inbox.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_id": {"type": "string", "description": "File ID from assistant_list_inbox"}
                    },
                    "required": ["file_id"]
                }
            },
            {
                "name": "assistant_move_to_outbox",
                "description": "[WRITE] Move a processed file from inbox to outbox.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_id": {"type": "string", "description": "File ID to move"}
                    },
                    "required": ["file_id"]
                }
            },
            # -----------------------------------------------------------------
            # Drive Tools - Write
            # -----------------------------------------------------------------
            {
                "name": "assistant_write_project",
                "description": "[WRITE] Update a project document. IMPORTANT: Always call assistant_get_project first to read current content, then modify and write back. Max content size: 200KB.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "Project document ID"},
                        "content": {"type": "string", "description": "Full markdown content for the project"}
                    },
                    "required": ["project_id", "content"]
                }
            },
            {
                "name": "assistant_append_log",
                "description": "[APPEND] Add an entry to the activity log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry": {"type": "string", "description": "Log entry text"}
                    },
                    "required": ["entry"]
                }
            },
            # -----------------------------------------------------------------
            # Session Logging
            # -----------------------------------------------------------------
            {
                "name": "assistant_log_session",
                "description": "[APPEND] Log the current conversation session. Call at START with initial summary, UPDATE at END with final summary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Session ID (omit for new session, include to update existing)"},
                        "summary": {"type": "string", "description": "Brief 1-2 sentence description of the conversation"},
                        "status": {"type": "string", "enum": ["active", "completed"], "default": "active"}
                    },
                    "required": ["summary"]
                }
            },
            # -----------------------------------------------------------------
            # Gmail Tools
            # -----------------------------------------------------------------
            {
                "name": "assistant_gmail_list",
                "description": "[READ] List recent emails. Supports label filtering and pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "description": "Label to filter (INBOX, UNREAD, STARRED, etc)", "default": "INBOX"},
                        "max_results": {"type": "integer", "description": "Max emails to return", "default": 20},
                        "page_token": {"type": "string", "description": "Pagination token for next page"}
                    }
                }
            },
            {
                "name": "assistant_gmail_read",
                "description": "[READ] Read the full content of a specific email.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID from assistant_gmail_list"}
                    },
                    "required": ["message_id"]
                }
            },
            {
                "name": "assistant_gmail_search",
                "description": "[READ] Search emails using Gmail query syntax (from:, to:, subject:, has:attachment, etc).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Gmail search query"},
                        "max_results": {"type": "integer", "default": 20}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "assistant_gmail_label",
                "description": "[MODIFY] Add or remove labels from an email.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID"},
                        "add_labels": {"type": "array", "items": {"type": "string"}, "description": "Labels to add"},
                        "remove_labels": {"type": "array", "items": {"type": "string"}, "description": "Labels to remove"}
                    },
                    "required": ["message_id"]
                }
            },
            {
                "name": "assistant_gmail_archive",
                "description": "[MODIFY] Archive an email (removes INBOX label).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID to archive"}
                    },
                    "required": ["message_id"]
                }
            },
            {
                "name": "assistant_gmail_mark_read",
                "description": "[MODIFY] Mark an email as read or unread.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID"},
                        "read": {"type": "boolean", "description": "True to mark as read, false to mark as unread", "default": True}
                    },
                    "required": ["message_id"]
                }
            },
            # -----------------------------------------------------------------
            # Calendar Tools
            # -----------------------------------------------------------------
            {
                "name": "assistant_calendar_list_calendars",
                "description": "[READ] List all accessible calendars.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "assistant_calendar_list_events",
                "description": "[READ] List upcoming calendar events.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary", "description": "Calendar ID (use 'primary' for main calendar)"},
                        "time_min": {"type": "string", "description": "ISO datetime, defaults to now"},
                        "time_max": {"type": "string", "description": "ISO datetime for end of range"},
                        "max_results": {"type": "integer", "default": 10}
                    }
                }
            },
            {
                "name": "assistant_calendar_get_event",
                "description": "[READ] Get details of a specific calendar event.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary"},
                        "event_id": {"type": "string", "description": "Event ID"}
                    },
                    "required": ["event_id"]
                }
            },
            {
                "name": "assistant_calendar_create_event",
                "description": "[WRITE] Create a new calendar event.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary"},
                        "summary": {"type": "string", "description": "Event title"},
                        "start": {"type": "string", "description": "ISO datetime for start"},
                        "end": {"type": "string", "description": "ISO datetime for end"},
                        "description": {"type": "string", "description": "Event description"},
                        "location": {"type": "string", "description": "Event location"},
                        "attendees": {"type": "array", "items": {"type": "string"}, "description": "Email addresses of attendees"}
                    },
                    "required": ["summary", "start", "end"]
                }
            },
            {
                "name": "assistant_calendar_update_event",
                "description": "[WRITE] Update an existing calendar event.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary"},
                        "event_id": {"type": "string", "description": "Event ID to update"},
                        "summary": {"type": "string"},
                        "start": {"type": "string"},
                        "end": {"type": "string"},
                        "description": {"type": "string"},
                        "location": {"type": "string"},
                        "attendees": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["event_id"]
                }
            },
            {
                "name": "assistant_calendar_delete_event",
                "description": "[DELETE] Delete a calendar event. This action is irreversible.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary"},
                        "event_id": {"type": "string", "description": "Event ID to delete"}
                    },
                    "required": ["event_id"]
                }
            },
            # -----------------------------------------------------------------
            # Account Info
            # -----------------------------------------------------------------
            {
                "name": "assistant_google_account",
                "description": "[READ] Get the email address of the currently authenticated Google account.",
                "inputSchema": {"type": "object", "properties": {}}
            },
        ]
    }


# =============================================================================
# Tool Handlers
# =============================================================================

async def handle_assistant_tool_call(name: str, args: Dict[str, Any], user_email: str) -> Dict[str, Any]:
    """Handle a tool call for the assistant."""
    
    try:
        client = get_assistant_client(user_email)
    except ValueError as e:
        return {
            "isError": True,
            "content": [{"type": "text", "text": str(e)}]
        }
    
    try:
        # ---------------------------------------------------------------------
        # Drive Tools - Read
        # ---------------------------------------------------------------------
        if name == "assistant_get_rules":
            doc_id = client.get_doc_by_name("rules", "rules")
            if not doc_id:
                return {"content": [{"type": "text", "text": "No rules document found. Create a doc named 'rules' in the rules/ folder."}]}
            content = client.read_doc_content(doc_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_get_priorities":
            doc_id = client.get_doc_by_name("priorities", "priorities")
            if not doc_id:
                return {"content": [{"type": "text", "text": "No priorities document found."}]}
            content = client.read_doc_content(doc_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_get_resources":
            doc_id = client.get_doc_by_name("resources", "resources")
            if not doc_id:
                return {"content": [{"type": "text", "text": "No resources document found."}]}
            content = client.read_doc_content(doc_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_list_projects":
            docs = client.list_docs_in_folder("projects")
            projects = [{"id": d["id"], "name": d["name"], "modified": d.get("modifiedTime")} for d in docs]
            return {"content": [{"type": "text", "text": safe_dumps(projects)}]}
        
        elif name == "assistant_get_project":
            project_id = args.get("project_id")
            content = client.read_doc_content(project_id)
            return {"content": [{"type": "text", "text": content}]}
        
        # ---------------------------------------------------------------------
        # Drive Tools - Inbox/Outbox
        # ---------------------------------------------------------------------
        elif name == "assistant_list_inbox":
            files = client.list_files_in_folder("inbox")
            items = [{"id": f["id"], "name": f["name"], "type": f.get("mimeType"), "modified": f.get("modifiedTime")} for f in files]
            return {"content": [{"type": "text", "text": safe_dumps(items)}]}
        
        elif name == "assistant_read_inbox_file":
            file_id = args.get("file_id")
            content = client.read_file_content(file_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_move_to_outbox":
            file_id = args.get("file_id")
            success = client.move_file(file_id, "outbox")
            if success:
                return {"content": [{"type": "text", "text": "File moved to outbox successfully."}]}
            else:
                return {"isError": True, "content": [{"type": "text", "text": "Failed to move file. Check if outbox folder exists."}]}
        
        # ---------------------------------------------------------------------
        # Drive Tools - Write
        # ---------------------------------------------------------------------
        elif name == "assistant_write_project":
            project_id = args.get("project_id")
            content = args.get("content", "")
            
            # Guardrail: Check content size
            if len(content.encode('utf-8')) > MAX_CONTENT_SIZE:
                return {"isError": True, "content": [{"type": "text", "text": f"Content exceeds maximum size of {MAX_CONTENT_SIZE // 1024}KB"}]}
            
            client.write_doc_content(project_id, content)
            return {"content": [{"type": "text", "text": "Project updated successfully."}]}
        
        elif name == "assistant_append_log":
            entry = args.get("entry", "")
            timestamp = datetime.now(timezone.utc).isoformat()
            log_entry = f"\n[{timestamp}] {entry}"
            
            doc_id = client.get_doc_by_name("logs", "assistant_log")
            if not doc_id:
                return {"isError": True, "content": [{"type": "text", "text": "Log document not found. Create 'assistant_log' in logs/ folder."}]}
            
            client.append_to_doc(doc_id, log_entry)
            return {"content": [{"type": "text", "text": "Log entry added."}]}
        
        # ---------------------------------------------------------------------
        # Session Logging
        # ---------------------------------------------------------------------
        elif name == "assistant_log_session":
            session_id = args.get("session_id")
            summary = args.get("summary", "")
            status = args.get("status", "active")
            
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
            
            if not session_id:
                # Generate new session ID
                session_id = f"sess_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            
            doc_id = client.get_doc_by_name("logs", "sessions")
            if not doc_id:
                # Try alternative name
                doc_id = client.get_doc_by_name("logs", "session_log")
            
            if not doc_id:
                return {"isError": True, "content": [{"type": "text", "text": "Sessions log not found. Create 'sessions' doc in logs/ folder."}]}
            
            log_entry = f"\n| {session_id} | {timestamp} | {user_email.split('@')[0]} | {summary} | {status} |"
            client.append_to_doc(doc_id, log_entry)
            
            return {"content": [{"type": "text", "text": safe_dumps({"session_id": session_id, "status": status})}]}
        
        # ---------------------------------------------------------------------
        # Gmail Tools
        # ---------------------------------------------------------------------
        elif name == "assistant_gmail_list":
            label = args.get("label", "INBOX")
            max_results = args.get("max_results", 20)
            page_token = args.get("page_token")
            
            request_args = {
                "userId": "me",
                "labelIds": [label],
                "maxResults": max_results
            }
            if page_token:
                request_args["pageToken"] = page_token
            
            results = client.gmail.users().messages().list(**request_args).execute()
            messages = results.get("messages", [])
            next_page_token = results.get("nextPageToken")
            
            # Get basic info for each message
            email_list = []
            for msg in messages:
                msg_data = client.gmail.users().messages().get(
                    userId="me", id=msg["id"], format="metadata",
                    metadataHeaders=["From", "Subject", "Date"]
                ).execute()
                
                headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
                email_list.append({
                    "id": msg["id"],
                    "from": headers.get("From", ""),
                    "subject": headers.get("Subject", ""),
                    "date": headers.get("Date", ""),
                    "snippet": msg_data.get("snippet", "")[:100]
                })
            
            result = {"emails": email_list}
            if next_page_token:
                result["next_page_token"] = next_page_token
            
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        
        elif name == "assistant_gmail_read":
            message_id = args.get("message_id")
            msg = client.gmail.users().messages().get(userId="me", id=message_id, format="full").execute()
            
            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            
            # Extract body
            body = ""
            payload = msg.get("payload", {})
            if "body" in payload and payload["body"].get("data"):
                body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="replace")
            elif "parts" in payload:
                for part in payload["parts"]:
                    if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
                        body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="replace")
                        break
            
            result = {
                "id": message_id,
                "from": headers.get("From", ""),
                "to": headers.get("To", ""),
                "subject": headers.get("Subject", ""),
                "date": headers.get("Date", ""),
                "body": body
            }
            
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        
        elif name == "assistant_gmail_search":
            query = args.get("query", "")
            max_results = args.get("max_results", 20)
            
            results = client.gmail.users().messages().list(
                userId="me", q=query, maxResults=max_results
            ).execute()
            
            messages = results.get("messages", [])
            
            email_list = []
            for msg in messages:
                msg_data = client.gmail.users().messages().get(
                    userId="me", id=msg["id"], format="metadata",
                    metadataHeaders=["From", "Subject", "Date"]
                ).execute()
                
                headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
                email_list.append({
                    "id": msg["id"],
                    "from": headers.get("From", ""),
                    "subject": headers.get("Subject", ""),
                    "date": headers.get("Date", ""),
                    "snippet": msg_data.get("snippet", "")[:100]
                })
            
            return {"content": [{"type": "text", "text": safe_dumps({"emails": email_list, "query": query})}]}
        
        elif name == "assistant_gmail_label":
            message_id = args.get("message_id")
            add_labels = args.get("add_labels", [])
            remove_labels = args.get("remove_labels", [])
            
            body = {}
            if add_labels:
                body["addLabelIds"] = add_labels
            if remove_labels:
                body["removeLabelIds"] = remove_labels
            
            client.gmail.users().messages().modify(
                userId="me", id=message_id, body=body
            ).execute()
            
            return {"content": [{"type": "text", "text": "Labels updated."}]}
        
        elif name == "assistant_gmail_archive":
            message_id = args.get("message_id")
            client.gmail.users().messages().modify(
                userId="me", id=message_id, body={"removeLabelIds": ["INBOX"]}
            ).execute()
            return {"content": [{"type": "text", "text": "Email archived."}]}
        
        elif name == "assistant_gmail_mark_read":
            message_id = args.get("message_id")
            read = args.get("read", True)
            
            if read:
                body = {"removeLabelIds": ["UNREAD"]}
            else:
                body = {"addLabelIds": ["UNREAD"]}
            
            client.gmail.users().messages().modify(
                userId="me", id=message_id, body=body
            ).execute()
            
            return {"content": [{"type": "text", "text": f"Email marked as {'read' if read else 'unread'}."}]}
        
        # ---------------------------------------------------------------------
        # Calendar Tools
        # ---------------------------------------------------------------------
        elif name == "assistant_calendar_list_calendars":
            calendars = client.calendar.calendarList().list().execute()
            cal_list = [{"id": c["id"], "summary": c.get("summary", ""), "primary": c.get("primary", False)} for c in calendars.get("items", [])]
            return {"content": [{"type": "text", "text": safe_dumps(cal_list)}]}
        
        elif name == "assistant_calendar_list_events":
            calendar_id = args.get("calendar_id", "primary")
            time_min = args.get("time_min") or datetime.now(timezone.utc).isoformat()
            time_max = args.get("time_max")
            max_results = args.get("max_results", 10)
            
            request_args = {
                "calendarId": calendar_id,
                "timeMin": time_min,
                "maxResults": max_results,
                "singleEvents": True,
                "orderBy": "startTime"
            }
            if time_max:
                request_args["timeMax"] = time_max
            
            events = client.calendar.events().list(**request_args).execute()
            
            event_list = []
            for event in events.get("items", []):
                start = event.get("start", {}).get("dateTime") or event.get("start", {}).get("date")
                end = event.get("end", {}).get("dateTime") or event.get("end", {}).get("date")
                event_list.append({
                    "id": event["id"],
                    "summary": event.get("summary", ""),
                    "start": start,
                    "end": end,
                    "location": event.get("location", ""),
                    "description": event.get("description", "")[:200] if event.get("description") else ""
                })
            
            return {"content": [{"type": "text", "text": safe_dumps(event_list)}]}
        
        elif name == "assistant_calendar_get_event":
            calendar_id = args.get("calendar_id", "primary")
            event_id = args.get("event_id")
            
            event = client.calendar.events().get(calendarId=calendar_id, eventId=event_id).execute()
            
            return {"content": [{"type": "text", "text": safe_dumps(event)}]}
        
        elif name == "assistant_calendar_create_event":
            calendar_id = args.get("calendar_id", "primary")
            
            event_body = {
                "summary": args.get("summary"),
                "start": {"dateTime": args.get("start"), "timeZone": "UTC"},
                "end": {"dateTime": args.get("end"), "timeZone": "UTC"},
            }
            
            if args.get("description"):
                event_body["description"] = args["description"]
            if args.get("location"):
                event_body["location"] = args["location"]
            if args.get("attendees"):
                event_body["attendees"] = [{"email": e} for e in args["attendees"]]
            
            event = client.calendar.events().insert(calendarId=calendar_id, body=event_body).execute()
            
            return {"content": [{"type": "text", "text": safe_dumps({"id": event["id"], "htmlLink": event.get("htmlLink")})}]}
        
        elif name == "assistant_calendar_update_event":
            calendar_id = args.get("calendar_id", "primary")
            event_id = args.get("event_id")
            
            # Get existing event
            event = client.calendar.events().get(calendarId=calendar_id, eventId=event_id).execute()
            
            # Update fields
            if args.get("summary"):
                event["summary"] = args["summary"]
            if args.get("start"):
                event["start"] = {"dateTime": args["start"], "timeZone": "UTC"}
            if args.get("end"):
                event["end"] = {"dateTime": args["end"], "timeZone": "UTC"}
            if args.get("description"):
                event["description"] = args["description"]
            if args.get("location"):
                event["location"] = args["location"]
            if args.get("attendees"):
                event["attendees"] = [{"email": e} for e in args["attendees"]]
            
            updated = client.calendar.events().update(calendarId=calendar_id, eventId=event_id, body=event).execute()
            
            return {"content": [{"type": "text", "text": safe_dumps({"id": updated["id"], "updated": updated.get("updated")})}]}
        
        elif name == "assistant_calendar_delete_event":
            calendar_id = args.get("calendar_id", "primary")
            event_id = args.get("event_id")
            
            client.calendar.events().delete(calendarId=calendar_id, eventId=event_id).execute()
            
            return {"content": [{"type": "text", "text": "Event deleted."}]}
        
        # ---------------------------------------------------------------------
        # Account Info
        # ---------------------------------------------------------------------
        elif name == "assistant_google_account":
            return {"content": [{"type": "text", "text": safe_dumps({"email": user_email})}]}
        
        else:
            return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}
    
    except Exception as e:
        logger.error(f"Error executing assistant tool {name}: {e}")
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error executing {name}: {str(e)}"}],
            "metadata": {"reason": "exception", "exceptionType": type(e).__name__}
        }


# =============================================================================
# MCP Protocol Handlers
# =============================================================================

def _initialize_payload():
    """Standard MCP initialize response."""
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"listChanged": False, "subscribe": False},
            "prompts": {"listChanged": False},
            "logging": {},
        },
        "serverInfo": {"name": "assistant-mcp", "version": "1.0.0"},
    }


def _list_prompts():
    """Return MCP prompts for workflow guidance."""
    return {
        "prompts": [
            {
                "name": "session_start",
                "description": "Initialize a new assistant session with proper context loading",
                "arguments": []
            }
        ]
    }


def _get_prompt(name: str):
    """Get a specific prompt."""
    if name == "session_start":
        return {
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": """Start a new assistant session:
1. Call assistant_get_rules() to load operating guidelines
2. Call assistant_get_priorities() to understand current focus
3. Call assistant_list_projects() to see active work
4. Call assistant_log_session(summary="Session started", status="active") to log this session
5. Then respond to the user's request"""
                }
            }]
        }
    return {"messages": []}


@router.post("/mcp")
@router.post("/")
@router.post("")
async def handle_assistant_mcp(request: Request, payload: Dict = Depends(require_assistant_google_auth)):
    """Handle MCP JSON-RPC requests."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})
    
    # Get user email from the Auth0 payload
    user_email = payload.get("email")
    if not user_email:
        return _rpc_error(rpc_id, -32600, "User email not found in token")
    
    if method == "initialize":
        return _rpc_result(rpc_id, _initialize_payload())
    
    elif method == "ping":
        return _rpc_result(rpc_id, {"status": "ok"})
    
    elif method == "tools/list":
        return _rpc_result(rpc_id, _list_assistant_tools())
    
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        result = await handle_assistant_tool_call(name, args, user_email)
        return _rpc_result(rpc_id, result)
    
    elif method == "prompts/list":
        return _rpc_result(rpc_id, _list_prompts())
    
    elif method == "prompts/get":
        prompt_name = params.get("name")
        return _rpc_result(rpc_id, _get_prompt(prompt_name))
    
    elif method == "resources/list":
        # Could list Drive folders as resources
        return _rpc_result(rpc_id, {"resources": []})
    
    elif method == "resources/read":
        return _rpc_result(rpc_id, {"contents": []})
    
    else:
        return _rpc_error(rpc_id, -32601, f"Method {method} not found")
