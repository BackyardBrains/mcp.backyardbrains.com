"""
MCP Digital Assistant - Google Drive, Gmail, Calendar Integration

A stateless assistant that uses Google Drive as persistent memory,
with Gmail triage and Calendar management capabilities.
"""

import os
import json
import logging
import base64
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sse_starlette.sse import EventSourceResponse
from cryptography.fernet import Fernet

from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from utils import MCP_PROTOCOL_VERSION, _rpc_result, _rpc_error, logger, safe_dumps
from auth import require_assistant_auth

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

# Login / OAuth Configuration
ASSISTANT_GOOGLE_CREDENTIALS_FILE = os.environ.get(
    "ASSISTANT_GOOGLE_CREDENTIALS_FILE", "assistant_google_credentials.json"
)
# Support direct env vars for OAuth (easier for server deployment)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_AUTH_URI = os.environ.get("GOOGLE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth")
GOOGLE_TOKEN_URI = os.environ.get("GOOGLE_TOKEN_URI", "https://oauth2.googleapis.com/token")

# Service Account Configuration (if set, uses service account instead of per-user OAuth)
ASSISTANT_SERVICE_ACCOUNT_FILE = os.environ.get("ASSISTANT_SERVICE_ACCOUNT_FILE")

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
        
        self.sa_creds, self.user_creds = self._get_credentials()
        self._drive = None
        self._docs = None
        self._gmail = None
        self._calendar = None
        self._folder_cache = {}  # Cache folder IDs
    
    def _get_credentials(self):
        """Get Google credentials - both service account and per-user OAuth if available."""
        sa_creds = None
        user_creds = None
        
        # 1. Load Service Account if configured
        if ASSISTANT_SERVICE_ACCOUNT_FILE and os.path.exists(ASSISTANT_SERVICE_ACCOUNT_FILE):
            try:
                # Service account scopes (no Gmail for SAs without domain-wide delegation)
                sa_scopes = [
                    'https://www.googleapis.com/auth/drive',
                    'https://www.googleapis.com/auth/documents',
                    'https://www.googleapis.com/auth/calendar',
                ]
                sa_creds = service_account.Credentials.from_service_account_file(
                    ASSISTANT_SERVICE_ACCOUNT_FILE,
                    scopes=sa_scopes
                )
                logger.debug(f"Loaded service account credentials for {self.email}")
            except Exception as e:
                logger.error(f"Failed to load service account: {e}")
        
        # 2. Load Per-User OAuth if available
        token_data = get_user_tokens(self.email)
        if token_data:
            try:
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
                
                user_creds = creds
                logger.debug(f"Loaded user OAuth credentials for {self.email}")
            except Exception as e:
                logger.error(f"Failed to load/refresh user tokens for {self.email}: {e}")

        if not sa_creds and not user_creds:
            raise ValueError(f"No credentials available for {self.email}. Please authenticate via /assistant/google/login")
            
        return sa_creds, user_creds
    
    @property
    def effective_creds(self):
        """Effective credentials, prioritizing per-user OAuth."""
        return self.user_creds or self.sa_creds

    @property
    def drive(self):
        if not self._drive:
            self._drive = build('drive', 'v3', credentials=self.effective_creds)
        return self._drive
    
    @property
    def docs(self):
        if not self._docs:
            self._docs = build('docs', 'v1', credentials=self.effective_creds)
        return self._docs
    
    @property
    def gmail(self):
        if not self.user_creds:
            raise ValueError("Gmail requires per-user authentication. Please visit /assistant/google/login")
        if not self._gmail:
            self._gmail = build('gmail', 'v1', credentials=self.user_creds)
        return self._gmail
    
    @property
    def calendar(self):
        if not self._calendar:
            self._calendar = build('calendar', 'v3', credentials=self.effective_creds)
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
        """Get the ID of a doc by name within a folder (or 'base' for root)."""
        if folder_name == "base":
            folder_id = self.root_folder_id
        else:
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
        if end_index > 2:
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

    def create_doc(self, folder_name: str, title: str, content: Optional[str] = None) -> str:
        """Create a new Google Doc in a subfolder (or 'base' for root)."""
        if folder_name == "base":
            folder_id = self.root_folder_id
        else:
            folder_id = self.get_subfolder_id(folder_name)
            
        if not folder_id:
            raise ValueError(f"Folder '{folder_name}' not found.")

        file_metadata = {
            'name': title,
            'mimeType': 'application/vnd.google-apps.document',
            'parents': [folder_id]
        }
        
        doc = self.drive.files().create(body=file_metadata, fields='id').execute()
        doc_id = doc.get('id')
        
        if content:
            self.write_doc_content(doc_id, content)
            
        return doc_id
    
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
# SSE Transport (Standard MCP)
# =============================================================================

# Map of sessionId -> asyncio.Queue for outgoing SSE messages
_assistant_sse_sessions: Dict[str, asyncio.Queue] = {}

async def _assistant_sse_stream(session_id: str):
    """The actual SSE stream generator."""
    queue = _assistant_sse_sessions.get(session_id)
    if not queue:
        return

    try:
        # 1. Send the endpoint event
        post_url = f"{MCP_BASE_URL.rstrip('/')}/assistant/mcp?session_id={session_id}"
        yield {
            "event": "endpoint",
            "data": post_url
        }

        # 2. Forward messages from the queue
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                yield {
                    "event": "message",
                    "data": safe_dumps(msg)
                }
            except asyncio.TimeoutError:
                # EventSourceResponse handles keep-alives automatically if configured, 
                # but we can also yield a comment to be safe.
                yield ": keep-alive"
            except Exception as e:
                logger.error(f"SSE stream error for {session_id}: {e}")
                break
    finally:
        _assistant_sse_sessions.pop(session_id, None)
        logger.info(f"SSE session {session_id} closed")


# =============================================================================
# OAuth Endpoints
# =============================================================================

@router.get("/")
@router.get("")
async def assistant_index(request: Request):
    """Basic index endpoint. Supports SSE transport if requested."""
    # Check if this is an SSE connection request (ChatGPT uses this)
    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        session_id = str(uuid.uuid4())
        _assistant_sse_sessions[session_id] = asyncio.Queue()
        logger.info(f"Starting Assistant SSE session: {session_id}")
        
        return EventSourceResponse(
            _assistant_sse_stream(session_id),
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

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

@router.get("/favicon.ico")
async def assistant_favicon():
    return Response(status_code=204)


@router.get("/google/login")
async def assistant_google_login(request: Request):
    """Initiate Google OAuth flow for Drive, Gmail, and Calendar."""
    redirect_uri = f"{MCP_BASE_URL.rstrip('/')}/assistant/google/callback"
    
    # Try to load client config
    client_config = None
    if os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
        with open(ASSISTANT_GOOGLE_CREDENTIALS_FILE, 'r') as f:
            creds_data = json.load(f)
            client_type = 'web' if 'web' in creds_data else ('installed' if 'installed' in creds_data else None)
            if client_type:
                client_config = creds_data[client_type]
    elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        # Construct config from environment variables
        client_config = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": GOOGLE_AUTH_URI,
            "token_uri": GOOGLE_TOKEN_URI
        }
    
    if not client_config:
        error_msg = f"Google OAuth configuration not found at '{ASSISTANT_GOOGLE_CREDENTIALS_FILE}'"
        if os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
             with open(ASSISTANT_GOOGLE_CREDENTIALS_FILE, 'r') as f:
                 data = json.load(f)
                 if data.get('type') == 'service_account':
                     error_msg = f"Error: '{ASSISTANT_GOOGLE_CREDENTIALS_FILE}' is a Service Account file, but a 'Web Application' OAuth client secret is required here. Please download the correct JSON from Google Cloud Console."
        
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)
    
    # Construct flow object from config dict
    flow = Flow.from_client_config(
        {"web": client_config} if "auth_uri" in client_config else {"installed": client_config},
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
    
    # Validation check for credential file type
    if os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
        with open(ASSISTANT_GOOGLE_CREDENTIALS_FILE, 'r') as f:
            creds_data = json.load(f)
            if creds_data.get('type') == 'service_account':
                 error_msg = f"Error: '{ASSISTANT_GOOGLE_CREDENTIALS_FILE}' is a Service Account file, but a 'Web Application' OAuth client secret is required for the user login flow. Please check your .env file or upload the correct OAuth JSON."
                 logger.error(error_msg)
                 raise HTTPException(status_code=500, detail=error_msg)

    # Try to load client config
    client_config = None
    if os.path.exists(ASSISTANT_GOOGLE_CREDENTIALS_FILE):
        with open(ASSISTANT_GOOGLE_CREDENTIALS_FILE, 'r') as f:
            creds_data = json.load(f)
            client_type = 'web' if 'web' in creds_data else ('installed' if 'installed' in creds_data else None)
            if client_type:
                client_config = creds_data[client_type]
    elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        client_config = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": GOOGLE_AUTH_URI,
            "token_uri": GOOGLE_TOKEN_URI
        }

    if not client_config:
        raise HTTPException(status_code=500, detail="Google OAuth configuration missing during callback")

    flow = Flow.from_client_config(
        {"web": client_config} if "auth_uri" in client_config else {"installed": client_config},
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
    
    # Save tokens
    token_data = json.loads(creds.to_json())
    save_user_tokens(email, token_data)
    clear_client_cache(email)
    
    logger.info(f"Google OAuth completed for {email}")
    
    return HTMLResponse(content=f"""
        <h1>Google Authorization Complete!</h1>
        <p>Logged in as: <strong>{email}</strong></p>
        <p>You can now close this window and use the Assistant MCP.</p>
        <p>Scopes authorized: Drive, Gmail, Calendar</p>
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
            {
                "name": "assistant_get_rules",
                "description": "Returns the assistant's operating rules and behavioral guidelines. Call this first to understand constraints.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_write_rules",
                "description": "WARNING: Use extreme caution. This updates the assistant's core operating rules. Always read the current rules first, then modify and write back the full content.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Full markdown content for the rules"}
                    },
                    "required": ["content"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_get_priorities",
                "description": "Get current priorities. Call after assistant_get_rules to understand current focus.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_write_priorities",
                "description": "WARNING: Updates the assistant's high-level priorities. Always read current priorities first, then modify and write back the full content.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Full markdown content for priorities"}
                    },
                    "required": ["content"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_get_deadlines",
                "description": "Get the deadlines file content. Use this to track important dates and milestones.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_write_deadlines",
                "description": "WARNING: Updates the deadlines file. Always read current deadlines first, then modify and write back the full content.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Full markdown content for deadlines"}
                    },
                    "required": ["content"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_get_resources",
                "description": "Get reference resources and materials.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_list_projects",
                "description": "List all projects. Returns project IDs and names for use with assistant_get_project.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_get_project",
                "description": "Get the full content of a specific project document.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "Project document ID from assistant_list_projects"}
                    },
                    "required": ["project_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_list_inbox",
                "description": "List files in the inbox waiting to be processed.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_read_inbox_file",
                "description": "Read the content of a file in the inbox.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_id": {"type": "string", "description": "File ID from assistant_list_inbox"}
                    },
                    "required": ["file_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_move_to_outbox",
                "description": "Move a processed file from inbox to outbox.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_id": {"type": "string", "description": "File ID to move"}
                    },
                    "required": ["file_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_write_project",
                "description": "Update a project document. Always read current content first, then modify and write back.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project_id": {"type": "string", "description": "Project document ID"},
                        "content": {"type": "string", "description": "Full markdown content for the project"}
                    },
                    "required": ["project_id", "content"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_create_project",
                "description": "Create a new project document in the projects/ folder.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Project title (will be the Doc name)"},
                        "content": {"type": "string", "description": "Initial markdown content (optional)"}
                    },
                    "required": ["title"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_append_log",
                "description": "Add an entry to the activity log.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry": {"type": "string", "description": "Log entry text"}
                    },
                    "required": ["entry"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False
            },
            {
                "name": "assistant_log_session",
                "description": "Log the current conversation session. Call at start with initial summary, update at end with final summary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Session ID (omit for new session, include to update existing)"},
                        "summary": {"type": "string", "description": "Brief 1-2 sentence description of the conversation"},
                        "status": {"type": "string", "enum": ["active", "completed"], "default": "active"}
                    },
                    "required": ["summary"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False
            },
            {
                "name": "assistant_gmail_list",
                "description": "List recent emails. Supports label filtering and pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "description": "Label to filter (INBOX, UNREAD, STARRED, etc)", "default": "INBOX"},
                        "max_results": {"type": "integer", "description": "Max emails to return", "default": 20},
                        "page_token": {"type": "string", "description": "Pagination token for next page"}
                    }
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_gmail_read",
                "description": "Read the full content of a specific email.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID from assistant_gmail_list"}
                    },
                    "required": ["message_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_gmail_search",
                "description": "Search emails using Gmail query syntax.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Gmail search query"},
                        "max_results": {"type": "integer", "default": 20}
                    },
                    "required": ["query"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_gmail_label",
                "description": "Add or remove labels from an email.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID"},
                        "add_labels": {"type": "array", "items": {"type": "string"}, "description": "Labels to add"},
                        "remove_labels": {"type": "array", "items": {"type": "string"}, "description": "Labels to remove"}
                    },
                    "required": ["message_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False
            },
            {
                "name": "assistant_gmail_archive",
                "description": "Archive an email (removes INBOX label).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID to archive"}
                    },
                    "required": ["message_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_gmail_mark_read",
                "description": "Mark an email as read or unread.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "Message ID"},
                        "read": {"type": "boolean", "description": "True to mark as read, false to mark as unread", "default": True}
                    },
                    "required": ["message_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False
            },
            {
                "name": "assistant_calendar_list_calendars",
                "description": "List all accessible calendars.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_calendar_list_events",
                "description": "List upcoming calendar events.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary", "description": "Calendar ID"},
                        "time_min": {"type": "string", "description": "ISO datetime, defaults to now"},
                        "time_max": {"type": "string", "description": "ISO datetime for end of range"},
                        "max_results": {"type": "integer", "default": 10}
                    }
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_calendar_get_event",
                "description": "Get details of a specific calendar event.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary"},
                        "event_id": {"type": "string", "description": "Event ID"}
                    },
                    "required": ["event_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_calendar_create_event",
                "description": "Create a new calendar event.",
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
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_calendar_update_event",
                "description": "Update an existing calendar event.",
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
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": True,
                    "idempotentHint": True
                }
            },
            {
                "name": "assistant_calendar_delete_event",
                "description": "Delete a calendar event.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "calendar_id": {"type": "string", "default": "primary"},
                        "event_id": {"type": "string", "description": "Event ID to delete"}
                    },
                    "required": ["event_id"]
                },
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:write:assistant"]}],
                "x-openai-isConsequential": True,
                "isConsequential": True,
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": False,
                    "idempotentHint": False
                }
            },
            {
                "name": "assistant_google_account",
                "description": "Get the email address of the currently authenticated Google account.",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [{"type": "oauth2", "scopes": ["mcp:read:assistant"]}],
                "x-openai-isConsequential": False,
                "isConsequential": False,
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True
                }
            }
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
            doc_id = client.get_doc_by_name("base", "rules")
            if not doc_id:
                return {"content": [{"type": "text", "text": "No rules document found. Create a doc named 'rules' in your root folder."}]}
            content = client.read_doc_content(doc_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_write_rules":
            content = args.get("content", "")
            doc_id = client.get_doc_by_name("base", "rules")
            if not doc_id:
                doc_id = client.create_doc("base", "rules", content)
                return {"content": [{"type": "text", "text": "Created 'rules' document and wrote content."}]}
            client.write_doc_content(doc_id, content)
            return {"content": [{"type": "text", "text": "Rules updated successfully."}]}

        elif name == "assistant_get_priorities":
            doc_id = client.get_doc_by_name("base", "priorities")
            if not doc_id:
                return {"content": [{"type": "text", "text": "No priorities document found in root folder."}]}
            content = client.read_doc_content(doc_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_write_priorities":
            content = args.get("content", "")
            doc_id = client.get_doc_by_name("base", "priorities")
            if not doc_id:
                doc_id = client.create_doc("base", "priorities", content)
                return {"content": [{"type": "text", "text": "Created 'priorities' document and wrote content."}]}
            client.write_doc_content(doc_id, content)
            return {"content": [{"type": "text", "text": "Priorities updated successfully."}]}

        elif name == "assistant_get_deadlines":
            doc_id = client.get_doc_by_name("base", "deadlines")
            if not doc_id:
                return {"content": [{"type": "text", "text": "No deadlines document found in root folder."}]}
            content = client.read_doc_content(doc_id)
            return {"content": [{"type": "text", "text": content}]}
        
        elif name == "assistant_write_deadlines":
            content = args.get("content", "")
            doc_id = client.get_doc_by_name("base", "deadlines")
            if not doc_id:
                doc_id = client.create_doc("base", "deadlines", content)
                return {"content": [{"type": "text", "text": "Created 'deadlines' document and wrote content."}]}
            client.write_doc_content(doc_id, content)
            return {"content": [{"type": "text", "text": "Deadlines updated successfully."}]}

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

        elif name == "assistant_create_project":
            title = args.get("title")
            content = args.get("content")
            
            try:
                doc_id = client.create_doc("projects", title, content)
                return {"content": [{"type": "text", "text": f"Project '{title}' created successfully. Doc ID: {doc_id}"}]}
            except Exception as e:
                return {"isError": True, "content": [{"type": "text", "text": f"Failed to create project: {e}"}]}
        
        elif name == "assistant_append_log":
            entry = args.get("entry", "")
            timestamp = datetime.now(timezone.utc).isoformat()
            log_entry = f"\n[{timestamp}] {entry}"
            
            doc_id = client.get_doc_by_name("base", "assistant_log")
            if not doc_id:
                return {"isError": True, "content": [{"type": "text", "text": "Log document not found. Create 'assistant_log' in your root folder."}]}
            
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
            
            doc_id = client.get_doc_by_name("base", "sessions")
            if not doc_id:
                # Try alternative name
                doc_id = client.get_doc_by_name("base", "session_log")
            
            if not doc_id:
                return {"isError": True, "content": [{"type": "text", "text": "Sessions log not found. Create 'sessions' doc in your root folder."}]}
            
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
    
    except ValueError as e:
        # Handle specific authentication errors with a clear call to action
        error_msg = str(e)
        if "/assistant/google/login" in error_msg:
            logger.warning(f"Auth required for {name}: {error_msg}")
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Authentication required: {error_msg}"}],
                "metadata": {"reason": "auth_required", "login_url": f"{MCP_BASE_URL.rstrip('/')}/assistant/google/login"}
            }
        logger.error(f"Validation error in assistant tool {name}: {e}")
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error: {error_msg}"}],
            "metadata": {"reason": "validation_error"}
        }
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
async def handle_assistant_mcp(request: Request, payload: Dict = Depends(require_assistant_auth)):
    """Handle MCP JSON-RPC requests."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})
    
    # Check for SSE session
    session_id = request.query_params.get("session_id")
    sse_queue = _assistant_sse_sessions.get(session_id) if session_id else None

    async def _send_response(resp: Dict):
        if sse_queue:
            # Route response to SSE stream
            await sse_queue.put(resp)
            return Response(status_code=202)
        else:
            # Standard direct JSON response
            return resp

    if method == "initialize":
        return await _send_response(_rpc_result(rpc_id, _initialize_payload()))
    
    elif method == "ping":
        return await _send_response(_rpc_result(rpc_id, {"status": "ok"}))
    
    elif method == "tools/list":
        return await _send_response(_rpc_result(rpc_id, _list_assistant_tools()))
    
    elif method == "tools/call":
        # Get user email from the Auth0 payload - only required for tool execution
        from auth import extract_email
        user_email = extract_email(payload)
        
        if not user_email:
            # Fallback logic: If exactly one user is enabled in .assistant_users.json, use that.
            try:
                config = load_users_config()
                users_map = config.get("users", {})
                enabled_users = [email for email, u in users_map.items() if u.get("enabled", True)]
                
                if len(enabled_users) == 1:
                    user_email = enabled_users[0]
                    logger.warning(f"No email in token. Falling back to single configured user: {user_email}")
                elif len(enabled_users) > 1:
                    # Multiple users, cannot fallback safely
                    logger.error(f"User identity missing in token and multiple users are configured: {enabled_users}")
                    logger.error(f"Full payload dump: {safe_dumps(payload)}")
                    
                    user_list_str = ", ".join(enabled_users)
                    error_resp = _rpc_error(rpc_id, -32600, 
                        f"User identity missing and multiple users configured ({user_list_str}). "
                        "Please update ChatGPT scopes to include 'openid profile email' so we can identify you."
                    )
                    return await _send_response(error_resp)
            except Exception as e:
                logger.error(f"Error checking user fallback: {e}")
            
        name = params.get("name")
        args = params.get("arguments", {})
        result = await handle_assistant_tool_call(name, args, user_email)
        return await _send_response(_rpc_result(rpc_id, result))
    
    elif method == "prompts/list":
        return await _send_response(_rpc_result(rpc_id, _list_prompts()))
    
    elif method == "prompts/get":
        prompt_name = params.get("name")
        return await _send_response(_rpc_result(rpc_id, _get_prompt(prompt_name)))
    
    elif method == "resources/list":
        return await _send_response(_rpc_result(rpc_id, {"resources": []}))
    
    elif method == "resources/read":
        return await _send_response(_rpc_result(rpc_id, {"contents": []}))
    
    else:
        return await _send_response(_rpc_error(rpc_id, -32601, f"Method {method} not found"))
