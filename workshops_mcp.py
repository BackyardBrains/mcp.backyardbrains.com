import os
import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends, Response
from datetime import datetime
import phpserialize
import mysql.connector
import requests
import time
from cryptography.fernet import Fernet, InvalidToken

from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

from utils import MCP_PROTOCOL_VERSION, _rpc_result, _rpc_error, logger, safe_dumps
from auth import require_workshops_auth, check_permissions

# Environment variables
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')
WP_URL = os.getenv('WP_URL')
MCP_BASE_URL = os.getenv('MCP_BASE_URL')

router = APIRouter()

# Google Sheets Configuration
GOOGLE_CREDENTIALS_FILE = os.environ.get("GOOGLE_CREDENTIALS_FILE", "google_credentials.json")
GOOGLE_TOKEN_STORE_PATH = os.environ.get("GOOGLE_TOKEN_STORE_PATH", ".google_tokens.enc")
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']

# Encryption setup (shared with Xero if TOKEN_ENC_KEY is set)
TOKEN_ENC_KEY = os.environ.get("TOKEN_ENC_KEY")
if not TOKEN_ENC_KEY:
    logger.warning("TOKEN_ENC_KEY not set; Google tokens will not be encrypted!")
fernet = Fernet(TOKEN_ENC_KEY) if TOKEN_ENC_KEY else None

def encrypt_data(data: bytes) -> bytes:
    if not fernet: return data
    return fernet.encrypt(data)

def decrypt_data(encrypted: bytes) -> bytes:
    if not fernet: return encrypted
    try:
        return fernet.decrypt(encrypted)
    except InvalidToken:
        raise ValueError("Invalid encryption key or corrupted token file")

def load_google_tokens():
    if not os.path.exists(GOOGLE_TOKEN_STORE_PATH):
        return None
    try:
        with open(GOOGLE_TOKEN_STORE_PATH, 'rb') as f:
            encrypted = f.read()
        decrypted = decrypt_data(encrypted)
        return json.loads(decrypted)
    except Exception as e:
        logger.error(f"Failed to load Google tokens: {e}")
        return None

def save_google_tokens(tokens: Dict):
    try:
        data = json.dumps(tokens).encode('utf-8')
        encrypted = encrypt_data(data)
        with open(GOOGLE_TOKEN_STORE_PATH, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        logger.error(f"Failed to save Google tokens: {e}")

def get_google_credentials():
    """Get authorized Google credentials, using Service Account or OAuth2 User Flow."""
    client_config = {}
    
    # 1. Load configuration from file (needed for both Service Account and OAuth refresh)
    if os.path.exists(GOOGLE_CREDENTIALS_FILE):
        try:
            with open(GOOGLE_CREDENTIALS_FILE, 'r') as f:
                creds_data = json.load(f)
            
            # Case A: Service Account
            if creds_data.get('type') == 'service_account':
                logger.info("Using Google Service Account credentials")
                return service_account.Credentials.from_service_account_info(
                    creds_data, scopes=GOOGLE_SCOPES
                )
            
            # Case B: OAuth Client Secret (Web or Desktop)
            # Detect client type: 'web' for Web Apps, 'installed' for Desktop
            client_type = 'web' if 'web' in creds_data else ('installed' if 'installed' in creds_data else None)
            if client_type:
                client_config = creds_data[client_type]
                logger.info(f"Loaded Google OAuth client configuration (type: {client_type})")
        except Exception as e:
            logger.error(f"Failed to read {GOOGLE_CREDENTIALS_FILE}: {e}")

    # 2. Fallback to OAuth2 User Flow if token data exists
    token_data = load_google_tokens()
    if not token_data:
        logger.warning(f"No Google tokens found at {GOOGLE_TOKEN_STORE_PATH}")
        return None
    
    # CRITICAL: Always use the client ID and secret from the current credentials file
    # This ensures that if the server environment changed (e.g. from Desktop to Web),
    # the existing Refresh Token is used with the new Client Identity.
    if client_config:
        token_data['client_id'] = client_config.get('client_id')
        token_data['client_secret'] = client_config.get('client_secret')
        # Some Google libraries also expect these for refresh
        if 'token_uri' in client_config:
            token_data['token_uri'] = client_config['token_uri']

    try:
        creds = Credentials.from_authorized_user_info(token_data, GOOGLE_SCOPES)
        
        if creds and creds.expired and creds.refresh_token:
            logger.info("Google token expired; attempting refresh...")
            creds.refresh(GoogleRequest())
            # Save the updated token data (including potentially new access token)
            save_google_tokens(json.loads(creds.to_json()))
            logger.info("Google token successfully refreshed")
                
        return creds
    except Exception as e:
        logger.error(f"Failed to load or refresh Google credentials: {e}")
        return None

def get_db_connection():
    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        raise ValueError("Missing database configuration in environment variables")
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

def _deserialize_php(value: Any) -> Any:
    """Attempt to deserialize if it looks like PHP serialized data."""
    try:
        if value and isinstance(value, str) and (value.startswith('a:') or value.startswith('O:') or value.startswith('s:') or value.startswith('i:') or value.startswith('d:') or value.startswith('b:')):
            deserialized = phpserialize.loads(value.encode('utf-8'))
            if isinstance(deserialized, dict):
                result = {}
                for sub_key, sub_value in deserialized.items():
                    k = sub_key.decode('utf-8') if isinstance(sub_key, bytes) else str(sub_key)
                    v = sub_value.decode('utf-8') if isinstance(sub_value, bytes) else str(sub_value)
                    result[f"{k}"] = v
                return result
            else:
                 return deserialized
        return value
    except Exception:
        return value

# Automatic language detection removed as per user requirement.
# Users must explicitly provide the 'language' parameter ('en' or 'sr').

def serialize_gallery_ids(ids: List[int]) -> str:
    """Serialize array of IDs to PHP format for gallery field."""
    if not ids:
        return 'a:0:{}'
    
    items = {}
    for i, idx in enumerate(ids):
        items[i] = str(idx).encode('utf-8')
    
    return phpserialize.dumps(items).decode('utf-8')

def deserialize_gallery_ids(serialized: str) -> List[int]:
    """Deserialize PHP array format to JS array."""
    if not serialized or serialized == 'a:0:{}':
        return []
    
    try:
        deserialized = phpserialize.loads(serialized.encode('utf-8'))
        if isinstance(deserialized, dict):
            return [int(v.decode('utf-8') if isinstance(v, bytes) else v) for v in deserialized.values()]
    except Exception:
        pass
    return []

def fetch_terms(cursor, post_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """Fetch audience (grade), language (workshop-language), Polylang language, and translations."""
    if not post_ids:
        return {}
    
    placeholders = ', '.join(['%s'] * len(post_ids))
    sql = f"""
        SELECT tr.object_id, tt.taxonomy, t.name, t.slug, tt.description
        FROM wp_term_relationships tr
        JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
        JOIN wp_terms t ON tt.term_id = t.term_id
        WHERE tr.object_id IN ({placeholders})
          AND tt.taxonomy IN ('grade', 'workshop-language', 'language', 'post_translations')
    """
    cursor.execute(sql, tuple(post_ids))
    rows = cursor.fetchall()
    
    results = {pid: {'audience': [], 'language_badge': [], 'pll_lang': None, 'translations': {}} for pid in post_ids}
    for row in rows:
        pid = row['object_id']
        tax = row['taxonomy']
        name = row['name']
        slug = row['slug']
        desc = row['description']
        
        if tax == 'grade':
            results[pid]['audience'].append(name)
        elif tax == 'workshop-language':
            results[pid]['language_badge'].append(name)
        elif tax == 'language':
            results[pid]['pll_lang'] = slug
        elif tax == 'post_translations':
            try:
                trans = _deserialize_php(desc)
                if isinstance(trans, dict):
                    results[pid]['translations'] = {k: int(v) for k, v in trans.items()}
            except Exception:
                pass
            
    return results


class PolylangClient:
    def __init__(self):
        if not WP_URL:
            logger.error("WP_URL environment variable not set")
            raise ValueError("WP_URL not set")
        
        self.base_url = WP_URL.rstrip("/")
        self.languages = {}
        self.last_refresh = 0
        self.ttl = 3600 # 1 hour
        
        # Initial discovery
        self.refresh_languages()

    def refresh_languages(self):
        """Fetch languages from Polylang REST API."""
        try:
            url = f"{self.base_url}/wp-json/pll/v1/languages"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            langs = resp.json()
            
            new_languages = {}
            for lang in langs:
                slug = lang.get('slug')
                # Polylang REST returns term_props.language.term_taxonomy_id or similar
                # Based on user description, we need term_taxonomy_id from term_props.language
                term_props = lang.get('term_props', {})
                language_props = term_props.get('language', {})
                tt_id = language_props.get('term_taxonomy_id')
                
                if slug and tt_id:
                    new_languages[slug] = int(tt_id)
            
            # Fail hard if en or sr are missing
            if 'en' not in new_languages:
                logger.error("Polylang discovery failed: 'en' slug missing")
                raise ValueError("Polylang discovery failed: 'en' missing")
            if 'sr' not in new_languages:
                logger.error("Polylang discovery failed: 'sr' slug missing")
                raise ValueError("Polylang discovery failed: 'sr' missing")
                
            self.languages = new_languages
            self.last_refresh = time.time()
            logger.info(f"Successfully discovered Polylang languages: {list(self.languages.keys())}")
        except Exception as e:
            logger.error(f"Failed to discover Polylang languages: {e}")
            if not self.languages: # If initial discovery fails
                raise

    def get_languages(self) -> Dict[str, int]:
        if time.time() - self.last_refresh > self.ttl:
            self.refresh_languages()
        return self.languages

    def get_tt_id(self, slug: str) -> Optional[int]:
        return self.get_languages().get(slug)

_polylang_client = None

def get_polylang_client():
    global _polylang_client
    if _polylang_client is None:
        try:
            _polylang_client = PolylangClient()
        except Exception as e:
            logger.error(f"Failed to initialize Polylang client: {e}")
            return None
    return _polylang_client

def pll_set_post_language(cursor, post_id: int, lang_code: str):
    """Set the Polylang language for a post using discovered IDs."""
    client = get_polylang_client()
    if not client:
        raise HTTPException(status_code=500, detail="Polylang client not initialized")
    
    tt_id = client.get_tt_id(lang_code)
    if not tt_id:
        raise HTTPException(status_code=400, detail=f"Invalid or undiscovered language slug: {lang_code}")

    # Delete existing language relationship for post_id
    sql_delete = """
        DELETE tr FROM wp_term_relationships tr
        JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
        WHERE tr.object_id = %s AND tt.taxonomy = 'language'
    """
    cursor.execute(sql_delete, (post_id,))

    # Insert new relationship
    sql_insert = "INSERT INTO wp_term_relationships (object_id, term_taxonomy_id, term_order) VALUES (%s, %s, 0)"
    cursor.execute(sql_insert, (post_id, tt_id))
    
    # Verify count == 1 (idempotent because we deleted first, but we check final state)
    cursor.execute("""
        SELECT COUNT(*) as count 
        FROM wp_term_relationships tr
        JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
        WHERE tr.object_id = %s AND tt.taxonomy = 'language'
    """, (post_id,))
    res = cursor.fetchone()
    if res['count'] != 1:
        raise Exception(f"Failed to set Polylang language: expected 1 relationship, found {res['count']}")

def pll_save_translations(cursor, post_ids_by_lang: Dict[str, int]):
    """Link posts as translations in Polylang with merge logic."""
    if len(post_ids_by_lang) < 1:
        return

    # 1. Fetch existing groups for all involved posts
    post_ids = list(post_ids_by_lang.values())
    placeholders = ', '.join(['%s'] * len(post_ids))
    sql_existing = f"""
        SELECT tr.object_id, tt.term_taxonomy_id, tt.description
        FROM wp_term_relationships tr
        JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
        WHERE tr.object_id IN ({placeholders}) AND tt.taxonomy = 'post_translations'
    """
    cursor.execute(sql_existing, tuple(post_ids))
    rows = cursor.fetchall()

    # Map post ID to its current group TT ID
    post_to_group = {row['object_id']: row['term_taxonomy_id'] for row in rows}
    # Map group TT ID to its current translations (deserialized)
    groups = {row['term_taxonomy_id']: _deserialize_php(row['description']) or {} for row in rows}

    # Decide which group to use (reuse existing if any)
    group_tt_ids = list(groups.keys())
    
    if not group_tt_ids:
        # Scenario: neither post in a group -> create
        import uuid
        group_name = f"pll_{uuid.uuid4().hex[:13]}"
        cursor.execute("INSERT INTO wp_terms (name, slug, term_group) VALUES (%s, %s, 0)", (group_name, group_name))
        term_id = cursor.lastrowid
        
        # We'll insert tt later once we have the full mapping
        group_tt_id = None 
        merged_translations = {}
    elif len(group_tt_ids) == 1:
        # Scenario: one or more posts in the SAME group -> reuse
        group_tt_id = group_tt_ids[0]
        merged_translations = groups[group_tt_id]
    else:
        # Scenario: posts in DIFFERENT groups -> merge
        # Take the first group and merge all others into it
        group_tt_id = group_tt_ids[0]
        merged_translations = groups[group_tt_id]
        
        for other_tt_id in group_tt_ids[1:]:
            other_trans = groups[other_tt_id]
            merged_translations.update(other_trans)
            
            # Delete the defunct group relationships and terms
            cursor.execute("DELETE FROM wp_term_relationships WHERE term_taxonomy_id = %s", (other_tt_id,))
            cursor.execute("SELECT term_id FROM wp_term_taxonomy WHERE term_taxonomy_id = %s", (other_tt_id,))
            old_term_res = cursor.fetchone()
            cursor.execute("DELETE FROM wp_term_taxonomy WHERE term_taxonomy_id = %s", (other_tt_id,))
            if old_term_res:
                cursor.execute("DELETE FROM wp_terms WHERE term_id = %s", (old_term_res['term_id'],))

    # Incorporate the new post_ids_by_lang
    for lang, pid in post_ids_by_lang.items():
        merged_translations[lang] = pid

    # Enforce invariant: description mapping matches exactly {en: id, sr: id} for your two-language world
    # (actually we keep whatever is there but prioritize the ones we just added)
    # We use phpserialize to ensure correctness
    
    # Cast IDs to int for serialization consistency
    final_translations = {str(k): int(v) for k, v in merged_translations.items()}
    # Filter to only 'en' and 'sr' as per user request "two-language world"
    final_translations = {k: v for k, v in final_translations.items() if k in ['en', 'sr']}
    
    # Sort keys for deterministic serialization string (helpful for testing)
    sorted_translations = dict(sorted(final_translations.items()))
    
    # We must use phpserialize properly. phpserialize.dumps uses bytes.
    # Convert to bytes for serialization
    bytes_map = {k.encode('utf-8'): v for k, v in sorted_translations.items()}
    serialized_desc = phpserialize.dumps(bytes_map).decode('utf-8')

    if group_tt_id is None:
        # Create the new taxonomy entry
        cursor.execute("INSERT INTO wp_term_taxonomy (term_id, taxonomy, description, count) VALUES (%s, 'post_translations', %s, %s)", 
                       (term_id, serialized_desc, len(sorted_translations)))
        group_tt_id = cursor.lastrowid
    else:
        # Update existing group
        cursor.execute("UPDATE wp_term_taxonomy SET description = %s, count = %s WHERE term_taxonomy_id = %s",
                       (serialized_desc, len(sorted_translations), group_tt_id))

    # Ensure all posts have EXACTLY one relationship to THIS group and NO others
    all_pids = list(sorted_translations.values())
    for pid in all_pids:
        # Delete ANY existing post_translations relationships for this post
        cursor.execute("""
            DELETE tr FROM wp_term_relationships tr
            JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
            WHERE tr.object_id = %s AND tt.taxonomy = 'post_translations'
        """, (pid,))
        
        # Insert the one true relationship
        cursor.execute("INSERT INTO wp_term_relationships (object_id, term_taxonomy_id, term_order) VALUES (%s, %s, 0)", (pid, group_tt_id))

def set_workshop_terms(cursor, post_id: int, taxonomy: str, term_names: List[str]):
    """Set terms for a post. If term_names is empty, clears terms for that taxonomy."""
    # First, delete existing relationships for this taxonomy
    sql_delete = """
        DELETE tr FROM wp_term_relationships tr
        JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
        WHERE tr.object_id = %s AND tt.taxonomy = %s
    """
    cursor.execute(sql_delete, (post_id, taxonomy))

    if not term_names:
        return

    # Filter out empty names
    term_names = [n for n in term_names if n.strip()]
    if not term_names:
        return

    # Find term_taxonomy_ids
    placeholders = ', '.join(['%s'] * len(term_names))
    sql_find = f"""
        SELECT tt.term_taxonomy_id
        FROM wp_term_taxonomy tt
        JOIN wp_terms t ON tt.term_id = t.term_id
        WHERE tt.taxonomy = %s AND t.name IN ({placeholders})
    """
    cursor.execute(sql_find, (taxonomy, *term_names))
    rows = cursor.fetchall()
    
    tt_ids = [row['term_taxonomy_id'] for row in rows]
    
    # Insert new relationships
    if tt_ids:
        sql_insert = "INSERT INTO wp_term_relationships (object_id, term_taxonomy_id, term_order) VALUES (%s, %s, 0)"
        for tt_id in tt_ids:
            cursor.execute(sql_insert, (post_id, tt_id))

# Workshop Specific Functions

async def workshop_list(params: Dict[str, Any]):
    status = params.get('status', 'publish')
    language = params.get('language', 'all')
    upcoming_only = params.get('upcoming_only', False)
    start_date_after = params.get('start_date_after')
    start_date_before = params.get('start_date_before')
    limit = params.get('limit', 50)
    include_meta = params.get('include_meta', False)

    status_condition = "p.post_status IN ('publish', 'draft')" if status == 'all' else f"p.post_status = %s"
    status_val = (status,) if status != 'all' else ()

    meta_fields = ""
    if include_meta:
        meta_fields = """,
          MAX(CASE WHEN pm.meta_key = 'about_left' THEN pm.meta_value END) as about_left,
          MAX(CASE WHEN pm.meta_key = 'about_right' THEN pm.meta_value END) as about_right,
          MAX(CASE WHEN pm.meta_key = 'sign_up_link' THEN pm.meta_value END) as sign_up_link"""

    sql = f"""
        SELECT 
          p.ID as id,
          p.post_title as title,
          p.post_status as status,
          p.post_date as created,
          MAX(CASE WHEN pm.meta_key = 'start_date' THEN pm.meta_value END) as start_date,
          MAX(CASE WHEN pm.meta_key = 'end_date' THEN pm.meta_value END) as end_date,
          MAX(CASE WHEN pm.meta_key = 'location' THEN pm.meta_value END) as location,
          MAX(CASE WHEN pm.meta_key = 'full' THEN pm.meta_value END) as is_full
          {meta_fields}
        FROM wp_posts p
        LEFT JOIN wp_postmeta pm ON p.ID = pm.post_id
        WHERE p.post_type = 'workshop'
          AND {status_condition}
        GROUP BY p.ID
        HAVING 1=1
    """

    if start_date_after:
        sql = sql.replace("HAVING 1=1", "HAVING start_date >= %s")
    if start_date_before:
        if "start_date >=" in sql:
            sql = sql.replace("HAVING start_date >= %s", "HAVING start_date >= %s AND start_date <= %s")
        else:
            sql = sql.replace("HAVING 1=1", "HAVING start_date <= %s")

    sql += """
        ORDER BY start_date DESC
        LIMIT %s
    """

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query_params = list(status_val)
        if start_date_after:
            query_params.append(start_date_after)
        if start_date_before:
            query_params.append(start_date_before)
        query_params.append(limit)
        
        cursor.execute(sql, tuple(query_params))
        rows = cursor.fetchall()
        
        workshops = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for row in rows:
            if upcoming_only and row['start_date'] and row['start_date'] <= now:
                continue
                
            workshop = {
                **row,
                'is_full': row['is_full'] == '1',
                'created': row['created'].isoformat() if hasattr(row['created'], 'isoformat') else str(row['created'])
            }
            workshops.append(workshop)
            
        # Fetch terms for all workshops
        if workshops:
            wids = [w['id'] for w in workshops]
            terms_map = fetch_terms(cursor, wids)
            filtered_workshops = []
            for w in workshops:
                tags = terms_map.get(w['id'], {})
                w['audience'] = tags.get('audience', [])
                
                # Polylang lang is source of truth
                pll_lang = tags.get('pll_lang')
                if pll_lang:
                    w['language'] = pll_lang
                else:
                    w['language'] = 'unknown'

                if language != 'all' and w['language'] != language:
                    continue

                # Use the first language badge found, or fallback to w['language']
                l_badges = tags.get('language_badge', [])
                w['language_badge'] = l_badges[0] if l_badges else w['language']
                w['translations'] = tags.get('translations', {})
                
                filtered_workshops.append(w)
            workshops = filtered_workshops
                
        return {"workshops": workshops, "count": len(workshops)}
    finally:
        conn.close()

async def workshop_get(params: Dict[str, Any]):
    ids = params.get('ids', [])
    include_gallery = params.get('include_gallery', True)
    include_registrations = params.get('include_registrations', False)

    if not ids:
        return {"workshops": []}

    placeholders = ', '.join(['%s'] * len(ids))
    sql = rf"""
        SELECT 
          p.ID,
          p.post_title,
          p.post_status,
          p.post_date,
          p.post_modified,
          p.post_content,
          p.post_excerpt,
          pm.meta_key,
          pm.meta_value
        FROM wp_posts p
        LEFT JOIN wp_postmeta pm ON p.ID = pm.post_id
        WHERE p.ID IN ({placeholders})
          AND p.post_type = 'workshop'
          AND (pm.meta_key NOT LIKE '\\_%' OR pm.meta_key = '_thumbnail_id')
        ORDER BY p.ID, pm.meta_key
    """

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, tuple(ids))
        rows = cursor.fetchall()

        workshops_map = {}
        for row in rows:
            wid = row['ID']
            if wid not in workshops_map:
                workshops_map[wid] = {
                    'id': wid,
                    'title': row['post_title'],
                    'status': row['post_status'],
                    'post_content': row['post_content'],
                    'post_excerpt': row['post_excerpt'],
                    'created': row['post_date'].isoformat() if hasattr(row['post_date'], 'isoformat') else str(row['post_date']),
                    'modified': row['post_modified'].isoformat() if hasattr(row['post_modified'], 'isoformat') else str(row['post_modified']),
                    'is_full': False,
                    'featured_image_id': None,
                    'gallery_ids': [],
                    'translations': {}
                }
            
            key = row['meta_key']
            val = row['meta_value']
            
            if key == 'start_date': workshops_map[wid]['start_date'] = val
            elif key == 'end_date': workshops_map[wid]['end_date'] = val
            elif key == 'location': workshops_map[wid]['location'] = val
            elif key == 'about_left': workshops_map[wid]['about_left'] = val
            elif key == 'about_right': workshops_map[wid]['about_right'] = val
            elif key == 'sign_up_link': workshops_map[wid]['sign_up_link'] = val
            elif key == 'full': workshops_map[wid]['is_full'] = val == '1'
            elif key == '_thumbnail_id': workshops_map[wid]['featured_image_id'] = int(val) if val else None
            elif key == 'gallery' and include_gallery:
                workshops_map[wid]['gallery_ids'] = deserialize_gallery_ids(val)

        # Fetch terms
        if workshops_map:
            wids = list(workshops_map.keys())
            terms_map = fetch_terms(cursor, wids)
            for wid, w in workshops_map.items():
                tags = terms_map.get(wid, {})
                w['audience'] = tags.get('audience', [])
                
                pll_lang = tags.get('pll_lang')
                if pll_lang:
                    w['language'] = pll_lang
                else:
                    w['language'] = 'unknown'

                l_badges = tags.get('language_badge', [])
                w['language_badge'] = l_badges[0] if l_badges else w['language']
                w['translations'] = tags.get('translations', {})

        workshops = list(workshops_map.values())

        if include_registrations:
            for w in workshops:
                reg_sql = """
                    SELECT COUNT(*) as registrations
                    FROM wp_frmt_form_entry_meta
                    WHERE meta_key = 'text-4'
                      AND meta_value LIKE %s
                """
                cursor.execute(reg_sql, (f"%{w['title']}%",))
                reg_res = cursor.fetchone()
                w['registrations'] = reg_res['registrations'] if reg_res else 0
        
        include_feedback = params.get('include_feedback', False)
        if include_feedback:
            # Note: This is expensive as it fetches all feedback from sheets.
            # In a real app, you'd cache this or use a more efficient query.
            for w in workshops:
                # We need spreadsheet IDs for feedback. 
                # For now, we'll try to use provided IDs or placeholders.
                rs_sheet_id = params.get('feedback_spreadsheet_rs')
                en_sheet_id = params.get('feedback_spreadsheet_en')
                
                feedback_data = []
                if rs_sheet_id:
                    res = await workshop_read_feedback({"spreadsheet_id": rs_sheet_id, "workshop_title": w['title']})
                    feedback_data.extend(res.get('feedback', []))
                if en_sheet_id:
                    res = await workshop_read_feedback({"spreadsheet_id": en_sheet_id, "workshop_title": w['title']})
                    feedback_data.extend(res.get('feedback', []))
                
                w['feedback'] = feedback_data
                w['feedback_count'] = len(feedback_data)

        return {"workshops": workshops}
    finally:
        conn.close()

async def workshop_create(params: Dict[str, Any]):
    title = params.get('title')
    start_date = params.get('start_date')
    end_date = params.get('end_date')
    location = params.get('location')
    about_left = params.get('about_left')
    about_right = params.get('about_right')
    post_content = params.get('post_content', '')
    post_excerpt = params.get('post_excerpt', '')
    sign_up_link = params.get('sign_up_link', '')
    language = params.get('language') # Required: 'en' or 'sr'
    if not language:
        raise HTTPException(status_code=400, detail="Language is required (en or sr)")
    
    language_badge = params.get('language_badge')
    translation_of = params.get('translation_of') # ID of post this is a translation of

    status = params.get('status', 'draft')
    is_full = params.get('is_full', False)
    gallery_ids = params.get('gallery_ids', [])
    featured_image_id = params.get('featured_image_id')
    audience = params.get('audience', [])

    slug = title.lower().replace(' ', '-').replace('/', '-')

    sql_post = """
        INSERT INTO wp_posts (
          post_author, post_date, post_date_gmt, post_content, post_title,
          post_excerpt, post_status, comment_status, ping_status, post_name,
          post_modified, post_modified_gmt, post_parent, guid, menu_order, post_type,
          to_ping, pinged, post_content_filtered
        ) VALUES (
          1, NOW(), UTC_TIMESTAMP(), %s, %s, %s, %s, 'closed', 'closed', %s,
          NOW(), UTC_TIMESTAMP(), 0, '', 0, 'workshop', '', '', ''
        )
    """

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql_post, (post_content, title, post_excerpt, status, slug))
        new_id = cursor.lastrowid

        guid = f"{WP_URL}/?post_type=workshop&p={new_id}"
        cursor.execute("UPDATE wp_posts SET guid = %s WHERE ID = %s", (guid, new_id))

        meta_v = [
            (new_id, 'start_date', start_date),
            (new_id, 'end_date', end_date),
            (new_id, 'location', location),
            (new_id, 'about_left', about_left),
            (new_id, 'about_right', about_right),
            (new_id, 'sign_up_link', sign_up_link),
            (new_id, 'full', '1' if is_full else '0'),
            (new_id, 'badges', ''),
            (new_id, 'resources', ''),
            (new_id, 'gallery', serialize_gallery_ids(gallery_ids))
        ]
        if featured_image_id:
            meta_v.append((new_id, '_thumbnail_id', str(featured_image_id)))

        cursor.executemany("INSERT INTO wp_postmeta (post_id, meta_key, meta_value) VALUES (%s, %s, %s)", meta_v)
        
        # Set terms
        if audience:
            set_workshop_terms(cursor, new_id, 'grade', audience)

        # Polylang Assignment (Strict DB assignment)
        pll_set_post_language(cursor, new_id, language)
        
        # Language Badge (Legacy UI support)
        if not language_badge:
            language_badge = "English" if language == "en" else "Serbian"
        set_workshop_terms(cursor, new_id, 'workshop-language', [language_badge])
        
        # Translation Linking (Merge logic)
        if translation_of:
            # We need the language of the other post for linking
            cursor.execute("""
                SELECT t.slug 
                FROM wp_term_relationships tr 
                JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id 
                JOIN wp_terms t ON tt.term_id = t.term_id 
                WHERE tr.object_id = %s AND tt.taxonomy = 'language'
            """, (translation_of,))
            t_row = cursor.fetchone()
            if t_row:
                pll_save_translations(cursor, {language: new_id, t_row['slug']: translation_of})

        conn.commit()
        return {"id": new_id, "status": "success"}
    finally:
        conn.close()

async def workshop_update(params: Dict[str, Any]):
    wid = params.get('id')
    if not wid:
        raise HTTPException(status_code=400, detail="Missing workshop ID")

    updates = []
    post_params = []
    
    if 'title' in params:
        updates.append("post_title = %s")
        post_params.append(params['title'])
    if 'status' in params:
        updates.append("post_status = %s")
        post_params.append(params['status'])
    if 'post_content' in params:
        updates.append("post_content = %s")
        post_params.append(params['post_content'])
    if 'post_excerpt' in params:
        updates.append("post_excerpt = %s")
        post_params.append(params['post_excerpt'])
    
    if updates:
        updates.append("post_modified = NOW(), post_modified_gmt = UTC_TIMESTAMP()")
        sql_update = f"UPDATE wp_posts SET {', '.join(updates)} WHERE ID = %s AND post_type = 'workshop'"
        post_params.append(wid)
        
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        if updates:
            cursor.execute(sql_update, tuple(post_params))

        meta_keys = {
            'start_date': params.get('start_date'),
            'end_date': params.get('end_date'),
            'location': params.get('location'),
            'about_left': params.get('about_left'),
            'about_right': params.get('about_right'),
            'sign_up_link': params.get('sign_up_link'),
            'full': '1' if params.get('is_full') is True else ('0' if params.get('is_full') is False else None),
            '_thumbnail_id': params.get('featured_image_id'),
            'gallery': serialize_gallery_ids(params.get('gallery_ids')) if 'gallery_ids' in params else None
        }

        for key, val in meta_keys.items():
            if val is not None:
                cursor.execute("SELECT meta_id FROM wp_postmeta WHERE post_id = %s AND meta_key = %s", (wid, key))
                rows = cursor.fetchall()
                if rows:
                    # Update existing meta entries
                    for row in rows:
                        cursor.execute("UPDATE wp_postmeta SET meta_value = %s WHERE meta_id = %s", (val, row['meta_id']))
                else:
                    cursor.execute("INSERT INTO wp_postmeta (post_id, meta_key, meta_value) VALUES (%s, %s, %s)", (wid, key, val))

        # Update terms
        if 'audience' in params:
            set_workshop_terms(cursor, wid, 'grade', params['audience'])
        
        if 'language' in params:
            lang_code = params['language']
            pll_set_post_language(cursor, wid, lang_code)
            
            # If no badge update provided, try to update it too
            if 'language_badge' not in params:
                new_badge = "English" if lang_code == "en" else "Serbian"
                set_workshop_terms(cursor, wid, 'workshop-language', [new_badge])

        if 'language_badge' in params:
            set_workshop_terms(cursor, wid, 'workshop-language', [params['language_badge']])
            
        if 'translation_of' in params:
            # Need current language for linking
            cursor.execute("""
                SELECT t.slug 
                FROM wp_term_relationships tr 
                JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id 
                JOIN wp_terms t ON tt.term_id = t.term_id 
                WHERE tr.object_id = %s AND tt.taxonomy = 'language'
            """, (wid,))
            w_row = cursor.fetchone()
            current_lang = w_row['slug'] if w_row else None
            
            trans_of = params['translation_of']
            if trans_of and current_lang:
                # Get the translation of's language
                cursor.execute("""
                    SELECT t.slug 
                    FROM wp_term_relationships tr 
                    JOIN wp_term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id 
                    JOIN wp_terms t ON tt.term_id = t.term_id 
                    WHERE tr.object_id = %s AND tt.taxonomy = 'language'
                """, (trans_of,))
                t_row = cursor.fetchone()
                if t_row:
                    pll_save_translations(cursor, {current_lang: wid, t_row['slug']: trans_of})

        conn.commit()
        return {"id": wid, "status": "success"}
    finally:
        conn.close()

async def workshop_find_pair(params: Dict[str, Any]):
    wid = params.get('id')
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        sql_info = """
            SELECT 
                p.ID,
                MAX(CASE WHEN pm.meta_key = 'start_date' THEN pm.meta_value END) as start_date,
                MAX(CASE WHEN pm.meta_key = 'location' THEN pm.meta_value END) as location
            FROM wp_posts p
            JOIN wp_postmeta pm ON p.ID = pm.post_id
            WHERE p.ID = %s
            GROUP BY p.ID
        """
        cursor.execute(sql_info, (wid,))
        info = cursor.fetchone()
        
        if not info:
            return {"pair": None}
            
        # 1. NEW: Check Polylang for a hard link
        terms = fetch_terms(cursor, [wid])
        w_terms = terms.get(wid, {})
        translations = w_terms.get('translations', {})
        pll_lang = w_terms.get('pll_lang')
        
        if translations and pll_lang:
            pair_lang = 'sr' if pll_lang == 'en' else 'en'
            pair_id = translations.get(pair_lang)
            if pair_id:
                cursor.execute("SELECT ID, post_title FROM wp_posts WHERE ID = %s", (pair_id,))
                p_row = cursor.fetchone()
                if p_row:
                    return {"pair": p_row, "source": "polylang"}

        # Fallback to matching by metadata
        sql_pair = """
            SELECT 
              p.ID,
              p.post_title
            FROM wp_posts p
            JOIN wp_postmeta pm ON p.ID = pm.post_id
            WHERE p.post_type = 'workshop'
              AND p.post_status = 'publish'
              AND p.ID != %s
            GROUP BY p.ID
            HAVING 
              MAX(CASE WHEN pm.meta_key = 'start_date' THEN pm.meta_value END) = %s
              AND MAX(CASE WHEN pm.meta_key = 'location' THEN pm.meta_value END) = %s
        """
        cursor.execute(sql_pair, (wid, info['start_date'], info['location']))
        pair = cursor.fetchone()
        
        return {"pair": pair, "source": "metadata" if pair else None}
    finally:
        conn.close()

async def workshop_registrations(params: Dict[str, Any]):
    wid = params.get('workshop_id')
    title_match = params.get('workshop_title')
    include_details = params.get('include_details', False)
    
    # Forminator doesn't store the workshop ID, only the title (in field text-4).
    # To find all registrations for a workshop, we must search for its primary title 
    # and all of its translation titles in the registration entries.
    titles_to_match = []
    if title_match:
        titles_to_match.append(title_match)

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        
        # 1. If we have a title but no ID, try to find the ID to get translations
        if title_match and not wid:
            cursor.execute("SELECT ID FROM wp_posts WHERE post_title = %s AND post_type = 'workshop' LIMIT 1", (title_match,))
            t_row = cursor.fetchone()
            if t_row:
                wid = t_row['ID']

        # 2. If we have an ID (or just found it), get its title and all translation titles
        if wid:
            # Get primary title if not already added (ensures we have the exact DB title)
            cursor.execute("SELECT post_title FROM wp_posts WHERE ID = %s", (wid,))
            res = cursor.fetchone()
            if res:
                primary_title = res['post_title']
                if primary_title not in titles_to_match:
                    titles_to_match.append(primary_title)
            
            # Find all translations linked via Polylang
            terms_map = fetch_terms(cursor, [wid])
            translations = terms_map.get(wid, {}).get('translations', {})
            
            # Fetch titles for all translated IDs
            other_ids = [tid for tid in translations.values() if tid != wid]
            if other_ids:
                placeholders = ', '.join(['%s'] * len(other_ids))
                cursor.execute(f"SELECT post_title FROM wp_posts WHERE ID IN ({placeholders})", tuple(other_ids))
                t_rows = cursor.fetchall()
                for tr in t_rows:
                    if tr['post_title'] not in titles_to_match:
                        titles_to_match.append(tr['post_title'])
    finally:
        # Keep connection open for the main query
        pass

    if not titles_to_match:
        conn.close()
        return {"registrations": []}

    # Build the OR conditions for titles (text-4)
    # Even though we have IDs, Forminator records only capture the title text.
    title_conditions = " OR ".join(["text_4 LIKE %s"] * len(titles_to_match))
    query_params = [f"%{t}%" for t in titles_to_match]

    sql = f"""
        SELECT 
          e.entry_id,
          e.form_id,
          e.date_created,
          MAX(CASE WHEN m.meta_key = 'name-1' THEN m.meta_value END) as name,
          MAX(CASE WHEN m.meta_key = 'email-1' THEN m.meta_value END) as email,
          MAX(CASE WHEN m.meta_key = 'phone-1' THEN m.meta_value END) as phone,
          MAX(CASE WHEN m.meta_key = 'radio-1' THEN m.meta_value END) as category,
          MAX(CASE WHEN m.meta_key = 'text-1' THEN m.meta_value END) as text_1,
          MAX(CASE WHEN m.meta_key = 'text-2' THEN m.meta_value END) as text_2,
          MAX(CASE WHEN m.meta_key = 'text-3' THEN m.meta_value END) as text_3,
          MAX(CASE WHEN m.meta_key = 'text-4' THEN m.meta_value END) as text_4,
          MAX(CASE WHEN m.meta_key = 'text-5' THEN m.meta_value END) as text_5,
          MAX(CASE WHEN m.meta_key = 'textarea-1' THEN m.meta_value END) as textarea_1
        FROM wp_frmt_form_entry e
        JOIN wp_frmt_form_entry_meta m ON e.entry_id = m.entry_id
        WHERE e.form_id IN (786, 798)
        GROUP BY e.entry_id
        HAVING {title_conditions}
        ORDER BY e.date_created DESC
    """

    try:
        cursor.execute(sql, tuple(query_params))
        rows = cursor.fetchall()
        
        entries = []
        for r in rows:
            form_id = r['form_id']
            lang = "Serbian" if form_id == 786 else "English"
            
            # Forminator name field can be a string (legacy EN) or serialized dict (SR and new EN)
            name_val = _deserialize_php(r['name'])
            first_name = ""
            last_name = ""
            full_name = ""
            
            if isinstance(name_val, dict):
                first_name = name_val.get('first-name', '').strip()
                last_name = name_val.get('last-name', '').strip()
                full_name = f"{first_name} {last_name}".strip()
            else:
                full_name = str(name_val).strip() if name_val else ""
                if " " in full_name:
                    parts = full_name.split(" ", 1)
                    first_name = parts[0]
                    last_name = parts[1]
                else:
                    first_name = full_name
                    last_name = ""
            
            # Affiliation/School mapping is a bit fluid across form versions
            # Usually text-1 is school, text-2/text-3 is university/faculty
            school = _deserialize_php(r['text_1'])
            affiliation = _deserialize_php(r['text_2']) or _deserialize_php(r['text_3'])
            notes = _deserialize_php(r['textarea_1'])
            category = _deserialize_php(r['category'])
            workshop = _deserialize_php(r['text_4'])

            entry = {
                "entry_id": r['entry_id'],
                "date": r['date_created'].isoformat() if hasattr(r['date_created'], 'isoformat') else str(r['date_created']),
                "full_name": full_name,
                "first_name": first_name,
                "last_name": last_name,
                "email": r['email'],
                "phone": r['phone'],
                "category": category,
                "affiliation": affiliation,
                "school": school,
                "workshop": workshop,
                "language": lang,
                "notes": notes
            }
            entries.append(entry)

        if not include_details:
            # We return a simplified list but include key identifying info
            return {
                "count": len(entries), 
                "entries": [
                    {
                        "entry_id": e['entry_id'], 
                        "date": e['date'],
                        "first_name": e['first_name'],
                        "last_name": e['last_name'],
                        "email": e['email'],
                        "phone": e['phone'],
                        "language": e['language']
                    } for e in entries
                ]
            }
            
        return {"count": len(entries), "entries": entries}
    finally:
        conn.close()

# Generic MySQL Functions (Moved from mysql_mcp.py)

def get_forms():
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT ID as id, post_title as name FROM wp_posts WHERE post_type = 'forminator_forms'")
        forms = cursor.fetchall()
        return forms
    finally:
        conn.close()

def get_entries(form_id):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        entries_table = "wp_frmt_form_entry"
        meta_table = "wp_frmt_form_entry_meta"
        query = f"""
            SELECT e.entry_id, e.date_created, m.meta_key, m.meta_value
            FROM {entries_table} e
            JOIN {meta_table} m ON e.entry_id = m.entry_id
            WHERE e.form_id = %s
            ORDER BY e.date_created ASC
        """
        cursor.execute(query, (form_id,))
        rows = cursor.fetchall()
        
        entries = {}
        for row in rows:
            eid = row['entry_id']
            if eid not in entries:
                entries[eid] = {
                    'entry_id': eid, 
                    'date_created': row['date_created'].isoformat() if hasattr(row['date_created'], 'isoformat') else str(row['date_created'])
                }
            
            key = row['meta_key']
            value = row['meta_value']
            deserialized = _deserialize_php(value)
            if isinstance(deserialized, dict):
                for k, v in deserialized.items():
                    entries[eid][f"{key}_{k}"] = v
            else:
                entries[eid][key] = deserialized
            
        return list(entries.values())
    finally:
        conn.close()

def get_entry_by_id(entry_id):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        entries_table = "wp_frmt_form_entry"
        meta_table = "wp_frmt_form_entry_meta"
        query = f"""
            SELECT e.entry_id, e.date_created, e.form_id, m.meta_key, m.meta_value
            FROM {entries_table} e
            JOIN {meta_table} m ON e.entry_id = m.entry_id
            WHERE e.entry_id = %s
        """
        cursor.execute(query, (entry_id,))
        rows = cursor.fetchall()
        
        if not rows:
            return None
            
        entry = {
            'entry_id': entry_id, 
            'date_created': rows[0]['date_created'].isoformat() if hasattr(rows[0]['date_created'], 'isoformat') else str(rows[0]['date_created']),
            'form_id': rows[0]['form_id']
        }
        
        for row in rows:
            key = row['meta_key']
            value = row['meta_value']
            deserialized = _deserialize_php(value)
            if isinstance(deserialized, dict):
                for k, v in deserialized.items():
                    entry[f"{key}_{k}"] = v
            else:
                entry[key] = deserialized
                
        return entry
    finally:
        conn.close()

async def workshop_read_instructors(params: Dict[str, Any]):
    """Read instructor interest forms from Google Sheets."""
    spreadsheet_id = params.get('spreadsheet_id', '1wSV_ilS06z2eeiIB9_aIbGSBuCNTkqqgiwetKIX-0co')
    range_name = params.get('range_name') # No default, we detect if empty
    
    creds = get_google_credentials()
    if not creds:
        return {
            "error": "Google Sheets not authorized",
            "auth_url": f"{MCP_BASE_URL.rstrip('/')}/workshops/google/login" if MCP_BASE_URL else "/workshops/google/login"
        }

    try:
        service = build('sheets', 'v4', credentials=creds)
        
        # If no range_name is provided, find the first sheet title
        if not range_name:
            spreadsheet = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
            sheets = spreadsheet.get('sheets', [])
            if not sheets:
                return {"error": "No sheets found in spreadsheet."}
            first_sheet_title = sheets[0].get('properties', {}).get('title')
            range_name = f"{first_sheet_title}!A:Z"
            logger.info(f"Detected sheet name: {first_sheet_title} for spreadsheet {spreadsheet_id}")

        result = service.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=range_name).execute()
        values = result.get('values', [])
        
        if not values:
            return {"instructors": [], "message": f"No data found in {range_name}."}
            
        headers = values[0]
        rows = values[1:]
        
        instructors = []
        for row in rows:
            instructor = {}
            for i, header in enumerate(headers):
                instructor[header] = row[i] if i < len(row) else ""
            instructors.append(instructor)
            
        return {"instructors": instructors, "count": len(instructors)}
    except Exception as e:
        error_msg = str(e)
        if "404" in error_msg:
            error_msg = f"Spreadsheet not found (404). Check if ID {spreadsheet_id} is correct and shared with the authorized account."
        logger.error(f"Error reading instructors from Google Sheets: {e}")
        return {"error": error_msg}

FEEDBACK_HEADER_MAP = {
    'Timestamp': 'timestamp',
    'Datum radionice kojoj ste prisustvovali': 'workshop_date',
    'Kojoj radionici ste prisustvovali?': 'workshop_name',
    'Kako ste saznali za ovu radionicu?': 'source',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Ciljevi radionice su jasno objašnjeni.]': 'score_goals',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Predavač je bio stručan i zanimljiv.]': 'score_instructor',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Sadržaj radionice je bio na odgovarajućem nivou težine za mene.]': 'score_difficulty',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Praktične aktivnosti su bile zanimljive i edukativne.]': 'score_activities',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Trajanje radionice je bilo odgovarajuće.]': 'score_duration',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Materijali i oprema su dobro funkcionisali.]': 'score_equipment',
    'Iskustvo sa radionicom: ocenite u kojoj meri se slažete sa sledećim izjavama. [Nakon radionice imam bolje razumevanje ove teme.]': 'score_learning',
    'Koliko ste zadovoljni radionicom u kojoj ste učestvovali? [Koliko ste ukupno zadovoljni radionicom?]': 'score_overall',
    'Kolika je verovatnoća da biste preporučili ovu radionicu? [Kolika je verovatnoća da biste preporučili ovu radionicu prijatelju ili kolegi?]': 'score_recommend',
    'Kolika je verovatnoća da biste preporučili ovu radionicu? [Kolika je verovatnoća da biste ponovo prisustvovali nekoj budućoj Backyard Brains radionici?]': 'score_return',
    'Šta vam se najviše svidelo na radionici?': 'liked_most',
    'Šta biste poboljšali ili promenili?': 'improvement',
    'Koje biste teme voleli da vidite na budućim radionicama?': 'future_topics'
}

LIKERT_SCALE_MAP = {
    # Agreement scale
    "Uopšte se ne slažem": 1,
    "Ne slažem se": 2,
    "Niti se slažem, niti se ne slažem": 3,
    "Slažem se": 4,
    "U potpunosti se slažem": 5,
    # Likelihood scale
    "Nema šanse": 1,
    "Male šanse": 2,
    "Nisam siguran": 3,
    "Veoma verovatno": 4,
    "Sigurno": 5,
    # Satisfaction scale
    "Uopšte nisam zadovoljan/na": 1,
    "Nisam zadovoljan/na": 2,
    "Niti sam zadovoljan/na, niti sam nezadovoljan/na": 3,
    "Zadovoljan/na sam": 4,
    "U potpunosti sam zadovoljan/na": 5,
    "Uopšte nisam zadovoljan": 1,
    "Nisam zadovoljan": 2,
    "Zadovoljan": 4,
    "U potpunosti zadovoljan": 5,
    "Uopšte nisam zadovoljna": 1,
    "Nisam zadovoljna": 2,
    "Zadovoljna": 4,
    "U potpunosti zadovoljna": 5
}

async def workshop_read_feedback(params: Dict[str, Any]):
    """Read feedback from Google Sheets (linked to Google Forms)."""
    spreadsheet_id = params.get('spreadsheet_id', '1wSV_ilS06z2eeiIB9_aIbGSBuCNTkqqgiwetKIX-0co')
    
    # Safety Override: AI clients sometimes persist stale IDs. 
    # Swap the known incorrect ID for the correct one if provided.
    BAD_ID = "1Eg6Dbh4yYPvvFrnM08TK39qrjxMQbNjxp-upUGhjHmY"
    if spreadsheet_id == BAD_ID:
        logger.warning(f"Intercepted incorrect spreadsheet ID {BAD_ID}. Overriding with correct ID.")
        spreadsheet_id = "1wSV_ilS06z2eeiIB9_aIbGSBuCNTkqqgiwetKIX-0co"
    range_name = params.get('range_name') # No default, we detect if empty
    workshop_id = params.get('workshop_id')
    workshop_title = params.get('workshop_title')
    normalize = params.get('normalize', True)
    
    if not spreadsheet_id:
        return {"error": "spreadsheet_id is required for feedback retrieval."}
    
    creds = get_google_credentials()
    if not creds:
        return {
            "error": "Google Sheets not authorized",
            "auth_url": f"{MCP_BASE_URL.rstrip('/')}/workshops/google/login" if MCP_BASE_URL else "/workshops/google/login"
        }

    try:
        service = build('sheets', 'v4', credentials=creds)
        
        # If no range_name is provided, find the first sheet title
        if not range_name:
            spreadsheet = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
            sheets = spreadsheet.get('sheets', [])
            if not sheets:
                return {"error": "No sheets found in spreadsheet."}
            first_sheet_title = sheets[0].get('properties', {}).get('title')
            range_name = f"{first_sheet_title}!A:Z"
            logger.info(f"Detected sheet name: {first_sheet_title} for spreadsheet {spreadsheet_id}")

        result = service.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=range_name).execute()
        values = result.get('values', [])
        
        if not values:
            return {"feedback": [], "message": f"No data found in {range_name}."}
            
        headers = values[0]
        rows = values[1:]
        
        # Try to find the workshop title if only ID is provided
        if workshop_id and not workshop_title:
            conn = get_db_connection()
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT post_title FROM wp_posts WHERE ID = %s", (workshop_id,))
                res = cursor.fetchone()
                if res:
                    workshop_title = res['post_title']
            finally:
                conn.close()

        feedback_list = []
        for row in rows:
            entry = {}
            for i, header in enumerate(headers):
                val = row[i] if i < len(row) else ""
                
                if normalize:
                    # Map header name
                    clean_key = FEEDBACK_HEADER_MAP.get(header, header)
                    
                    # Try to convert value if it's a known Likert scale string
                    if isinstance(val, str) and val.strip() in LIKERT_SCALE_MAP:
                        val = LIKERT_SCALE_MAP[val.strip()]
                    
                    entry[clean_key] = val
                else:
                    entry[header] = val
            
            # Simple matching: if workshop_title is provided, look for it in the row
            if workshop_title:
                match = False
                # If normalized, workshop_name key is preferred for matching
                w_name = entry.get('workshop_name', "") if normalize else entry.get('Kojoj radionici ste prisustvovali?', "")
                if w_name and str(workshop_title).lower() in str(w_name).lower():
                    match = True
                else:
                    # Fallback to general substring match across all values
                    for val in entry.values():
                        if str(workshop_title).lower() in str(val).lower():
                            match = True
                            break
                if not match:
                    continue
                    
            feedback_list.append(entry)
            
        return {"feedback": feedback_list, "count": len(feedback_list)}
    except Exception as e:
        error_msg = str(e)
        if "404" in error_msg:
            error_msg = f"Spreadsheet not found (404). Check if ID {spreadsheet_id} is correct and shared with the authorized account."
        logger.error(f"Error reading feedback from Google Sheets: {e}")
        return {"error": error_msg}

async def workshop_google_account(params: Dict[str, Any]):
    """Get the email address of the currently authorized Google account."""
    creds = get_google_credentials()
    if not creds:
        return {"error": "Google Sheets not authorized"}
    
    try:
        # Check tokens directly for an 'account' field if it exists
        token_data = load_google_tokens()
        if token_data and 'account' in token_data:
            return {"email": token_data['account']}
            
        # Try to use the userinfo endpoint
        service = build('oauthinfo', 'v2', credentials=creds)
        # Note: This might fail if the 'email' scope wasn't requested.
        # But we can at least return the client_id or other metadata.
        return {
            "client_id": creds.client_id,
            "scopes": creds.scopes,
            "expired": creds.expired,
            "message": "To get the exact email, the 'email' scope must be authorized. However, you can see the client_id and scopes above."
        }
    except Exception as e:
        return {"error": str(e), "client_id": getattr(creds, 'client_id', 'unknown')}

@router.get("/google/login")
async def workshop_google_auth_login(request: Request):
    """Initiate Google OAuth flow."""
    redirect_uri = f"{MCP_BASE_URL.rstrip('/')}/workshops/google/callback" if MCP_BASE_URL else f"{str(request.base_url).rstrip('/')}/workshops/google/callback"
    flow = Flow.from_client_secrets_file(
        GOOGLE_CREDENTIALS_FILE,
        scopes=GOOGLE_SCOPES,
        redirect_uri=redirect_uri
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='false',
        prompt='consent'
    )
    # Store state in session or just use it in the callback
    # For simplicity, we'll just redirect
    from fastapi.responses import RedirectResponse
    return RedirectResponse(authorization_url)

@router.get("/google/callback")
async def workshop_google_auth_callback(request: Request, code: str, state: str = None):
    """Handle Google OAuth callback."""
    redirect_uri = f"{MCP_BASE_URL.rstrip('/')}/workshops/google/callback" if MCP_BASE_URL else f"{str(request.base_url).rstrip('/')}/workshops/google/callback"
    flow = Flow.from_client_secrets_file(
        GOOGLE_CREDENTIALS_FILE,
        scopes=GOOGLE_SCOPES,
        redirect_uri=redirect_uri
    )
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        # Google sometimes returns extra scopes (e.g. if previously authorized) 
        # which can trigger a Warning/Exception in oauthlib. 
        # If we still got the credentials, we can proceed.
        logger.warning(f"Google OAuth token exchange warning/error: {e}")
        if not flow.credentials:
            raise HTTPException(status_code=500, detail=f"Failed to fetch token: {str(e)}")
            
    creds = flow.credentials
    save_google_tokens(json.loads(creds.to_json()))
    
    return Response(content="<h1>Google Sheets Authorized!</h1><p>You can now close this window and return to the chat.</p>", media_type="text/html")

def execute_query(query: str, params: tuple = None):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        if query.strip().lower().startswith("select"):
            return cursor.fetchall()
        else:
            conn.commit()
            return {"affected_rows": cursor.rowcount}
    finally:
        conn.close()

# Tool Handler

def _list_workshop_tools():
    return {
        "tools": [
            # Workshop tools
            {
                "name": "workshop_list",
                "description": "List all workshops with optional filtering by status, language, and date",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string", "enum": ["publish", "draft", "all"], "default": "publish" },
                        "language": { "type": "string", "enum": ["sr", "en", "all"], "default": "all" },
                        "upcoming_only": { "type": "boolean", "default": False },
                        "start_date_after": { "type": "string", "description": "Filter workshops starting on or after this date (YYYY-MM-DD)" },
                        "start_date_before": { "type": "string", "description": "Filter workshops starting on or before this date (YYYY-MM-DD)" },
                        "limit": { "type": "number", "default": 50 },
                        "include_meta": { "type": "boolean", "default": False }
                    }
                }
            },
            {
                "name": "workshop_get",
                "description": "Get full details for specific workshop(s) by ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ids": { "type": "array", "items": { "type": "number" } },
                        "include_gallery": { "type": "boolean", "default": True },
                        "include_registrations": { "type": "boolean", "default": False },
                        "include_feedback": { "type": "boolean", "default": False },
                        "feedback_spreadsheet_rs": { "type": "string", "description": "Spreadsheet ID for Serbian feedback" },
                        "feedback_spreadsheet_en": { "type": "string", "description": "Spreadsheet ID for English feedback" }
                    },
                    "required": ["ids"]
                }
            },
            {
                "name": "workshop_create",
                "description": "Create a new workshop",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" },
                        "start_date": { "type": "string", "description": "ISO format: 2025-12-11 18:00:00" },
                        "end_date": { "type": "string", "description": "ISO format: 2025-12-11 20:00:00" },
                        "location": { "type": "string" },
                        "about_left": { "type": "string", "description": "HTML content" },
                        "about_right": { "type": "string", "description": "HTML content" },
                        "post_content": { "type": "string", "description": "Main workshop content" },
                        "post_excerpt": { "type": "string", "description": "Short excerpt/summary" },
                        "sign_up_link": { "type": "string" },
                        "is_full": { "type": "boolean", "default": False },
                        "status": { "type": "string", "enum": ["publish", "draft"], "default": "draft" },
                        "featured_image_id": { "type": "number" },
                        "gallery_ids": { "type": "array", "items": { "type": "number" } },
                        "audience": { "type": "array", "items": { "type": "string" }, "description": "Audience badges. Available: 'For Everyone', 'High Schoolers', 'Mladi profesionalci', 'Srednjoškolci', 'Studenti', 'Students', 'Young Professionals', 'Za sve'" },
                        "language": { "type": "string", "enum": ["en", "sr"], "description": "Explicit language code" },
                        "language_badge": { "type": "string", "description": "Language badge. Available: 'English', 'Serbian', 'Srpski', 'Engleski'" },
                        "translation_of": { "type": "number", "description": "ID of the existing workshop to link as a translation" }
                    },
                    "required": ["title", "language", "start_date", "description", "location", "about_left", "about_right"]
                }
            },
            {
                "name": "workshop_update",
                "description": "Update an existing workshop",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "number" },
                        "title": { "type": "string" },
                        "start_date": { "type": "string" },
                        "end_date": { "type": "string" },
                        "location": { "type": "string" },
                        "about_left": { "type": "string" },
                        "about_right": { "type": "string" },
                        "post_content": { "type": "string" },
                        "post_excerpt": { "type": "string" },
                        "sign_up_link": { "type": "string" },
                        "is_full": { "type": "boolean" },
                        "status": { "type": "string", "enum": ["publish", "draft"] },
                        "featured_image_id": { "type": "number" },
                        "gallery_ids": { "type": "array", "items": { "type": "number" } },
                        "audience": { "type": "array", "items": { "type": "string" }, "description": "Audience badges. Available: 'For Everyone', 'High Schoolers', 'Mladi profesionalci', 'Srednjoškolci', 'Studenti', 'Students', 'Young Professionals', 'Za sve'" },
                        "language_badge": { "type": "string", "description": "Language badge. Available: 'English', 'Serbian', 'Srpski', 'Engleski'" },
                        "translation_of": { "type": "number", "description": "ID of the existing workshop to link as a translation" }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "workshop_find_pair",
                "description": "Find the language pair (Serbian/English) for a workshop",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "number" }
                    },
                    "required": ["id"]
                }
            },
            {
                "name": "workshop_registrations",
                "description": "Get registration entries for a workshop",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workshop_id": { "type": "number" },
                        "workshop_title": { "type": "string" },
                        "include_details": { "type": "boolean", "default": False }
                    }
                }
            },
            {
                "name": "workshop_google_account",
                "description": "Get the email address of the currently authorized Google account",
                "inputSchema": {"type": "object", "properties": {}}
            },
            # Generic SQL tool
            {
                "name": "workshop_sql_query",
                "description": "Execute a generic MySQL query (Requires admin role)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "SQL query to execute"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "workshop_get_forms",
                "description": "List Forminator forms from wp_posts",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "workshop_get_entries",
                "description": "Fetch entries for a specific Forminator form",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "form_id": {"type": "integer", "description": "ID of the form"}
                    },
                    "required": ["form_id"]
                }
            },
            {
                "name": "workshop_get_entry_by_id",
                "description": "Fetch a single Forminator entry by ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "description": "ID of the entry"}
                    },
                    "required": ["entry_id"]
                }
            },
            # Polylang specific tools
            {
                "name": "polylang_get_languages",
                "description": "Get discovered Polylang languages and their term_taxonomy_ids",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "workshop_set_language",
                "description": "Assign a language to a workshop post (Strict DB-side assignment)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "post_id": {"type": "integer"},
                        "language": {"type": "string", "enum": ["en", "sr"]}
                    },
                    "required": ["post_id", "language"]
                }
            },
            {
                "name": "workshop_link_translations",
                "description": "Link multiple workshops as translations (With merge logic)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "post_ids_by_lang": {
                            "type": "object",
                            "description": "Mapping of lang code to post ID, e.g., {'en': 123, 'sr': 456}"
                        }
                    },
                    "required": ["post_ids_by_lang"]
                }
            },
            {
                "name": "workshop_flush_cache",
                "description": "Flush MCP Polylang discovery cache (and document WP cache flush)",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "workshop_read_instructors",
                "description": "Read instructor interest forms from Google Sheets (OAuth required)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "spreadsheet_id": { "type": "string", "description": "Google Spreadsheet ID", "default": "1wSV_ilS06z2eeiIB9_aIbGSBuCNTkqqgiwetKIX-0co" },
                        "range_name": { "type": "string", "description": "Range to read (e.g. 'Sheet1!A:Z'). If omitted, the first sheet tab will be detected automatically." }
                    }
                }
            },
            {
                "name": "workshop_read_feedback",
                "description": "Read attendee feedback from Google Sheets (OAuth required)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "spreadsheet_id": { "type": "string", "description": "Google Spreadsheet ID", "default": "1wSV_ilS06z2eeiIB9_aIbGSBuCNTkqqgiwetKIX-0co" },
                        "range_name": { "type": "string", "description": "Range to read (e.g. 'Sheet1!A:Z'). If omitted, the first sheet tab will be detected automatically." },
                        "workshop_id": { "type": "number", "description": "Filter by workshop ID" },
                        "workshop_title": { "type": "string", "description": "Filter by workshop title (substring match)" },
                        "normalize": { "type": "boolean", "description": "Map headers to English keys and convert scores to numbers", "default": True }
                    },
                    "required": ["spreadsheet_id"]
                }
            },
            {
                "name": "workshop_google_account",
                "description": "Get identity of the currently authorized Google account",
                "inputSchema": {"type": "object", "properties": {}}
            }
        ]
    }

async def handle_workshop_tool_call(name: str, args: Dict, auth_payload: Dict):
    # Check permissions based on tool name
    is_write = name in ["workshop_create", "workshop_update", "workshop_set_language", "workshop_link_translations"]
    is_admin = name in ["workshop_sql_query", "workshop_flush_cache"]
    
    if is_admin:
        if not check_permissions(auth_payload, ["mcp:admin:workshops"]):
            return {"isError": True, "content": [{"type": "text", "text": "Insufficient permissions. Admin role required for workshop_sql_query."}]}
    elif is_write:
        if not check_permissions(auth_payload, ["mcp:write:workshops", "mcp:admin:workshops"]):
            return {"isError": True, "content": [{"type": "text", "text": "Insufficient permissions. Write access required."}]}
    else:
        # Read operations
        if not check_permissions(auth_payload, ["mcp:read:workshops", "mcp:write:workshops", "mcp:admin:workshops"]):
             return {"isError": True, "content": [{"type": "text", "text": "Insufficient permissions. Read access required."}]}

    try:
        # Workshop tools
        if name == "workshop_list":
            result = await workshop_list(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_get":
            result = await workshop_get(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_create":
            result = await workshop_create(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_update":
            result = await workshop_update(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_find_pair":
            result = await workshop_find_pair(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_registrations":
            result = await workshop_registrations(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
            
        # Generic tool
        elif name == "workshop_sql_query":
            query = args.get("query")
            result = execute_query(query)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_get_forms":
            result = get_forms()
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_get_entries":
            form_id = args.get("form_id")
            result = get_entries(form_id)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_get_entry_by_id":
            entry_id = args.get("entry_id")
            result = get_entry_by_id(entry_id)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
            
        # Polylang tools
        elif name == "polylang_get_languages":
            client = get_polylang_client()
            if not client:
                return {"isError": True, "content": [{"type": "text", "text": "Polylang client not initialized"}]}
            return {"content": [{"type": "text", "text": safe_dumps(client.get_languages())}]}
            
        elif name == "workshop_set_language":
            post_id = args.get("post_id")
            lang = args.get("language")
            conn = get_db_connection()
            try:
                cursor = conn.cursor(dictionary=True)
                pll_set_post_language(cursor, post_id, lang)
                conn.commit()
                return {"content": [{"type": "text", "text": f"Successfully set language '{lang}' for post {post_id}"}]}
            finally:
                conn.close()
                
        elif name == "workshop_link_translations":
            post_ids_by_lang = args.get("post_ids_by_lang")
            conn = get_db_connection()
            try:
                cursor = conn.cursor(dictionary=True)
                pll_save_translations(cursor, post_ids_by_lang)
                conn.commit()
                return {"content": [{"type": "text", "text": f"Successfully linked translations: {post_ids_by_lang}"}]}
            finally:
                conn.close()
                
        elif name == "workshop_flush_cache":
            client = get_polylang_client()
            if not client:
                return {"isError": True, "content": [{"type": "text", "text": "Polylang client not initialized"}]}
            client.refresh_languages()
            return {"content": [{"type": "text", "text": "Polylang discovery cache flushed. Note: You may also need to flush WordPress object cache (e.g., via WP Rocket or Redis) for UI changes to reflect immediately."}]}
            
        # Google Sheets tools
        elif name == "workshop_read_instructors":
            result = await workshop_read_instructors(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_read_feedback":
            result = await workshop_read_feedback(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "workshop_google_account":
            result = await workshop_google_account(args)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
            
        else:
            return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}
    except Exception as e:
        logger.error(f"Error executing Workshop tool {name}: {e}")
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error executing {name}: {str(e)}"}],
            "metadata": {"reason": "exception", "exceptionType": type(e).__name__}
        }

@router.post("/mcp")
async def handle_workshop_mcp(request: Request, payload: Dict = Depends(require_workshops_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    def _initialize_payload():
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
                "prompts": {"listChanged": False},
                "logging": {},
            },
            "serverInfo": {"name": "workshops-mcp", "version": "1.0.0"},
        }

    if method == "initialize":
        return _rpc_result(rpc_id, _initialize_payload())
    elif method == "ping":
        return _rpc_result(rpc_id, {"status": "ok"})
    elif method == "tools/list":
        return _rpc_result(rpc_id, _list_workshop_tools())
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        result = await handle_workshop_tool_call(name, args, payload)
        return _rpc_result(rpc_id, result)
    else:
        return _rpc_error(rpc_id, -32601, f"Method {method} not found")

@router.post("/")
@router.post("")
async def workshops_index_post(request: Request, payload: Dict = Depends(require_workshops_auth)):
    """Handle MCP JSON-RPC requests at the root /workshops/ endpoint."""
    return await handle_workshop_mcp(request, payload)

@router.get("/")
@router.get("")
def workshop_index():
    return {"service": "workshops-mcp", "status": "ok"}
