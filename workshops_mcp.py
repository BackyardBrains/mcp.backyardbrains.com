import os
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from datetime import datetime
import phpserialize
import mysql.connector
import requests
import time

from utils import MCP_PROTOCOL_VERSION, _rpc_result, _rpc_error, logger, safe_dumps
from auth import require_workshops_auth, check_permissions

# Environment variables
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')
WP_URL = os.getenv('WP_URL')

router = APIRouter()

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
        ORDER BY start_date DESC
        LIMIT %s
    """

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query_params = status_val + (limit,)
        cursor.execute(sql, query_params)
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

    if wid and not title_match:
        conn = get_db_connection()
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT post_title FROM wp_posts WHERE ID = %s", (wid,))
            res = cursor.fetchone()
            if res:
                title_match = res['post_title']
        finally:
            conn.close()

    if not title_match:
        return {"registrations": []}

    sql = """
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
        HAVING text_4 LIKE %s
        ORDER BY e.date_created DESC
    """

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (f"%{title_match}%",))
        rows = cursor.fetchall()
        
        entries = []
        for r in rows:
            form_id = r['form_id']
            lang = "Serbian" if form_id == 786 else "English"
            
            # Forminator name field can be a string (EN) or serialized dict (SR)
            name_val = _deserialize_php(r['name'])
            if isinstance(name_val, dict):
                full_name = f"{name_val.get('first-name', '')} {name_val.get('last-name', '')}".strip()
            else:
                full_name = str(name_val) if name_val else ""
            
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
            # We still return a simplified list but keep the count
            return {"count": len(entries), "entries": [{"entry_id": e['entry_id'], "date": e['date']} for e in entries]}
            
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
                        "include_registrations": { "type": "boolean", "default": False }
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
