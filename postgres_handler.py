import json
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

from utils import hash_file

DSN = "dbname=fukhara user=postgres password=fukhara host=localhost port=5432"
_pool = SimpleConnectionPool(minconn=1, maxconn=10, dsn=DSN)

APK_ANALYSIS_SCHEMA = """
CREATE TABLE IF NOT EXISTS apk_analysis (
    sha256       TEXT PRIMARY KEY,
    uploaded_at  TIMESTAMPTZ NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    tool_results JSONB NOT NULL DEFAULT '{}'::jsonb
);
"""

APK_ANALYSIS_GIN_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_apk_analysis_tool_results_gin
    ON apk_analysis USING GIN (tool_results);
"""

FUZZY_HASHES_SCHEMA =
"""
CREATE TABLE IF NOT EXISTS fuzzy_hashes (
    id          SERIAL PRIMARY KEY,
    sha256      TEXT NOT NULL,
    tool        TEXT NOT NULL,
    filename    TEXT NOT NULL,
    fuzzy_hash  TEXT NOT NULL,
    UNIQUE (sha256, tool, filename, fuzzy_hash)
);
"""

FUZZY_HASHES_GIN_SHCEMA = 
"""
CREATE INDEX IF NOT EXISTS idx_fuzzy_hashes_sha256_tool
    ON fuzzy_hashes (sha256, tool);
"""

def _get_conn():
    return _pool.getconn()

def _put_conn(conn):
    _pool.putconn(conn)

def init_schema():
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(APK_ANALYSIS_SCHEMA)
            cur.execute(APK_ANALYSIS_GIN_SCHEMA)
            cur.execute(FUZZY_HASHES_SCHEMA)
            cur.execute(FUZZY_HASHES_GIN_SHCEMA)
        conn.commit()
    finally:
        _put_conn(conn)


def create_apk_analysis(path):
    conn = _get_conn()
    try:
        sha256 = hash_file(path)
        uploaded_at = str(datetime.now())
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO apk_analysis (sha256, uploaded_at, status)
                VALUES (%s, %s, 'pending')
                ON CONFLICT (sha256) DO NOTHING
             sha256   """,
                (sha256, uploaded_at),
            )
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        _put_conn(conn)


def add_tool_analysis(sha256, tool_name, result):
    """Merge {tool_name: result} into the tool_results JSONB column,
    equivalent to Mongo's $set: {tool_name: result} on the document."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE apk_analysis
                SET tool_results = tool_results || %s::jsonb
                WHERE sha256 = %s
                """,
                (json.dumps({tool_name: result}), sha256),
            )
        conn.commit()
    finally:
        _put_conn(conn)


def list_apk_analyses():
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT sha256 FROM apk_analysis")
            return [row[0] for row in cur.fetchall()]
    finally:
        _put_conn(conn)


def get_tool_analysis(sha256, tool_name):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tool_results -> %s FROM apk_analysis WHERE sha256 = %s",
                (tool_name, sha256),
            )
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        _put_conn(conn)


def get_analysis_status(sha256):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM apk_analysis WHERE sha256 = %s", (sha256,)
            )
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        _put_conn(conn)


def get_analysis_upload_timestamp(sha256):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT uploaded_at FROM apk_analysis WHERE sha256 = %s", (sha256,)
            )
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        _put_conn(conn)


def set_analysis_status(sha256, status):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE apk_analysis SET status = %s WHERE sha256 = %s",
                (status, sha256),
            )
        conn.commit()
    finally:
        _put_conn(conn)


def find_by_tool_result(tool_name, contains):
    """Bonus helper enabled by the GIN index: find sha256s where
    tool_results->tool_name contains the given dict, e.g.
    find_by_tool_result('mobsf', {'verdict': 'malware'})."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT sha256 FROM apk_analysis
                WHERE tool_results -> %s @> %s::jsonb
                """,
                (tool_name, json.dumps(contains)),
            )
            return [row[0] for row in cur.fetchall()]
    finally:
        _put_conn(conn)


def add_fuzzy_hash(sha256, tool, filename, fuzzy_hash):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fuzzy_hashes (sha256, tool, filename, fuzzy_hash)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (sha256, tool, filename, fuzzy_hash) DO NOTHING
                """,
                (sha256, tool, filename, fuzzy_hash),
            )
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        _put_conn(conn)


def get_fuzzy_hash_analysis(sha256, tool_name):
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM fuzzy_hashes WHERE sha256 = %s AND tool = %s",
                (sha256, tool_name),
            )
            return cur.fetchall()
    finally:
        _put_conn(conn)
