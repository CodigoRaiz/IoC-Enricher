# cache.py — Lógica de caché SQLite con TTL de 24 horas
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import CACHE_TTL_HOURS

# Ruta de la base de datos
DB_PATH = Path(__file__).parent.parent / "data" / "feeds.db"

def get_connection():
    """Retorna una conexión a la base de datos SQLite."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Crea la tabla de caché si no existe."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_key TEXT NOT NULL UNIQUE,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                sources TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cache_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hits INTEGER DEFAULT 0,
                date TEXT NOT NULL UNIQUE
            )
        """)
        conn.commit()

def make_cache_key(ioc: str, ioc_type: str, sources: list) -> str:
    """Genera la clave única de caché para un IoC."""
    sources_str = ":".join(sorted(sources))
    return f"{ioc}:{ioc_type}:{sources_str}"

def get_cached(ioc: str, ioc_type: str, sources: list) -> dict | None:
    """
    Busca un resultado en caché.
    Retorna el resultado si existe y no ha expirado, None si no.
    """
    key = make_cache_key(ioc, ioc_type, sources)
    expiry = datetime.now() - timedelta(hours=CACHE_TTL_HOURS)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT result_json, created_at FROM ioc_cache WHERE cache_key = ? AND created_at > ?",
            (key, expiry.isoformat())
        ).fetchone()

        if row:
            # Registrar hit en estadísticas
            today = datetime.now().strftime("%Y-%m-%d")
            conn.execute("""
                INSERT INTO cache_stats (date, hits) VALUES (?, 1)
                ON CONFLICT(date) DO UPDATE SET hits = hits + 1
            """, (today,))
            conn.commit()
            return json.loads(row["result_json"])

    return None

def save_to_cache(ioc: str, ioc_type: str, sources: list, result: dict):
    """Guarda un resultado en caché."""
    key = make_cache_key(ioc, ioc_type, sources)
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO ioc_cache (cache_key, ioc, ioc_type, sources, result_json)
            VALUES (?, ?, ?, ?, ?)
        """, (key, ioc, ioc_type, ":".join(sorted(sources)), json.dumps(result)))
        conn.commit()

def get_today_hits() -> int:
    """Retorna el número de hits de caché del día de hoy."""
    today = datetime.now().strftime("%Y-%m-%d")
    with get_connection() as conn:
        row = conn.execute(
            "SELECT hits FROM cache_stats WHERE date = ?", (today,)
        ).fetchone()
        return row["hits"] if row else 0

def cleanup_expired():
    """Elimina entradas de caché expiradas."""
    expiry = datetime.now() - timedelta(hours=CACHE_TTL_HOURS)
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM ioc_cache WHERE created_at <= ?",
            (expiry.isoformat(),)
        )
        conn.commit()