# config.py — Carga y centraliza todas las variables de entorno
import os
from dotenv import load_dotenv

# Cargar variables desde .env
load_dotenv()

# ── Multi-propósito ──
VIRUSTOTAL_API_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
THREATBOOK_API_KEY       = os.getenv("THREATBOOK_API_KEY", "")
HYBRID_ANALYSIS_KEY      = os.getenv("HYBRID_ANALYSIS_KEY", "")

# ── Dominios / URLs ──
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

# ── IPs ──
ABUSEIPDB_API_KEY        = os.getenv("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY        = os.getenv("GREYNOISE_API_KEY", "")

# ── Hashes / Archivos ──
METADEFENDER_API_KEY     = os.getenv("METADEFENDER_API_KEY", "")

# ── Threat Intelligence ──
ALIENVAULT_OTX_KEY       = os.getenv("ALIENVAULT_OTX_KEY", "")
MISP_URL                 = os.getenv("MISP_URL", "")
MISP_API_KEY             = os.getenv("MISP_API_KEY", "")

# ── IA ──
GEMINI_API_KEY           = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY             = os.getenv("GROQ_API_KEY", "")

# ── Configuración general ──
CACHE_TTL_HOURS          = int(os.getenv("CACHE_TTL_HOURS", "24"))
MAX_IOCS_PER_REQUEST     = int(os.getenv("MAX_IOCS_PER_REQUEST", "10"))

# ── Timeout para todas las requests a APIs externas ──
REQUEST_TIMEOUT          = 10