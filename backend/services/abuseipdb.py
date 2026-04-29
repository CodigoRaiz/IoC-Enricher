# abuseipdb.py — Integración con AbuseIPDB API v2
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ABUSEIPDB_API_KEY, REQUEST_TIMEOUT

WEB_URL = "https://www.abuseipdb.com/check/{ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta AbuseIPDB para IPs.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type != "ip":
        return {
            "verdict": "unknown",
            "detail":  "AbuseIPDB solo soporta direcciones IP",
            "web_url": ""
        }

    if not ABUSEIPDB_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de AbuseIPDB no configurada",
            "web_url": WEB_URL.format(ioc=ioc)
        }

    try:
        headers = {
            "Key":    ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress":    ioc,
            "maxAgeInDays": 90,
            "verbose":      True
        }
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data  = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            total = data.get("totalReports", 0)
            country = data.get("countryCode", "N/A")
            isp   = data.get("isp", "N/A")

            # Lógica de veredicto
            if score >= 75:
                verdict = "malicious"
            elif score >= 25:
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"Score: {score}% · {total} reportes · {country} · {isp}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": WEB_URL.format(ioc=ioc)
            }

        elif resp.status_code == 429:
            return {
                "verdict": "unknown",
                "detail":  "Límite de API alcanzado (rate limit)",
                "web_url": WEB_URL.format(ioc=ioc)
            }
        else:
            return {
                "verdict": "unknown",
                "detail":  f"Error HTTP {resp.status_code}",
                "web_url": WEB_URL.format(ioc=ioc)
            }

    except requests.Timeout:
        return {
            "verdict": "unknown",
            "detail":  "Timeout — AbuseIPDB no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }