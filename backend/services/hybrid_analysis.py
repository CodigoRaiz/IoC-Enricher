# hybrid_analysis.py — Integración con Hybrid Analysis API v2
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import HYBRID_ANALYSIS_KEY, REQUEST_TIMEOUT

WEB_URL = "https://www.hybrid-analysis.com/sample/{ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta Hybrid Analysis para hashes de archivos.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type not in ["hash", "md5", "sha1", "sha256"]:
        return {
            "verdict": "unknown",
            "detail":  "Hybrid Analysis solo soporta hashes de archivos",
            "web_url": ""
        }

    if not HYBRID_ANALYSIS_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de Hybrid Analysis no configurada",
            "web_url": WEB_URL.format(ioc=ioc)
        }

    try:
        headers = {
            "api-key":    HYBRID_ANALYSIS_KEY,
            "User-Agent": "Falcon Sandbox",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        resp = requests.post(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            headers=headers,
            data={"hash": ioc},
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data = resp.json()

            if not data:
                return {
                    "verdict": "unknown",
                    "detail":  "Hash no encontrado en Hybrid Analysis",
                    "web_url": WEB_URL.format(ioc=ioc)
                }

            # Tomar el primer resultado
            item         = data[0] if isinstance(data, list) else data
            verdict_raw  = item.get("verdict", "unknown")
            threat_score = item.get("threat_score", "N/A")
            vx_family    = item.get("vx_family", "N/A")
            environment  = item.get("environment_description", "N/A")
            sha256       = item.get("sha256", ioc)

            # Lógica de veredicto
            if verdict_raw == "malicious":
                verdict = "malicious"
            elif verdict_raw == "suspicious":
                verdict = "suspicious"
            elif verdict_raw == "no specific threat":
                verdict = "clean"
            else:
                verdict = "unknown"

            detail = f"Threat score: {threat_score} · Familia: {vx_family} · Entorno: {environment}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": WEB_URL.format(ioc=sha256)
            }

        elif resp.status_code == 401:
            return {
                "verdict": "unknown",
                "detail":  "API key de Hybrid Analysis inválida",
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
            "detail":  "Timeout — Hybrid Analysis no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }