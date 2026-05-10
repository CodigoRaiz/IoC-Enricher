# threatbook.py — Integración con ThreatBook API
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import THREATBOOK_API_KEY, REQUEST_TIMEOUT

# URLs de la API por tipo de IoC
API_URLS = {
    "ip":     "https://api.threatbook.io/v2/ip/query",
    "domain": "https://api.threatbook.io/v2/domain/query",
    "url":    "https://api.threatbook.io/v2/url/query",
    "hash":   "https://api.threatbook.io/v2/file/query",
    "md5":    "https://api.threatbook.io/v2/file/query",
    "sha1":   "https://api.threatbook.io/v2/file/query",
    "sha256": "https://api.threatbook.io/v2/file/query",
}

# URLs públicas por tipo de IoC
WEB_URLS = {
    "ip":     "https://i.threatbook.io/research/{ioc}",
    "domain": "https://i.threatbook.io/research/{ioc}",
    "url":    "https://i.threatbook.io/research/{ioc}",
    "hash":   "https://i.threatbook.io/research/{ioc}",
    "md5":    "https://i.threatbook.io/research/{ioc}",
    "sha1":   "https://i.threatbook.io/research/{ioc}",
    "sha256": "https://i.threatbook.io/research/{ioc}",
}

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta ThreatBook para IPs, dominios y hashes.
    Retorna veredicto, detalle y URL pública.
    """
    web_url = WEB_URLS.get(ioc_type, "").format(ioc=ioc)

    if not THREATBOOK_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de ThreatBook no configurada",
            "web_url": web_url
        }

    api_url = API_URLS.get(ioc_type, "")
    if not api_url:
        return {
            "verdict": "unknown",
            "detail":  f"Tipo de IoC no soportado: {ioc_type}",
            "web_url": ""
        }

    try:
        params = {
            "apikey":   THREATBOOK_API_KEY,
            "resource": ioc,
        }
        resp = requests.post(
            api_url,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data      = resp.json()
            resp_code = data.get("response_code", -1)

            if resp_code != 0:
                return {
                    "verdict": "unknown",
                    "detail":  f"Error ThreatBook: {data.get('message', 'Sin mensaje')}",
                    "web_url": web_url
                }

            ioc_data  = data.get("data", {})
            judgments = ioc_data.get("judgments", [])

            judgment_str = ", ".join(judgments) if judgments else "Sin juicio"
            if any(j in ["Malicious", "C2", "Botnet", "Phishing"] for j in judgments):
                verdict = "malicious"
            elif judgments:
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"Juicio: {judgment_str}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": web_url
            }

        elif resp.status_code == 401:
            return {
                "verdict": "unknown",
                "detail":  "API key de ThreatBook inválida",
                "web_url": web_url
            }
        else:
            return {
                "verdict": "unknown",
                "detail":  f"Error HTTP {resp.status_code} — {resp.text[:100]}",
                "web_url": web_url
            }

    except requests.Timeout:
        return {
            "verdict": "unknown",
            "detail":  "Timeout — ThreatBook no respondió en 10s",
            "web_url": web_url
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": web_url
        }