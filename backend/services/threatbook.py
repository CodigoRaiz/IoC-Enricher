# threatbook.py — Integración con ThreatBook CTI API
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import THREATBOOK_API_KEY, REQUEST_TIMEOUT

# URLs públicas por tipo de IoC
WEB_URLS = {
    "ip":     "https://i.threatbook.io/research/{ioc}",
    "domain": "https://i.threatbook.io/research/{ioc}",
    "url":    "",
    "hash":   "",
    "md5":    "",
    "sha1":   "",
    "sha256": "",
}

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta ThreatBook CTI.
    - IPs: usa la API gratuita (50 req/día)
    - Otros tipos: solo botón Ver en web (requiere plan Premium)
    """
    web_url = WEB_URLS.get(ioc_type, "").format(ioc=ioc)

    # Solo IPs usan la API gratuita
    if ioc_type == "ip":
        pass  # continúa con la API
    elif ioc_type == "domain":
        return {
            "verdict": "unknown",
            "detail":  "Consulta manual disponible — haz clic en 'Ver en web'",
            "web_url": web_url
        }
    else:
        return {
            "verdict": "unknown",
            "detail":  "ThreatBook solo soporta IPs y Dominios en el plan gratuito",
            "web_url": ""
        }

    # Si es URL, extraer el dominio para buscar en ThreatBook
    if ioc_type == "url":
        from urllib.parse import urlparse
        parsed = urlparse(ioc)
        ioc = parsed.netloc or ioc
        web_url = WEB_URLS.get("domain", "").format(ioc=ioc)

    if not THREATBOOK_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de ThreatBook no configurada",
            "web_url": web_url
        }

    try:
        params = {
            "apikey":   THREATBOOK_API_KEY,
            "resource": ioc
        }
        resp = requests.post(
            "https://api.threatbook.io/v1/community/ip",
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data      = resp.json()
            msg = data.get("msg", "")
            if msg != "Success":
                return {
                    "verdict": "unknown",
                    "detail":  f"Error ThreatBook: {msg}",
                    "web_url": web_url
                }

            ioc_data  = data.get("data", {})
            summary   = ioc_data.get("summary", {})
            basic     = ioc_data.get("basic", {})
            judgments = summary.get("judgments", [])
            country   = basic.get("location", {}).get("country", "N/A")

            judgment_str = ", ".join(judgments) if judgments else "Sin juicio"

            if any(j in ["Malicious", "C2", "Botnet", "Phishing", "Spam"] for j in judgments):
                verdict = "malicious"
            elif judgments:
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"Juicio: {judgment_str} · País: {country}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": web_url
            }

        elif resp.status_code == 401:
            return {
                "verdict": "unknown",
                "detail":  "API key de ThreatBook inválida o sin permisos",
                "web_url": web_url
            }
        else:
            return {
                "verdict": "unknown",
                "detail":  f"Error HTTP {resp.status_code}",
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