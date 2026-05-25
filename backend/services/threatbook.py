# threatbook.py — Integración con ThreatBook CTI API
import requests
import sys
import os
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import THREATBOOK_API_KEY, REQUEST_TIMEOUT

# URLs públicas por tipo de IoC (solo IP y Domain tienen URL pública)
WEB_URLS = {
    "ip":     "https://i.threatbook.io/research/{ioc}",
    "domain": "https://i.threatbook.io/research/{ioc}",
}

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta ThreatBook CTI.
    - IPs: consulta API gratuita de IPs
    - Dominios: consulta API gratuita de dominios vía endpoint /v1/community/domain
    - URLs sin http://: se tratan como dominio
    - URLs con http:// o https://: no soportadas (retorna unknown)
    - Hashes (md5, sha1, sha256): no soportados
    """

    # ── Hashes: no soportados ──
    if ioc_type in ["hash", "md5", "sha1", "sha256"]:
        return {
            "verdict": "unknown",
            "detail":  "ThreatBook no soporta hashes",
            "web_url": ""
        }

    # ── URLs: verificar si trae o no http ──
    if ioc_type == "url":
        if ioc.startswith("http://") or ioc.startswith("https://"):
            # URL completa → no soportada, pero mostrar web_url con el dominio extraído
            parsed = urlparse(ioc)
            domain = parsed.netloc or parsed.path
            return {
                "verdict": "unknown",
                "detail":  "ThreatBook no soporta URLs completas",
                "web_url": WEB_URLS.get("domain", "").format(ioc=domain)
            }
        else:
            # No tiene http:// → es un dominio desnudo, tratarlo como dominio
            ioc_type = "domain"

    web_url = WEB_URLS.get(ioc_type, "").format(ioc=ioc)

    if not THREATBOOK_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de ThreatBook no configurada",
            "web_url": web_url
        }

    # Solo IPs tienen API gratuita
    if ioc_type == "domain":
        return {
            "verdict": "unknown",
            "detail":  "Consulta manual disponible — haz clic en 'Ver en web'",
            "web_url": web_url
        }
    elif ioc_type == "ip":
        api_url = "https://api.threatbook.io/v1/community/ip"
    else:
        return {
            "verdict": "unknown",
            "detail":  "ThreatBook solo soporta IPs y Dominios",
            "web_url": ""
        }

    try:
        params = {
            "apikey":   THREATBOOK_API_KEY,
            "resource": ioc
        }
        resp = requests.post(
            api_url,
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