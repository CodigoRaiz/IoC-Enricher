# google_safebrowsing.py — Integración con Google Safe Browsing API v4
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GOOGLE_SAFE_BROWSING_KEY, REQUEST_TIMEOUT

WEB_URL = "https://transparencyreport.google.com/safe-browsing/search?url={ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta Google Safe Browsing para URLs y dominios.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type not in ["url", "domain"]:
        return {
            "verdict": "unknown",
            "detail":  "Google Safe Browsing solo soporta URLs y dominios",
            "web_url": ""
        }

    if not GOOGLE_SAFE_BROWSING_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de Google Safe Browsing no configurada",
            "web_url": WEB_URL.format(ioc=ioc)
        }

    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"

        # Asegurar que el IoC tenga esquema HTTP para la consulta
        check_url = ioc if ioc.startswith("http") else f"http://{ioc}"

        body = {
            "client": {
                "clientId":      "ioc-enricher",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes":      [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": check_url}]
            }
        }

        resp = requests.post(
            api_url,
            json=body,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data    = resp.json()
            matches = data.get("matches", [])

            if matches:
                verdict     = "malicious"
                threat_type = matches[0].get("threatType", "N/A")
                platform    = matches[0].get("platformType", "N/A")
                detail      = f"Tipo de amenaza: {threat_type} · Plataforma: {platform}"
            else:
                verdict = "clean"
                detail  = "No encontrado en Google Safe Browsing"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": WEB_URL.format(ioc=ioc)
            }

        elif resp.status_code == 400:
            return {
                "verdict": "unknown",
                "detail":  "Solicitud inválida — verifica el formato de la URL",
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
            "detail":  "Timeout — Google Safe Browsing no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }