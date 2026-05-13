# urlhaus.py — Integración con URLhaus API (pública, sin API key)
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import REQUEST_TIMEOUT, MALWAREBAZAAR_API_KEY

WEB_URL = "https://urlhaus.abuse.ch/browse.php?search={ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta URLhaus para URLs y dominios.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type not in ["url", "domain"]:
        return {
            "verdict": "unknown",
            "detail":  "URLhaus solo soporta URLs y dominios",
            "web_url": ""
        }

    try:
        headers = {}
        if MALWAREBAZAAR_API_KEY:
            headers["Auth-Key"] = MALWAREBAZAAR_API_KEY

        # URLhaus: usar endpoint de URL si tiene http://, sino usar host
        if ioc.startswith("http://") or ioc.startswith("https://"):
            data_payload = {"url": ioc}
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        else:
            data_payload = {"host": ioc}
            api_url = "https://urlhaus-api.abuse.ch/v1/host/"

        resp = requests.post(
            api_url,
            headers=headers,
            data=data_payload,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data          = resp.json()
            query_status  = data.get("query_status", "no_results")
            urls_count = int(data.get("url_count", data.get("urls_count", 0)))
            threat        = data.get("threat", "N/A")
            tags          = data.get("tags", [])
            tags_str      = ", ".join(tags) if tags else "Sin tags"

            # Lógica de veredicto
            threat = data.get("threat", "")
            if query_status == "ismalware" or urls_count > 0 or threat not in ["", "N/A", None]:
                verdict = "malicious"
            elif query_status == "suspicious":
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"{query_status} · Malware: {threat} · Tags: {tags_str} · URLs: {urls_count}"

            return {
                "verdict": verdict,
                "detail":  detail,
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
            "detail":  "Timeout — URLhaus no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }