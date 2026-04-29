# alienvault_otx.py — Integración con AlienVault OTX API
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ALIENVAULT_OTX_KEY, REQUEST_TIMEOUT

# URLs de la API por tipo de IoC
API_URLS = {
    "ip":     "https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
    "domain": "https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general",
    "url":    "https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general",
    "hash":   "https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
    "md5":    "https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
    "sha1":   "https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
    "sha256": "https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
}

# URLs públicas por tipo de IoC
WEB_URLS = {
    "ip":     "https://otx.alienvault.com/indicator/ip/{ioc}",
    "domain": "https://otx.alienvault.com/indicator/domain/{ioc}",
    "url":    "https://otx.alienvault.com/indicator/url/{ioc}",
    "hash":   "https://otx.alienvault.com/indicator/file/{ioc}",
    "md5":    "https://otx.alienvault.com/indicator/file/{ioc}",
    "sha1":   "https://otx.alienvault.com/indicator/file/{ioc}",
    "sha256": "https://otx.alienvault.com/indicator/file/{ioc}",
}

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta AlienVault OTX para cualquier tipo de IoC.
    Retorna veredicto, detalle y URL pública.
    """
    api_url = API_URLS.get(ioc_type, "").format(ioc=ioc)
    web_url = WEB_URLS.get(ioc_type, "").format(ioc=ioc)

    if not api_url:
        return {
            "verdict": "unknown",
            "detail":  f"Tipo de IoC no soportado: {ioc_type}",
            "web_url": ""
        }

    try:
        headers = {}
        if ALIENVAULT_OTX_KEY:
            headers["X-OTX-API-KEY"] = ALIENVAULT_OTX_KEY

        resp = requests.get(
            api_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data        = resp.json()
            pulse_info  = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            reputation  = data.get("reputation", 0)

            # Lógica de veredicto
            if pulse_count > 3:
                verdict = "malicious"
            elif pulse_count > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"{pulse_count} pulsos · Reputación: {reputation}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": web_url
            }

        elif resp.status_code == 404:
            return {
                "verdict": "clean",
                "detail":  "IoC no encontrado en OTX",
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
            "detail":  "Timeout — AlienVault OTX no respondió en 10s",
            "web_url": web_url
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": web_url
        }