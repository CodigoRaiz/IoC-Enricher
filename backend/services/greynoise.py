# greynoise.py — Integración con GreyNoise API
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GREYNOISE_API_KEY, REQUEST_TIMEOUT

WEB_URL = "https://viz.greynoise.io/ip/{ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta GreyNoise para IPs.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type != "ip":
        return {
            "verdict": "unknown",
            "detail":  "GreyNoise solo soporta direcciones IP",
            "web_url": ""
        }

    if not GREYNOISE_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de GreyNoise no configurada",
            "web_url": WEB_URL.format(ioc=ioc)
        }

    try:
        headers = {
            "key":    GREYNOISE_API_KEY,
            "Accept": "application/json"
        }
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ioc}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data           = resp.json()
            classification = data.get("classification", "unknown")
            noise          = data.get("noise", False)
            name           = data.get("name", "N/A")
            riot           = data.get("riot", False)

            # Lógica de veredicto
            if classification == "malicious":
                verdict = "malicious"
            elif noise:
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"Clasificación: {classification} · Org: {name} · Noise: {noise} · RIOT: {riot}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": WEB_URL.format(ioc=ioc)
            }

        elif resp.status_code == 404:
            return {
                "verdict": "clean",
                "detail":  "IP no encontrada en GreyNoise (sin actividad registrada)",
                "web_url": WEB_URL.format(ioc=ioc)
            }
        elif resp.status_code == 429:
            return {
                "verdict": "unknown",
                "detail":  "Límite semanal de API alcanzado (50 req/semana)",
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
            "detail":  "Timeout — GreyNoise no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }