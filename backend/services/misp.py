# misp.py — Integración con MISP (self-hosted)
import requests
import sys
import os
import urllib3

# Deshabilitar advertencias de SSL para instancias MISP con certificado autofirmado
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MISP_URL, MISP_API_KEY, REQUEST_TIMEOUT

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta MISP para cualquier tipo de IoC.
    Retorna veredicto, detalle y URL pública.
    """
    web_url = f"{MISP_URL}/attributes/index" if MISP_URL else ""

    if not MISP_URL or not MISP_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "MISP no configurado (MISP_URL o MISP_API_KEY faltante)",
            "web_url": ""
        }

    try:
        headers = {
            "Authorization": MISP_API_KEY,
            "Accept":        "application/json",
            "Content-Type":  "application/json"
        }

        body = {
            "value":  ioc,
            "limit":  10,
            "page":   1
        }

        resp = requests.post(
            f"{MISP_URL.rstrip('/')}/attributes/restSearch",
            headers=headers,
            json=body,
            timeout=REQUEST_TIMEOUT,
            verify=False  # Para certificados autofirmados
        )

        if resp.status_code == 200:
            data    = resp.json()
            attrs   = data.get("response", {}).get("Attribute", [])
            matches = len(attrs)

            if matches > 0:
                # Extraer información de los atributos encontrados
                categories = list(set(a.get("category", "N/A") for a in attrs))
                types      = list(set(a.get("type", "N/A") for a in attrs))
                events     = list(set(a.get("event_id", "") for a in attrs))

                verdict = "malicious" if matches > 2 else "suspicious"
                detail  = f"{matches} coincidencias · Categorías: {', '.join(categories[:3])} · Eventos: {len(events)}"
            else:
                verdict = "clean"
                detail  = "Sin coincidencias en MISP"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": web_url
            }

        elif resp.status_code == 403:
            return {
                "verdict": "unknown",
                "detail":  "API key de MISP inválida o sin permisos",
                "web_url": web_url
            }
        elif resp.status_code == 404:
            return {
                "verdict": "clean",
                "detail":  "Sin coincidencias en MISP",
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
            "detail":  "Timeout — MISP no respondió en 10s",
            "web_url": web_url
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": web_url
        }