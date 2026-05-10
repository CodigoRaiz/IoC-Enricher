# metadefender.py — Integración con MetaDefender Cloud API v4
import requests
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import METADEFENDER_API_KEY, REQUEST_TIMEOUT

WEB_URL = "https://metadefender.com/results/hash/{ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta MetaDefender Cloud para hashes de archivos.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type not in ["hash", "md5", "sha1", "sha256"]:
        return {
            "verdict": "unknown",
            "detail":  "MetaDefender solo soporta hashes de archivos",
            "web_url": ""
        }

    if not METADEFENDER_API_KEY:
        return {
            "verdict": "unknown",
            "detail":  "API key de MetaDefender no configurada",
            "web_url": WEB_URL.format(ioc=ioc)
        }

    try:
        headers = {"apikey": METADEFENDER_API_KEY}
        resp = requests.get(
            f"https://api.metadefender.com/v4/hash/{ioc}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data         = resp.json()
            scan_results = data.get("scan_results", {})
            result_a     = scan_results.get("scan_all_result_a", "N/A")
            detected     = scan_results.get("total_detected_avs", 0)
            total        = scan_results.get("total_avs", 0)
            file_info    = data.get("file_info", {})
            file_type    = file_info.get("file_type_description", "N/A")

            # Lógica de veredicto
            if result_a == "Infected":
                verdict = "malicious"
            elif result_a == "Suspicious":
                verdict = "suspicious"
            elif result_a == "No threat detected":
                verdict = "clean"
            else:
                verdict = "unknown"

            detail = f"{detected}/{total} motores · {file_type} · Resultado: {result_a}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": WEB_URL.format(ioc=ioc)
            }

        elif resp.status_code == 404:
            return {
                "verdict": "unknown",
                "detail":  "Hash no encontrado en MetaDefender",
                "web_url": WEB_URL.format(ioc=ioc)
            }
        elif resp.status_code == 403:
            return {
                "verdict": "unknown",
                "detail":  "API key de MetaDefender inválida o sin permisos",
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
            "detail":  "Timeout — MetaDefender no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }