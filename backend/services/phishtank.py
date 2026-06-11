# phishtank.py — Integración con PhishTank API (pública, sin API key)
import requests
import urllib.parse
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import REQUEST_TIMEOUT

WEB_URL = "https://www.phishtank.com/phish_search.php?valid=y&active=y&Search=Search&url={ioc}"

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta PhishTank para URLs y dominios.
    Retorna veredicto, detalle y URL pública.
    """
    if ioc_type not in ["url", "domain"]:
        return {
            "verdict": "unknown",
            "detail":  "PhishTank solo soporta URLs y dominios",
            "web_url": ""
        }

    try:
        # PhishTank requiere URL codificada
        encoded_url = urllib.parse.quote(ioc, safe="")

        data_payload = {
            "url":    encoded_url,
            "format": "json",
            "app_key": ""
        }

        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=data_payload,
            headers={"User-Agent": "ioc-enricher/1.0"},
            timeout=REQUEST_TIMEOUT
        )

        if resp.status_code == 200:
            data        = resp.json()
            results     = data.get("results", {})
            in_database = results.get("in_database", False)
            verified    = results.get("verified", False)
            valid       = results.get("valid", False)

            # Lógica de veredicto
            if in_database and valid:
                verdict = "malicious"
            elif in_database:
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"En base de datos: {in_database} · Verificado: {verified} · Válido: {valid}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": WEB_URL.format(ioc=urllib.parse.quote(ioc, safe=""))
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
            "detail":  "Timeout — PhishTank no respondió en 10s",
            "web_url": WEB_URL.format(ioc=ioc)
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": WEB_URL.format(ioc=ioc)
        }