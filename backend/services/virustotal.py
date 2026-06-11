# virustotal.py — Integración con VirusTotal API v3
import requests
import base64
import sys
import os
import urllib.parse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import VIRUSTOTAL_API_KEY, REQUEST_TIMEOUT

# URLs de la API por tipo de IoC
API_URLS = {
    "ip":     "https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
    "domain": "https://www.virustotal.com/api/v3/domains/{ioc}",
    "hash":   "https://www.virustotal.com/api/v3/files/{ioc}",
    "md5":    "https://www.virustotal.com/api/v3/files/{ioc}",
    "sha1":   "https://www.virustotal.com/api/v3/files/{ioc}",
    "sha256": "https://www.virustotal.com/api/v3/files/{ioc}",
}

# URLs públicas por tipo de IoC
WEB_URLS = {
    "ip":     "https://www.virustotal.com/gui/ip-address/{ioc}",
    "domain": "https://www.virustotal.com/gui/domain/{ioc}",
    "url":    "https://www.virustotal.com/gui/url/{ioc}",
    "hash":   "https://www.virustotal.com/gui/file/{ioc}",
    "md5":    "https://www.virustotal.com/gui/file/{ioc}",
    "sha1":   "https://www.virustotal.com/gui/file/{ioc}",
    "sha256": "https://www.virustotal.com/gui/file/{ioc}",
}

def query(ioc: str, ioc_type: str) -> dict:
    """
    Consulta VirusTotal para cualquier tipo de IoC.
    Retorna veredicto, detalle y URL pública.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "verdict": "unknown",
            "detail": "API key de VirusTotal no configurada",
            "web_url": web_url
        }
    print(f"DEBUG virustotal: ioc_type={ioc_type}, ioc={ioc}")
    # Para URLs, extraer el dominio y consultar como dominio
    if ioc_type == "url":
        from urllib.parse import urlparse
        parsed  = urlparse(ioc)
        domain  = parsed.netloc or parsed.path
        api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        # VT requiere base64 URL-safe sin padding para la URL pública
        url_b64 = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        web_url = f"https://www.virustotal.com/gui/url/{url_b64}"
    else:
        api_url = API_URLS.get(ioc_type, "").format(ioc=ioc)
        web_url = WEB_URLS.get(ioc_type, "").format(ioc=ioc)

    if not api_url:
        return {
            "verdict": "unknown",
            "detail":  f"Tipo de IoC no soportado: {ioc_type}",
            "web_url": ""
        }

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(api_url, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 200:
            data       = resp.json().get("data", {}).get("attributes", {})
            stats      = data.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())

            # Lógica de veredicto
            if malicious > 3:
                verdict = "malicious"
            elif malicious > 0 or suspicious > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"

            # Información adicional según tipo
            extra = ""
            if ioc_type == "ip":
                country = data.get("country", "N/A")
                asn     = data.get("asn", "N/A")
                extra   = f" · País: {country} · ASN: {asn}"
            elif ioc_type in ["md5", "sha1", "sha256", "hash"]:
                name  = data.get("meaningful_name", "N/A")
                extra = f" · Nombre: {name}"

            detail = f"{malicious}/{total} motores{extra}"

            return {
                "verdict": verdict,
                "detail":  detail,
                "web_url": web_url
            }

        elif resp.status_code == 404:
            return {
                "verdict": "unknown",
                "detail":  "IoC no encontrado en VirusTotal",
                "web_url": web_url
            }
        elif resp.status_code == 429:
            return {
                "verdict": "unknown",
                "detail":  "Límite de API alcanzado (rate limit)",
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
            "detail":  "Timeout — VirusTotal no respondió en 10s",
            "web_url": web_url
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "detail":  f"Error: {str(e)}",
            "web_url": web_url
        }