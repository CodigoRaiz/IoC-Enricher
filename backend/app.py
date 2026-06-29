# app.py — Servidor principal Flask para IOC Enricher
import os
import sys
import time
import io
import base64
import atexit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from pathlib import Path

# Agregar el directorio backend al path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import MAX_IOCS_PER_REQUEST
from cache import init_db, get_cached, save_to_cache, get_today_hits, cleanup_expired
from utils.ioc_detector import detect_ioc_type, parse_ioc_list

# Importar todos los servicios
from services import (
    virustotal, abuseipdb, greynoise, alienvault_otx,
    threatbook, urlhaus, phishtank, google_safebrowsing,
    malwarebazaar, metadefender, hybrid_analysis, misp
)
from services.ai_summary import generate_summary
from services.screenshot_service import take_screenshot, close_browser
from services.report_generator import generate_word_report

app = Flask(__name__)
CORS(app)

# Registrar cierre limpio del navegador Playwright al detener el servidor
atexit.register(close_browser)

# Inicializar base de datos
init_db()

# Tiempo de inicio del servidor
START_TIME = datetime.now()

# Mapa de servicios disponibles
SERVICES = {
    "virustotal":         virustotal,
    "abuseipdb":          abuseipdb,
    "greynoise":          greynoise,
    "alienvault_otx":     alienvault_otx,
    "threatbook":         threatbook,
    "urlhaus":            urlhaus,
    "phishtank":          phishtank,
    "google_safebrowsing": google_safebrowsing,
    "malwarebazaar":      malwarebazaar,
    "metadefender":       metadefender,
    "hybrid_analysis":    hybrid_analysis,
    "misp":               misp,
}


def query_source(source_name: str, ioc: str, ioc_type: str) -> tuple:
    """Consulta una fuente de inteligencia y retorna el resultado."""
    service = SERVICES.get(source_name)
    if not service:
        return source_name, {
            "verdict": "unknown",
            "detail":  f"Servicio '{source_name}' no encontrado",
            "web_url": ""
        }
    try:
        result = service.query(ioc, ioc_type)
        return source_name, result
    except Exception as e:
        return source_name, {
            "verdict": "unknown",
            "detail":  f"Error inesperado: {str(e)}",
            "web_url": ""
        }


def enrich_ioc(ioc: str, ioc_type: str, sources: list, ai_provider: str) -> dict:
    """
    Enriquece un IoC consultando todas las fuentes seleccionadas en paralelo.
    Usa caché si el resultado existe y no ha expirado.
    """
    # Verificar caché
    cached = get_cached(ioc, ioc_type, sources)
    if cached:
        cached["cached"] = True
        return cached

    # Consultar fuentes en paralelo
    source_results = {}
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {
            executor.submit(query_source, source, ioc, ioc_type): source
            for source in sources
        }
        for future in as_completed(futures):
            source_name, result = future.result()
            source_results[source_name] = result

    # Generar resumen con IA
    ai_summary = generate_summary(ioc, ioc_type, source_results, ai_provider)

    # Construir resultado final
    result = {
        "ioc":        ioc,
        "type":       ioc_type,
        "sources":    source_results,
        "ai_summary": ai_summary,
        "cached":     False
    }

    # Guardar en caché
    save_to_cache(ioc, ioc_type, sources, result)

    return result


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Endpoint principal — recibe IoCs y retorna resultados enriquecidos.
    """
    try:
        data        = request.get_json()
        iocs_raw    = data.get("iocs", [])
        sources     = data.get("sources", ["virustotal"])
        ioc_type_req = data.get("ioc_type", "auto")
        ai_provider = data.get("ai_provider", "gemini")

        # Parsear IoCs
        if isinstance(iocs_raw, str):
            ioc_list = parse_ioc_list(iocs_raw)
        else:
            ioc_list = [i.strip() for i in iocs_raw if i.strip()]

        if not ioc_list:
            return jsonify({"error": "No se proporcionaron IoCs válidos"}), 400

        if len(ioc_list) > MAX_IOCS_PER_REQUEST:
            return jsonify({
                "error": f"Máximo {MAX_IOCS_PER_REQUEST} IoCs por solicitud"
            }), 400

        if not sources:
            return jsonify({"error": "Selecciona al menos una fuente"}), 400

        # Limpiar caché expirada en cada request
        cleanup_expired()

        # Procesar cada IoC
        results = []
        for ioc in ioc_list:
            # Detectar tipo
            # "auto" → detectar siempre; "domain" → desambiguar entre dominio y URL
            if ioc_type_req in ("auto", "domain"):
                ioc_type = detect_ioc_type(ioc)
            else:
                ioc_type = ioc_type_req

            result = enrich_ioc(ioc, ioc_type, sources, ai_provider)
            results.append(result)

        return jsonify({"results": results})

    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health():
    """Retorna estado del servidor y estadísticas de caché."""
    uptime = datetime.now() - START_TIME
    return jsonify({
        "status":       "ok",
        "uptime":       str(uptime).split(".")[0],
        "cache_hits_today": get_today_hits(),
        "version":      "1.0.0",
        "timestamp":    datetime.now().isoformat()
    })

@app.route("/clear-cache", methods=["POST"])
def clear_cache():
    """Limpia completamente la tabla de caché en la base de datos."""
    import sqlite3
    from pathlib import Path
    DB_PATH = Path(__file__).parent.parent / "data" / "feeds.db"
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM ioc_cache")
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Caché limpiado"})


@app.route("/")
def frontend():
    """Sirve el frontend desde Flask."""
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
    return send_from_directory(frontend_path, "index.html")


# ── CONFIG ENDPOINTS ──

def _mask_key(value: str) -> str:
    """Enmascara un API key mostrando solo los últimos 4 caracteres."""
    if not value:
        return ""
    if len(value) <= 4:
        return "••••" + value
    return "••••••" + value[-4:]


def _get_env_path() -> Path:
    """Retorna la ruta al archivo .env en la raíz del proyecto."""
    return Path(__file__).parent.parent / ".env"


@app.route("/config", methods=["GET"])
def get_config():
    """
    Lee el archivo .env y retorna JSON con las keys enmascaradas (solo últimos 4 chars visibles)
    y la configuración general (CACHE_TTL_HOURS, MAX_IOCS_PER_REQUEST).
    """
    env_path = _get_env_path()
    config_data = {
        # API Keys (enmascaradas)
        "VIRUSTOTAL_API_KEY": "",
        "THREATBOOK_API_KEY": "",
        "HYBRID_ANALYSIS_KEY": "",
        "GOOGLE_SAFE_BROWSING_KEY": "",
        "ABUSEIPDB_API_KEY": "",
        "GREYNOISE_API_KEY": "",
        "METADEFENDER_API_KEY": "",
        "MALWAREBAZAAR_API_KEY": "",
        "ALIENVAULT_OTX_KEY": "",
        "MISP_API_KEY": "",
        "GEMINI_API_KEY": "",
        "GROQ_API_KEY": "",
        "MISP_URL": "",
        # Config general
        "CACHE_TTL_HOURS": "24",
        "MAX_IOCS_PER_REQUEST": "10",
    }

    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key in config_data:
                    # Enmascarar si es API key o similar (contiene KEY, _KEY, _URL)
                    if key.endswith("_KEY") or key == "MISP_URL":
                        config_data[key] = _mask_key(value)
                    else:
                        config_data[key] = value

    return jsonify(config_data)


@app.route("/config", methods=["POST"])
def update_config():
    """
    Recibe JSON con los valores nuevos, actualiza solo los campos recibidos
    y escribe los cambios en el archivo .env.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Cuerpo JSON requerido"}), 400

    env_path = _get_env_path()

    # Claves conocidas para la configuración
    known_keys = {
        "VIRUSTOTAL_API_KEY", "THREATBOOK_API_KEY", "HYBRID_ANALYSIS_KEY",
        "GOOGLE_SAFE_BROWSING_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY",
        "METADEFENDER_API_KEY", "MALWAREBAZAAR_API_KEY", "ALIENVAULT_OTX_KEY",
        "MISP_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "MISP_URL",
        "CACHE_TTL_HOURS", "MAX_IOCS_PER_REQUEST",
    }

    # Leer .env actual
    lines = []
    updated_keys = set()

    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    # Actualizar líneas existentes o agregar nuevas
    new_lines = []
    found_keys = set()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue

        key, _, _ = stripped.partition("=")
        key = key.strip()

        if key in known_keys and key in data:
            # Actualizar valor (sin comillas alrededor)
            new_value = str(data[key]).strip()
            new_lines.append(f"{key}={new_value}\n")
            found_keys.add(key)
            updated_keys.add(key)
        else:
            new_lines.append(line)

    # Agregar claves nuevas que no existían en el archivo
    for key in known_keys:
        if key in data and key not in found_keys:
            new_value = str(data[key]).strip()
            new_lines.append(f"{key}={new_value}\n")
            updated_keys.add(key)

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    return jsonify({"status": "ok", "updated": list(updated_keys)})


@app.route("/sessions/status", methods=["GET"])
def sessions_status():
    """
    Verifica si existen los archivos de sesión guardados en backend/data/sessions/.
    Retorna:
    {
      "abuseipdb": true/false,
      "greynoise": true/false,
      "threatbook": true/false
    }
    """
    sessions_dir = Path(__file__).parent / "data" / "sessions"

    status = {
        "abuseipdb":  (sessions_dir / "abuseipdb.json").exists(),
        "greynoise":  (sessions_dir / "greynoise.json").exists(),
        "threatbook": (sessions_dir / "threatbook.json").exists(),
    }

    return jsonify(status)


@app.route("/generate-report", methods=["POST"])
def generate_report():
    """
    Endpoint POST — genera un reporte .docx con screenshots (ya tomadas desde /analyze).
    Ahora soporta múltiples IoCs:
    Recibe JSON:
    {
      "ioc": "20.127.218.58, 20.168.5.42",
      "ioc_type": "ip",
      "results": { "20.127.218.58": {"virustotal": {...}, ...}, "20.168.5.42": ... },
      "ai_summary": "Resumen combinado...",
      "screenshots": { "20.127.218.58": {"virustotal": "base64...", ...}, ... }
    }
    Las screenshots vienen como dict anidado {ioc: {source: base64}}.
    Se decodifican a bytes (agrupadas por IoC) y se pasan a generate_word_report.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Cuerpo JSON requerido"}), 400

    ioc = data.get("ioc", "")
    ioc_type = data.get("ioc_type", "")
    results = data.get("results", {})
    ai_summary = data.get("ai_summary", "")
    screenshots_b64 = data.get("screenshots", {})

    if not results:
        return jsonify({"error": "results no puede estar vacío"}), 400

    # screenshots_b64 es un dict anidado: {ioc: {source: base64}}
    # Decodificar screenshots de base64 a bytes, agrupadas por IoC
    screenshots: dict = {}
    for ioc_key, ioc_sources_b64 in screenshots_b64.items():
        decoded_sources = {}
        for source_name, b64_str in ioc_sources_b64.items():
            if b64_str:
                try:
                    decoded_sources[source_name] = base64.b64decode(b64_str)
                except Exception:
                    decoded_sources[source_name] = None
            else:
                decoded_sources[source_name] = None
        screenshots[ioc_key] = decoded_sources

    # Generar el documento .docx (results ya viene como dict anidado {ioc: {fuente: datos}})
    docx_bytes = generate_word_report(ioc, ioc_type, results, ai_summary, screenshots)

    # Nombre del archivo con fecha
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ioc = ioc.replace(", ", "_").replace(" ", "_")[:50]
    filename = f"IOC_Report_{safe_ioc}_{date_str}.docx"

    return send_file(
        io.BytesIO(docx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )


@app.route("/capture-screenshots", methods=["POST"])
def capture_screenshots():
    """
    Endpoint POST — toma capturas de pantalla para un IoC específico.
    Recibe JSON: { "ioc": "...", "web_urls": {"virustotal": "url", ...} }
    Retorna: { "ioc": "...", "screenshots": {"virustotal": "base64...", ...} }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Cuerpo JSON requerido"}), 400

        ioc = data.get("ioc", "")
        web_urls = data.get("web_urls", {})

        if not ioc:
            return jsonify({"error": "ioc es requerido"}), 400
        if not web_urls:
            return jsonify({"error": "web_urls no puede estar vacío"}), 400

        import logging

        # Tomar screenshots con concurrencia limitada a 2
        screenshots = {}
        with ThreadPoolExecutor(max_workers=min(len(web_urls), 2)) as executor:
            future_map = {}
            for source_name, url in web_urls.items():
                future = executor.submit(
                    lambda sn=source_name, u=url: (sn, _run_screenshot(u, sn))
                )
                future_map[future] = source_name

            for future in as_completed(future_map):
                source_name = future_map[future]
                try:
                    _, png_bytes = future.result()
                    if png_bytes is not None:
                        screenshots[source_name] = base64.b64encode(png_bytes).decode("utf-8")
                    # Si png_bytes es None, no incluimos la fuente en el resultado
                except Exception as e:
                    logging.error(f"Screenshot falló para {source_name} ({ioc}): {e}")
                    # No incluimos fuentes con error en el resultado

        return jsonify({"ioc": ioc, "screenshots": screenshots})

    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500


def _run_screenshot(url: str, source_name: str, source_data: dict = None) -> bytes:
    """Ejecuta take_screenshot (async) de forma síncrona dentro de un hilo."""
    import asyncio
    return asyncio.run(take_screenshot(url, source_name, source_data))


if __name__ == "__main__":
    print("🚀 IOC Enricher — Backend iniciando...")
    print("📡 Servidor corriendo en http://localhost:5001")
    print("🌐 Abre frontend/index.html en tu navegador")
    app.run(debug=True, host="0.0.0.0", port=5001)