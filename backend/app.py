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

        # Recolectar web_urls de todos los resultados para tomar screenshots
        web_urls = {}
        for result in results:
            for source_name, source_data in result.get("sources", {}).items():
                url = source_data.get("web_url", "")
                if url and source_name not in web_urls:
                    web_urls[source_name] = url

        # Tomar screenshots en paralelo y convertir a base64
        screenshots = {}
        if web_urls:
            import logging
            with ThreadPoolExecutor(max_workers=min(len(web_urls), 8)) as executor:
                future_map = {}
                for source_name, url in web_urls.items():
                    future = executor.submit(
                        lambda sn=source_name, u=url: _run_screenshot(u, sn)
                    )
                    future_map[future] = source_name

                for future in as_completed(future_map):
                    source_name = future_map[future]
                    try:
                        png_bytes = future.result()
                        screenshots[source_name] = base64.b64encode(png_bytes).decode("utf-8")
                    except Exception as e:
                        logging.error(f"Screenshot falló para {source_name}: {e}")
                        screenshots[source_name] = None

        return jsonify({"results": results, "screenshots": screenshots})

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
@app.route("/generate-report", methods=["POST"])
def generate_report():
    """
    Endpoint POST — genera un reporte .docx con screenshots (ya tomadas desde /analyze).
    Recibe JSON: { "ioc", "ioc_type", "results", "ai_summary", "screenshots": {...} }
    Las screenshots vienen como dict de base64 strings; se decodifican a bytes.
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

    # Decodificar screenshots de base64 a bytes
    screenshots: dict = {}
    for source_name, b64_str in screenshots_b64.items():
        if b64_str:
            try:
                screenshots[source_name] = base64.b64decode(b64_str)
            except Exception:
                screenshots[source_name] = None
        else:
            screenshots[source_name] = None

    # Generar el documento .docx
    docx_bytes = generate_word_report(ioc, ioc_type, results, ai_summary, screenshots)

    # Nombre del archivo con fecha
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"IOC_Report_{ioc}_{date_str}.docx"

    return send_file(
        io.BytesIO(docx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )


def _run_screenshot(url: str, source_name: str, source_data: dict = None) -> bytes:
    """Ejecuta take_screenshot (async) de forma síncrona dentro de un hilo."""
    import asyncio
    return asyncio.run(take_screenshot(url, source_name, source_data))


if __name__ == "__main__":
    print("🚀 IOC Enricher — Backend iniciando...")
    print("📡 Servidor corriendo en http://localhost:5001")
    print("🌐 Abre frontend/index.html en tu navegador")
    app.run(debug=True, host="0.0.0.0", port=5001)
