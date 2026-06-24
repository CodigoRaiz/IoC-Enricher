# IOC Enricher — Resumen Técnico

## Propósito y Contexto

Herramienta SOC diseñada para analistas de ciberseguridad que permite enriquecer Indicadores de Compromiso (IoCs) —como IPs, dominios, URLs y hashes— consultando múltiples fuentes de Threat Intelligence en paralelo. Genera un veredicto consolidado (malicioso/sospechoso/limpio/desconocido) y un resumen ejecutivo con IA para acelerar la toma de decisiones en incidentes. Adicionalmente, permite capturar screenshots de las fuentes consultadas y generar un reporte .docx profesional en formato SOC con logotipos, tabla de análisis, riesgos, recomendaciones y evidencia visual.

## Stack Tecnológico

| Componente | Tecnología |
|---|---|
| Backend | Python 3 + Flask + Flask-CORS |
| Frontend | HTML + CSS + JavaScript vanilla (SPA) |
| Caché | SQLite con TTL configurable |
| Concurrencia | `concurrent.futures.ThreadPoolExecutor` |
| IA | Google Gemini 2.0 Flash / Groq (Llama 3.3 70B) |
| APIs externas | 12 fuentes de Threat Intelligence vía REST |
| Screenshots | Playwright (Chromium headless + Edge con sesiones persistentes) |
| Reportes Word | python-docx + Pillow (PIL) |
| Assets | Logotipos Axity y Cortex XDR en `backend/assets/` |

---

## Arquitectura

### Diagrama de árbol

```
IOC Enricher/
├── .env                          # API keys y configuración
├── backend/
│   ├── app.py                    # Servidor Flask: /analyze, /health, /clear-cache,
│   │                             #   /capture-screenshots, /generate-report
│   ├── config.py                 # Carga de variables de entorno
│   ├── cache.py                  # Caché SQLite con expiración
│   ├── save_sessions.py          # Utilidad para guardar sesiones autenticadas en navegador
│   ├── assets/                   # Recursos gráficos (Axity_Logo.png, Cortex-logo.webp)
│   ├── data/
│   │   └── sessions/             # Sesiones guardadas para AbuseIPDB, GreyNoise, ThreatBook
│   ├── utils/
│   │   └── ioc_detector.py       # Detección regex del tipo de IoC
│   ├── services/
│   │   ├── virustotal.py         # VirusTotal API v3
│   │   ├── abuseipdb.py          # AbuseIPDB API v2
│   │   ├── greynoise.py          # GreyNoise API v3
│   │   ├── alienvault_otx.py     # AlienVault OTX API
│   │   ├── threatbook.py         # ThreatBook CTI API
│   │   ├── urlhaus.py            # URLhaus API (pública)
│   │   ├── phishtank.py          # PhishTank API (pública)
│   │   ├── google_safebrowsing.py# Google Safe Browsing API v4
│   │   ├── malwarebazaar.py      # MalwareBazaar API
│   │   ├── metadefender.py       # MetaDefender Cloud API v4
│   │   ├── hybrid_analysis.py    # Hybrid Analysis API v2
│   │   ├── misp.py               # MISP (self-hosted)
│   │   ├── ai_summary.py         # Resumen ejecutivo con IA
│   │   ├── screenshot_service.py # Captura de pantallas con Playwright
│   │   └── report_generator.py   # Generación de reportes .docx formato SOC
│   └── __init__.py
├── frontend/
│   └── index.html                # Interfaz de usuario SPA
└── data/
    └── feeds.db                  # Base de datos SQLite (caché)
```

### Flujo de datos

```
Usuario (navegador)
    │
    ▼
Frontend (index.html) ──POST /analyze───────► Flask (app.py)  ──► enrich_ioc()
    │                                                   │
    │                                         ┌─────────┴─────────┐
    │                                         ▼                   ▼
    │                                   ioc_detector.py      cache.py
    │                                   (detecta tipo)    (busca SQLite)
    │                                         │                   │
    │                                         └──────┬───────────┘
    │                                                ▼
    │                                     ThreadPoolExecutor
    │                                     (consulta paralela a 12 fuentes)
    │                                                │
    │                                                ▼
    │                                         ai_summary.py
    │                                     (Gemini o Groq)
    │                                                │
    │                                                ▼
    │                                         save_to_cache()
    │                                                │
    │                                                ▼
    │                                 JSON → Frontend → Render cards
    │                                                │
    │                                ┌───────────────┴───────────────┐
    │                                ▼                               ▼
    │                    POST /capture-screenshots         Botón "Generar Reporte Word"
    │                    (Playwright, 2 hilos máximo)            │
    │                                │                           ▼
    │                                ▼              POST /generate-report
    │                    Screenshots base64          (results + screenshots)
    │                    agrupadas por IoC                    │
    │                                │                       ▼
    │                                └──────────► report_generator.py
    │                                            (python-docx + Pillow)
    │                                                │
    │                                                ▼
    │                                         .docx descargable
    │                                         (formato SOC oficial:
    │                                          logos, tabla análisis,
    │                                          riesgos, evidencia visual,
    │                                          recomendaciones, footer)
```

---

## Servicios Integrados

| Fuente | Estado | Tipo de IoC | API Key | Notas |
|---|---|---|---|---|
| VirusTotal | ✅ Funcional | ip, domain, url, hash | Requerida | Veredicto por conteo de motores maliciosos |
| AbuseIPDB | ✅ Funcional | ip | Requerida | Score de abuso + reportes + geolocalización |
| GreyNoise | ✅ Funcional | ip | Requerida | Clasifica ruido de fondo vs. malicioso |
| AlienVault OTX | ✅ Funcional | ip, domain, url, hash | Opcional | Pulsos de amenazas (comunidad) |
| ThreatBook | ⚠️ Limitado | ip (API), domain (manual) | Requerida | Solo IPs en plan gratuito (50 req/día) |
| URLhaus | ✅ Funcional | url, domain | No requiere | Pública, detecta malware distribution |
| PhishTank | ✅ Funcional | url, domain | No requiere | Pública, base de datos de phishing |
| Google Safe Browsing | ⚠️ Limitado | url, domain | Requerida | Solo URLs/dominios |
| MalwareBazaar | ✅ Funcional | hash | Opcional | Base de muestras de malware |
| MetaDefender | ⚠️ Limitado | hash | Requerida | Solo hashes |
| Hybrid Analysis | ⚠️ Limitado | hash | Requerida | Sandboxing, solo hashes |
| MISP | ⚠️ Limitado | ip, domain, url, hash | Requerida | Requiere instancia self-hosted |
| Gemini / Groq (IA) | ⚠️ Limitado | — | Requerida | Resumen ejecutivo en español, una por proveedor |

---

## Funciones Principales

### backend/app.py

| Función | Descripción |
|---|---|
| `query_source()` | Consulta una fuente individual con manejo de errores y retorno estructurado. |
| `enrich_ioc()` | Orquesta todas las consultas en paralelo, verifica caché y genera resumen IA para un IoC. |
| `analyze()` | Endpoint POST que recibe IoCs, detecta tipos y delega en `enrich_ioc()`. |
| `health()` | Endpoint GET que expone estado del servidor y estadísticas de caché del día. |
| `frontend()` | Sirve el archivo `index.html` desde Flask. |
| `clear_cache()` | Endpoint POST que limpia completamente la tabla de caché en SQLite. |
| `generate_report()` | Endpoint POST que recibe resultados, screenshots y resumen IA; genera y descarga un .docx en formato SOC oficial. |
| `capture_screenshots()` | Endpoint POST que recibe un IoC y sus web_urls; captura screenshots con Playwright (máx 2 concurrentes) y retorna base64. |
| `_run_screenshot()` | Helper síncrono que ejecuta `take_screenshot()` asíncrono dentro de un hilo. |

### backend/config.py

| Función/Variable | Descripción |
|---|---|
| *(module-level)* | Carga todas las API keys y parámetros desde `.env` usando `python-dotenv`. |

### backend/cache.py

| Función | Descripción |
|---|---|
| `init_db()` | Crea las tablas `ioc_cache` y `cache_stats` si no existen. |
| `get_cached()` | Busca resultado en caché; si existe y no expiró lo retorna incrementando hits. |
| `save_to_cache()` | Guarda el resultado en SQLite con clave compuesta `ioc:tipo:fuentes`. |
| `get_today_hits()` | Retorna cuántas veces se usó caché hoy (estadística). |
| `cleanup_expired()` | Elimina registros cuya `created_at` supere el TTL configurado (default 24h). |

### backend/utils/ioc_detector.py

| Función | Descripción |
|---|---|
| `detect_ioc_type()` | Clasifica un IoC como ip/domain/url/md5/sha1/sha256/unknown usando regex. |
| `normalize_ioc_type()` | Agrupa md5, sha1, sha256 como "hash" para APIs que no distinguen subtipo. |
| `is_valid_ioc()` | Retorna True si el string pasa la detección de tipo. |
| `parse_ioc_list()` | Divide texto plano en líneas, filtra comentarios (#) y duplicados, conserva solo IoCs válidos. |

### backend/services/virustotal.py

| Función | Descripción |
|---|---|
| `query()` | Consulta API v3, retorna conteo de motores maliciosos/sospechosos y geolocalización si es IP. |

### backend/services/abuseipdb.py

| Función | Descripción |
|---|---|
| `query()` | Consulta API v2 para IPs, retorna abuse confidence score, total reportes, país e ISP. |

### backend/services/greynoise.py

| Función | Descripción |
|---|---|
| `query()` | Consulta API v3 community para IPs, retorna clasificación, ruido y estado RIOT. |

### backend/services/alienvault_otx.py

| Función | Descripción |
|---|---|
| `query()` | Consulta cualquier tipo de IoC, retorna conteo de pulsos y reputación. |

### backend/services/threatbook.py

| Función | Descripción |
|---|---|
| `query()` | Consulta IPs vía endpoint gratuito (50 req/día); dominios requieren consulta manual en web. |

### backend/services/urlhaus.py

| Función | Descripción |
|---|---|
| `query()` | Consulta API pública para URLs y dominios, retorna threat, tags y conteo de URLs. |

### backend/services/phishtank.py

| Función | Descripción |
|---|---|
| `query()` | Consulta API pública para URLs y dominios, retorna si está en base de datos y verificado. |

### backend/services/google_safebrowsing.py

| Función | Descripción |
|---|---|
| `query()` | Consulta API v4 threatMatches para URLs/dominios, retorna tipo de amenaza detectada. |

### backend/services/malwarebazaar.py

| Función | Descripción |
|---|---|
| `query()` | Consulta hashes, retorna familia de malware, tipo de archivo y tags. |

### backend/services/metadefender.py

| Función | Descripción |
|---|---|
| `query()` | Consulta hashes, retorna detecciones por motor antivirus y tipo de archivo. |

### backend/services/hybrid_analysis.py

| Función | Descripción |
|---|---|
| `query()` | Consulta hashes, retorna threat score, familia y entorno de sandbox. |

### backend/services/misp.py

| Función | Descripción |
|---|---|
| `query()` | Consulta instancia MISP self-hosted vía restSearch, retorna coincidencias, categorías y eventos. |

### backend/services/ai_summary.py

| Función | Descripción |
|---|---|
| `format_sources_text()` | Convierte resultados de fuentes en texto plano para el prompt de la IA. |
| `generate_with_gemini()` | Llama a Gemini 2.0 Flash con el prompt estructurado. |
| `generate_with_groq()` | Llama a Groq (Llama 3.3 70B) con el prompt estructurado. |
| `generate_summary()` | Selecciona proveedor IA y genera resumen ejecutivo en español (máx 3 oraciones). |

### backend/services/screenshot_service.py

| Función | Descripción |
|---|---|
| `take_screenshot()` | Función asíncrona que captura una screenshot de una URL usando Playwright. Soporta dos modos: (1) sesión persistente con Edge y cookies inyectadas para AbuseIPDB/GreyNoise/ThreatBook; (2) Chromium headless temporal para el resto de fuentes. Incluye lógica anti-detección (webdriver override, user-agent realista) y manejo específico por fuente (selectores, tiempos de espera, captcha en ThreatBook). |
| `close_browser()` | Cierre limpio (ya no hay browser singleton). |

### backend/services/report_generator.py

| Función | Descripción |
|---|---|
| `generate_word_report()` | Función principal que genera un documento .docx profesional en formato SOC oficial. Recibe IoCs, resultados, resumen IA y screenshots (dict anidado). Construye: encabezado con logos Axity + Cortex XDR, tabla de metadatos (evento, fuente, criticidad), sección de análisis con tabla IP/sub-table, riesgos identificados según veredicto, tabla de datos del IoC, recomendaciones desde IA, evidencia visual con screenshots incrustadas, footer con analista y fecha, y nota legal. |
| `_build_analysis_text()` | Genera 3-4 oraciones de análisis descriptivo a partir de los resultados de las APIs. |
| `_build_risks()` | Genera lista de riesgos contextuales (4 items) según el veredicto: malicioso, sospechoso o limpio/desconocido. |
| `_get_worst_verdict()` | Determina el peor veredicto entre todas las fuentes para un IoC. |
| `_get_worst_verdict_from_nested()` | Determina el peor veredicto entre todos los IoCs y todas las fuentes. |

### backend/save_sessions.py

| Función | Descripción |
|---|---|
| `save_session()` | Abre una plataforma de Threat Intelligence en Edge (visible), espera que el usuario inicie sesión, y guarda cookies + localStorage en `backend/data/sessions/{source}.json`. |
| `main()` | Punto de entrada que itera sobre todas las plataformas (ThreatBook, AbuseIPDB, GreyNoise) ejecutando `save_session()` para cada una. |

### frontend/index.html (JS)

| Función | Descripción |
|---|---|
| `renderSources()` | Dibuja la UI de checkboxes para seleccionar fuentes desde la definición `SOURCES`. |
| `updateSourceCards()` | Actualiza estado habilitado/deshabilitado de las cards según el tipo de IoC seleccionado. |
| `toggleSource()` | Marca/desmarca una fuente y actualiza `selectedSources`. |
| `selectAI()` | Cambia entre proveedores de IA (Gemini/Groq). |
| `runAnalysis()` | Toma los IoCs del textarea, envía POST a `/analyze`, renderiza resultados e inicia captura de screenshots asíncrona. |
| `captureAllScreenshots()` | Itera secuencialmente sobre cada IoC llamando a `/capture-screenshots`, actualizando la UI de progreso y re-renderizando las imágenes conforme llegan. |
| `createScreenshotsSection()` | Crea la sección de capturas con spinners mientras se toman las screenshots. |
| `updateScreenshotsSection()` | Reemplaza spinners con las imágenes reales recibidas del backend. |
| `renderResults()` | Crea tarjetas con veredicto, resultados por fuente, resumen IA y sección de capturas agrupadas por IoC. |
| `getWorstVerdict()` | Determina el peor veredicto entre todas las fuentes para un IoC. |
| `buildReportText()` | Genera un reporte de texto plano exportable. |
| `copyReport()` | Copia el reporte al portapapeles. |
| `downloadReport()` | Descarga el reporte como archivo `.txt`. |
| `downloadWordReport()` | Recopila resultados y capturas seleccionadas (vía checkboxes), envía POST a `/generate-report` y descarga el .docx generado. |
| `updateCacheHits()` | Consulta `/health` para mostrar hits de caché del día. |
| `clearCache()` | Envía POST a `/clear-cache` para limpiar la base de datos. |

---

## Notas Importantes

### Limitaciones conocidas

- **ThreatBook**: La API gratuita solo cubre IPs (50 req/día); dominios requieren plan Premium y se redirigen a consulta manual.
- **GreyNoise**: El plan gratuito tiene un límite semanal de ~50 requests (endpoint `/v3/community`).
- **Hybrid Analysis**: El plan gratuito tiene rate limiting y requiere API key; sin ella el módulo no funciona.
- **MetaDefender**: API key obligatoria; sin configuración retorna "no configurada".
- **Google Safe Browsing**: Solo URLs y dominios; no soporta IPs ni hashes.
- **MISP**: Depende de una instancia self-hosted; si `MISP_URL` no está configurada, el servicio se desactiva silenciosamente.
- **Timeouts**: Todas las requests externas tienen un timeout global de 10 segundos configurable.
- **Caché**: TTL fijo de 24 horas; no hay invalidación manual ni por webhook.
- **Screenshots**: Las fuentes con protección Cloudflare (AbuseIPDB, GreyNoise, ThreatBook) requieren sesiones guardadas previamente con `save_sessions.py`. ThreatBook puede mostrar captcha si se excede la frecuencia.
- **Reportes Word**: Los logos Axity y Cortex XDR deben estar presentes en `backend/assets/`. Cortex-logo.webp se convierte a PNG en memoria con Pillow.

### Pendientes / Mejoras posibles

- **Soporte para IPv6**: El detector regex solo reconoce IPv4 (`\d{1,3}(\.\d{1,3}){3}`).
- **Autenticación**: No hay login ni control de acceso al endpoint `/analyze`.
- **Exportación JSON**: El frontend solo exporta en texto plano; no hay botón para descargar JSON estructurado.
- **Límite de 10 IoCs por request**: Definido en `config.py` pero el usuario no puede cambiarlo desde la UI.
- **Monitoreo**: No hay logging estructurado (solo `print` en `virustotal.py` y `screenshot_service.py`); no hay métricas exportables a Prometheus.
- **Pruebas automatizadas**: No se encontraron tests unitarios ni de integración en el repositorio.
- **Cola de procesamiento**: `ThreadPoolExecutor` se crea y destruye en cada request; no hay límite de concurrencia global.
- **Screenshots en cola**: Las capturas se toman secuencialmente por IoC; no hay cola de prioridad ni reintentos automáticos ante fallo.
- **Personalización de reportes**: El formato Word es fijo; no hay opción de seleccionar secciones o cambiar logos desde la UI.