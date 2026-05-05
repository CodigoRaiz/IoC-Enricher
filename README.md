# IOC Enricher — SOC Tool

Herramienta interna para analistas SOC que automatiza el enriquecimiento de Indicadores de Compromiso (IoCs) consultando múltiples fuentes de Threat Intelligence simultáneamente y generando resúmenes ejecutivos con IA.

---

## 🚀 Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/CodigoRaiz/IoC-Enricher.git
cd IoC-Enricher
```

### 2. Crear y activar el entorno virtual
```bash
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows
source .venv/bin/activate    # Linux/Mac
```

### 3. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar las API keys
Crea un archivo `.env` en la raíz del proyecto con este contenido:
VIRUSTOTAL_API_KEY=
THREATBOOK_API_KEY=
HYBRID_ANALYSIS_KEY=
GOOGLE_SAFE_BROWSING_KEY=
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
METADEFENDER_API_KEY=
ALIENVAULT_OTX_KEY=
MISP_URL=
MISP_API_KEY=
GEMINI_API_KEY=
ANTHROPIC_API_KEY=
CACHE_TTL_HOURS=24
MAX_IOCS_PER_REQUEST=10
### 5. Dónde obtener cada API key
| Fuente | URL de registro |
|--------|----------------|
| VirusTotal | https://virustotal.com |
| AbuseIPDB | https://abuseipdb.com |
| GreyNoise | https://greynoise.io |
| AlienVault OTX | https://otx.alienvault.com |
| ThreatBook | https://threatbook.io |
| Google Safe Browsing | https://developers.google.com/safe-browsing |
| MetaDefender | https://metadefender.opswat.com |
| Hybrid Analysis | https://hybrid-analysis.com |
| Gemini | https://aistudio.google.com |
| Anthropic (Claude) | https://console.anthropic.com |

> URLhaus, PhishTank y MalwareBazaar son públicas y no requieren API key.

---

## ▶️ Uso

### 1. Iniciar el backend
```bash
python backend/app.py
```

### 2. Abrir la interfaz
Abre en el navegador: http://localhost:5001

### 3. Analizar IoCs
1. Ingresa los IoCs en el textarea (uno por línea)
2. Selecciona el tipo de indicador
3. Elige el motor de IA (Gemini o Claude)
4. Selecciona hasta 2 fuentes de consulta
5. Haz clic en **Analizar Indicadores**

---

## 📁 Estructura del proyecto
IOC Enricher/
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── cache.py
│   ├── services/
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── greynoise.py
│   │   ├── alienvault_otx.py
│   │   ├── threatbook.py
│   │   ├── urlhaus.py
│   │   ├── phishtank.py
│   │   ├── google_safebrowsing.py
│   │   ├── malwarebazaar.py
│   │   ├── metadefender.py
│   │   ├── hybrid_analysis.py
│   │   ├── misp.py
│   │   └── ai_summary.py
│   └── utils/
│       └── ioc_detector.py
├── frontend/
│   └── index.html
├── data/
│   └── feeds.db
├── .env
├── .gitignore
├── requirements.txt
└── README.md
---

## 🛠️ Tecnologías
- **Backend:** Python 3.10+ · Flask · SQLite
- **Frontend:** HTML5 · CSS3 · JavaScript
- **IA:** Google Gemini 1.5 Flash / Anthropic Claude Sonnet