# ai_summary.py — Generación de resumen ejecutivo con IA (Gemini o Groq)
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEMINI_API_KEY, GROQ_API_KEY

# Prompt base para el resumen ejecutivo
PROMPT_TEMPLATE = """Eres un analista de ciberseguridad SOC. Basándote en los siguientes resultados de Threat Intelligence, redacta un resumen ejecutivo en español de máximo 3 oraciones para incluir en un informe de incidente de seguridad. Sé directo y técnico. Incluye: (1) veredicto general del indicador, (2) qué tipo de amenaza representa o por qué es sospechoso según las fuentes consultadas, (3) acción recomendada para el analista. No uses listas, solo párrafo continuo.

IoC: {ioc}
Tipo: {ioc_type}
Resultados por fuente:
{sources_text}"""


def format_sources_text(sources: dict) -> str:
    """Formatea los resultados de las fuentes para el prompt."""
    lines = []
    for source_name, result in sources.items():
        verdict = result.get("verdict", "unknown")
        detail  = result.get("detail", "Sin detalle")
        lines.append(f"- {source_name}: {verdict.upper()} — {detail}")
    return "\n".join(lines)


def generate_with_gemini(prompt: str) -> str:
    """Genera resumen usando Google Gemini."""
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        return f"Error al generar resumen con Gemini: {str(e)}"


def generate_with_groq(prompt: str) -> str:
    """Genera resumen usando Groq (Llama 3)."""
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error al generar resumen con Groq: {str(e)}"


def generate_summary(ioc: str, ioc_type: str, sources: dict, ai_provider: str = "gemini") -> str:
    """
    Genera un resumen ejecutivo del IoC usando la IA seleccionada.
    """
    if not sources:
        return "No hay resultados de fuentes para generar un resumen."

    sources_text = format_sources_text(sources)
    prompt = PROMPT_TEMPLATE.format(
        ioc          = ioc,
        ioc_type     = ioc_type.upper(),
        sources_text = sources_text
    )

    if ai_provider == "groq":
        if not GROQ_API_KEY:
            return "⚠️ API key de Groq no configurada en el archivo .env"
        return generate_with_groq(prompt)
    else:
        if not GEMINI_API_KEY:
            return "⚠️ API key de Gemini no configurada en el archivo .env"
        return generate_with_gemini(prompt)