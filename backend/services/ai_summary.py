# ai_summary.py — Generación de resumen ejecutivo con IA (Gemini o Claude)
import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import GEMINI_API_KEY, ANTHROPIC_API_KEY

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
    """Genera resumen usando Google Gemini 1.5 Flash."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model    = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        return response.text.strip()
    except ImportError:
        return "Error: librería google-generativeai no instalada. Ejecuta: pip install google-generativeai"
    except Exception as e:
        return f"Error al generar resumen con Gemini: {str(e)}"


def generate_with_claude(prompt: str) -> str:
    """Genera resumen usando Claude (Anthropic)."""
    try:
        import anthropic
        client   = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message  = client.messages.create(
            model      = "claude-sonnet-4-20250514",
            max_tokens = 400,
            messages   = [{"role": "user", "content": prompt}]
        )
        return message.content[0].text.strip()
    except ImportError:
        return "Error: librería anthropic no instalada. Ejecuta: pip install anthropic"
    except Exception as e:
        return f"Error al generar resumen con Claude: {str(e)}"


def generate_summary(ioc: str, ioc_type: str, sources: dict, ai_provider: str = "gemini") -> str:
    """
    Genera un resumen ejecutivo del IoC usando la IA seleccionada.

    Args:
        ioc:         El indicador analizado
        ioc_type:    Tipo de IoC (ip, domain, hash, etc.)
        sources:     Resultados de las fuentes consultadas
        ai_provider: 'gemini' o 'claude'

    Returns:
        Resumen ejecutivo en español
    """
    # Verificar que hay resultados para resumir
    if not sources:
        return "No hay resultados de fuentes para generar un resumen."

    # Construir el prompt
    sources_text = format_sources_text(sources)
    prompt = PROMPT_TEMPLATE.format(
        ioc          = ioc,
        ioc_type     = ioc_type.upper(),
        sources_text = sources_text
    )

    # Seleccionar proveedor de IA
    if ai_provider == "claude":
        if not ANTHROPIC_API_KEY:
            return "⚠️ API key de Anthropic no configurada en el archivo .env"
        return generate_with_claude(prompt)
    else:
        if not GEMINI_API_KEY:
            return "⚠️ API key de Gemini no configurada en el archivo .env"
        return generate_with_gemini(prompt)