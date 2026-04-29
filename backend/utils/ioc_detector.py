# ioc_detector.py — Detección automática del tipo de IoC mediante regex
import re

def detect_ioc_type(ioc: str) -> str:
    """
    Detecta el tipo de IoC basándose en su formato.
    Retorna: 'ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'unknown'
    """
    ioc = ioc.strip()

    # Hash SHA256 (64 caracteres hexadecimales)
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "sha256"

    # Hash SHA1 (40 caracteres hexadecimales)
    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "sha1"

    # Hash MD5 (32 caracteres hexadecimales)
    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "md5"

    # Dirección IP (IPv4)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        # Verificar que cada octeto sea válido (0-255)
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"

    # URL (empieza con http:// o https://)
    if re.match(r"https?://", ioc, re.IGNORECASE):
        return "url"

    # Dominio (formato general)
    if re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}", ioc):
        return "domain"

    return "unknown"

def normalize_ioc_type(ioc_type: str) -> str:
    """
    Normaliza el tipo de IoC para las APIs.
    Los hashes MD5, SHA1 y SHA256 se agrupan como 'hash'.
    """
    if ioc_type in ["md5", "sha1", "sha256"]:
        return "hash"
    return ioc_type

def is_valid_ioc(ioc: str) -> bool:
    """Verifica si un string es un IoC válido."""
    return detect_ioc_type(ioc.strip()) != "unknown"

def parse_ioc_list(raw_text: str) -> list:
    """
    Parsea un texto con múltiples IoCs (uno por línea).
    Ignora líneas vacías y comentarios (que empiezan con #).
    Retorna lista de IoCs válidos únicos.
    """
    iocs = []
    seen = set()

    for line in raw_text.splitlines():
        ioc = line.strip()
        if not ioc or ioc.startswith("#"):
            continue
        if ioc not in seen and is_valid_ioc(ioc):
            seen.add(ioc)
            iocs.append(ioc)

    return iocs