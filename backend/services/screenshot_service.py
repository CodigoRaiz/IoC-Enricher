"""screenshot_service.py — Captura de pantallas de fuentes de Threat Intelligence usando Playwright."""

import asyncio
import json
import os
import shutil
import tempfile
import time
from playwright.async_api import async_playwright, Browser, TimeoutError as PlaywrightTimeout

# Semáforo global para limitar capturas simultáneas a 2
_semaphore = asyncio.Semaphore(2)

# Realistic Chrome user agent
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

# Map source names to their session file paths
SESSION_MAP = {
    "threatbook": "backend/data/sessions/threatbook.json",
    "abuseipdb": "backend/data/sessions/abuseipdb.json",
    "greynoise": "backend/data/sessions/greynoise.json",
}

# Chrome arguments for headless mode — evita colgarse en páginas pesadas
CHROME_ARGS = [
    "--disable-gpu",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-accelerated-2d-canvas",
    "--disable-setuid-sandbox",
    "--disable-web-security",
    "--disable-features=VizDisplayCompositor",
]


async def take_screenshot(url: str, source_name: str, source_data: dict = None) -> bytes:
    """
    Take a screenshot of the given URL.

    Args:
        url: The full URL to navigate to.
        source_name: Key identifying the source (e.g., 'abuseipdb', 'virustotal').
        source_data: Optional API result data (not used in this version).

    Returns:
        PNG image bytes.
    """
    async with _semaphore:
        source_key = source_name.lower()

        print(f"Starting screenshot for {source_name}: {url}")

        # ── Session-based sources (AbuseIPDB, GreyNoise, ThreatBook) ──────────
        # Use launch_persistent_context with Edge to bypass Cloudflare detection
        if source_key in SESSION_MAP:
            session_path = SESSION_MAP[source_key]
            if not os.path.exists(session_path):
                raise FileNotFoundError(
                    f"Session file not found for {source_name}: {session_path}"
                )

            with open(session_path, "r", encoding="utf-8") as f:
                session_data = json.load(f)

            temp_dir = tempfile.mkdtemp(prefix=f"playwright_{source_key}_")
            print(f"[SESSION] Launching persistent context for {source_name}")

            async with async_playwright() as p:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    channel="msedge",
                    headless=False,
                    viewport={"width": 1280, "height": 900},
                )
                try:
                    # Inject saved session cookies into the persistent context
                    await context.add_cookies(session_data["cookies"])
                    print(f"[SESSION] Cookies injected: {len(session_data['cookies'])}")

                    # Disable webdriver detection
                    await context.add_init_script("""
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined
                        });
                    """)

                    # ThreatBook-specific stealth measures
                    if source_key == "threatbook":
                        await context.add_init_script("""
                            // Override navigator.plugins to appear as a normal browser
                            Object.defineProperty(navigator, 'plugins', {
                                get: () => [1, 2, 3, 4, 5]
                            });

                            // Override window.chrome to appear as Chrome
                            window.chrome = {
                                runtime: {},
                                loadTimes: function() {},
                                csi: function() {},
                                app: {}
                            };
                        """)
                        await context.set_extra_http_headers({
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
                        })

                    page = await context.new_page()
                    print(f"[SESSION] Opening Edge for {source_name}")

                    # AbuseIPDB: esperar 2s antes de navegar para que Edge esté listo
                    if source_name == "abuseipdb":
                        await asyncio.sleep(2)

                    await page.goto(url, wait_until="load", timeout=60000)

                    # Wait for network idle
                    try:
                        await page.wait_for_load_state("networkidle", timeout=20000)
                    except PlaywrightTimeout:
                        pass

                    # Source-specific wait logic
                    if source_name == "abuseipdb":
                        try:
                            await page.wait_for_selector('table, .card', timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    elif source_name == "greynoise":
                        try:
                            await page.click('button:has-text("Get Started")', timeout=3000)
                        except Exception:
                            pass
                        try:
                            await page.click('[aria-label="Close"]', timeout=3000)
                        except Exception:
                            pass
                        await page.keyboard.press("Escape")
                        await asyncio.sleep(2)

                    # All sources: sleep 3s after page load before screenshot
                    await asyncio.sleep(3)

                    # Verificar si ThreatBook mostró captcha — tomar screenshot igualmente
                    if source_key == "threatbook":
                        current_url = page.url
                        if "exceedFrequency" in current_url or "captcha" in current_url.lower():
                            print(f"[THREATBOOK] Captcha detectado en URL: {current_url} — tomando screenshot de la página de captcha")
                            screenshot_bytes = await page.screenshot(full_page=False)
                            print(f"Screenshot success (captcha page): {len(screenshot_bytes)} bytes")
                            return screenshot_bytes

                    screenshot_bytes = await page.screenshot(full_page=False)
                    print(f"Screenshot success: {len(screenshot_bytes)} bytes")
                    return screenshot_bytes

                except Exception as e:
                    print(f"Screenshot failed: {e}")
                    raise
                finally:
                    await context.close()
                    shutil.rmtree(temp_dir, ignore_errors=True)

        # ── Non-session sources (Chromium headless, browser temporal) ─────────
        # Crear browser NUEVO por cada captura para evitar estado inválido
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=CHROME_ARGS,
            )
            try:
                context = await browser.new_context(
                    user_agent=USER_AGENT,
                    viewport={"width": 1280, "height": 900},
                )

                # Disable webdriver detection for all sources
                await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                """)

                page = await context.new_page()

                try:
                    await page.goto(url, wait_until="load", timeout=60000)

                    # Wait for network idle (all sources)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=20000)
                    except PlaywrightTimeout:
                        pass  # Never fail on timeout

                    # Source-specific wait logic
                    if source_name == "abuseipdb":
                        await asyncio.sleep(5)
                    elif source_name == "greynoise":
                        await asyncio.sleep(3)
                    elif source_name == "virustotal":
                        try:
                            await page.wait_for_selector(".report-section", timeout=20000)
                        except PlaywrightTimeout:
                            pass  # Take screenshot anyway on timeout
                    elif source_name == "alienvault_otx":
                        try:
                            await page.wait_for_selector(".general-info", timeout=15000)
                        except PlaywrightTimeout:
                            pass  # Take screenshot anyway on timeout
                    elif source_name == "urlhaus":
                        try:
                            await page.wait_for_selector("table, .card, .result", timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    elif source_name == "google_safebrowsing":
                        try:
                            await page.wait_for_selector("#main-content, .sr-only, [role='main']", timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    elif source_name == "phishtank":
                        try:
                            await page.wait_for_selector("table, .phish-list, .result", timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    elif source_name == "malwarebazaar":
                        try:
                            await page.wait_for_selector("table, .card, .result", timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    elif source_name == "metadefender":
                        try:
                            await page.wait_for_selector(".report, .result, .card", timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    elif source_name == "hybrid_analysis":
                        try:
                            await page.wait_for_selector(".report, .card, .result", timeout=15000)
                        except PlaywrightTimeout:
                            pass
                    else:
                        pass  # No additional wait for other sources

                    # All sources: sleep 3s after page load before screenshot
                    await asyncio.sleep(3)

                    # Verificar si ThreatBook mostró captcha (non-session path, por si acaso)
                    if source_key == "threatbook":
                        current_url = page.url
                        if "exceedFrequency" in current_url or "captcha" in current_url.lower():
                            print(f"[THREATBOOK] Captcha detectado en URL: {current_url} — tomando screenshot de la página de captcha")
                            screenshot_bytes = await page.screenshot(full_page=False)
                            print(f"Screenshot success (captcha page): {len(screenshot_bytes)} bytes")
                            return screenshot_bytes

                    screenshot_bytes = await page.screenshot(full_page=False)
                    print(f"Screenshot success: {len(screenshot_bytes)} bytes")
                    return screenshot_bytes
                except Exception as e:
                    print(f"Screenshot failed: {e}")
                    raise
                finally:
                    await context.close()
            finally:
                await browser.close()


async def close_browser():
    """Clean shutdown — ya no hay browser singleton que cerrar."""
    pass