"""save_sessions.py — Save authenticated browser sessions for threat intelligence platforms."""

import asyncio
import json
import os
from playwright.async_api import async_playwright

# Realistic Chrome user agent
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

PLATFORMS = {
    "threatbook": "https://i.threatbook.io/research",
    "abuseipdb": "https://www.abuseipdb.com/",
    "greynoise": "https://viz.greynoise.io/",
}

SESSION_DIR = os.path.join("backend", "data", "sessions")


async def save_session(source: str, url: str):
    """Open a platform in a visible browser, wait for user login, and save the session."""
    print(f"\n{'='*60}")
    print(f"Opening {source}...")
    print(f"{'='*60}")

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=r"C:\Users\user\AppData\Local\Microsoft\Edge\User Data",
            channel="msedge",
            headless=False,
            viewport={"width": 1000, "height": 700}
        )

        page = await context.new_page()
        await page.goto(url, wait_until="load", timeout=60000)

        print(f"\n  Log in to {source} and press Enter when you see the results.")
        input("  > Press Enter to save session and continue...")

        # Save cookies
        cookies = await context.cookies()
        # Save localStorage
        localStorage = await page.evaluate("() => JSON.stringify(window.localStorage)")
        localStorage_data = json.loads(localStorage)

        session_data = {
            "cookies": cookies,
            "localStorage": localStorage_data,
        }

        os.makedirs(SESSION_DIR, exist_ok=True)
        session_path = os.path.join(SESSION_DIR, f"{source}.json")
        with open(session_path, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)

        print(f"  Session saved to {session_path}")

        await context.close()


async def main():
    """Main entry point — save sessions for all platforms."""
    os.makedirs(SESSION_DIR, exist_ok=True)

    for source, url in PLATFORMS.items():
        await save_session(source, url)

    print(f"\n{'='*60}")
    print("All sessions saved!")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())