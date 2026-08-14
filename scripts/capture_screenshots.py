"""Regenerate docs/screenshots/*.png from the live demo (`make screenshots`).

Requires the optional `screenshots` extra (Playwright) - never a base or CI
dependency. Starts the real app, visits each demo scenario URL, and saves a
full-page screenshot, so images stay provably current with the UI rather
than becoming stale hand-made artifacts. See README "Screenshots".
"""

import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

HOST = "127.0.0.1"
PORT = 8931
BASE_URL = f"http://{HOST}:{PORT}"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"

# (scenario name, output filename) - kept small and named after what each
# screenshot demonstrates, matching README "Screenshots" section.
SCENARIOS = [
    ("high_risk", "01-successful-investigation.png"),
    ("enrichment_failure", "02-enrichment-failure.png"),
    ("ai_failure", "03-ai-failure.png"),
]


def wait_for_server(timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{BASE_URL}/health", timeout=1)
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.3)
    raise RuntimeError(f"app did not become ready in time: {last_error}")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", HOST, "--port", str(PORT)],
    )
    try:
        wait_for_server()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1200, "height": 900})
            for scenario_name, filename in SCENARIOS:
                page.goto(f"{BASE_URL}/demo/{scenario_name}", wait_until="networkidle")
                page.screenshot(path=str(OUTPUT_DIR / filename), full_page=True)
                print(f"captured {filename}")
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    main()
