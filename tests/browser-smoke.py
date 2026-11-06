#!/usr/bin/env python3

import json
from playwright.sync_api import sync_playwright


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()
    console_errors = []
    page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
    page.goto("http://127.0.0.1:8000/", wait_until="domcontentloaded")
    page.wait_for_function(
        "document.querySelector('#fingerprint-status').textContent !== 'Running' && "
        "document.querySelector('#cve-status').textContent.includes('Showing')",
        timeout=30_000,
    )
    result = page.evaluate("""() => ({
      fingerprintStatus: document.querySelector('#fingerprint-status').textContent,
      fingerprint: JSON.parse(document.querySelector('#fingerprint-output').textContent),
      projectsStatus: document.querySelector('#projects-status').textContent,
      versionStatus: document.querySelector('#version-status').textContent,
      cveStatus: document.querySelector('#cve-status').textContent,
      cveNote: document.querySelector('#cve-note').textContent,
      consoleErrors: []
    })""")
    result["consoleErrors"] = console_errors
    print(json.dumps(result, indent=2))
    browser.close()
