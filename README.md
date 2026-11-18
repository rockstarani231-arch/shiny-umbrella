# SHIELD

SHIELD is a responsive, browser-based scam protection workspace published with GitHub Pages.

## Features
- Message scanning for common scam patterns and clear next-step guidance.
- URL structure checks without visiting the destination.
- Local phone-number reports and caller safety guidance.
- File metadata and SHA-256 fingerprint inspection in the browser.
- Local activity history, saved reports, privacy controls, and appearance settings.

The static SHIELD site runs without an API key or backend. Checks and saved history stay in the current browser. Results are pattern-based guidance, not a guarantee that a message, number, website, or file is safe. Caller IDs can be spoofed.

## Optional server project
`app.py`, `Dockerfile`, `requirements.txt`, and `render.yaml` are retained as a separate optional server project. They are not required to publish the static GitHub Pages site. The server requires a separate deployment and provider configuration; no credentials are stored in this repository.
