# Sentinel AI Online — Full Deployable Project

Responsive online security dashboard for desktop/mobile browsers.

## Included modules
- AI-assisted scam/message analysis via optional server-side OpenAI API; local heuristic fallback remains available.
- URL checks with heuristic analysis plus optional Google Safe Browsing and VirusTotal reputation lookups.
- Caller-number lookup backed by persistent community reports, plus optional Twilio line-type metadata. This is not a global Truecaller database.
- File inspection: SHA-256, optional ClamAV in Docker, and VirusTotal existing-hash lookup (no file upload to VirusTotal).
- Community reports, recent browser-session activity, privacy disclosures, mobile responsive interface.

## Deploy online (no PowerShell)
1. Create a GitHub repository and upload all files in this folder.
2. In Render, choose **New → Blueprint** and connect that repository.
3. Render reads `render.yaml`; review the plan/pricing and create the service.
4. In the Render service Environment page, add provider API keys. Never place keys in frontend code.
5. Wait for deployment, then open the HTTPS URL on mobile or PC.

Dockerfile installs ClamAV. The Render persistent disk keeps the SQLite community database across restarts. For larger production traffic, move to managed PostgreSQL, use stronger rate limiting/authentication, moderation, malware sandbox isolation, audit logs, backups, and a reviewed privacy policy.

## Providers
- OPENAI_API_KEY: enables AI text analysis; submitted text goes to OpenAI.
- GOOGLE_SAFE_BROWSING_KEY: URL reputation lookup; submitted URLs go to Google.
- VIRUSTOTAL_API_KEY: existing URL/hash reputation lookup. Files are not automatically uploaded to VirusTotal.
- TWILIO_*: optional number metadata/line type only; it does not provide a Truecaller-like spam database or verified caller name.

## Important limitations
- The community phone database begins empty. Unknown number = unknown, not safe.
- This browser app cannot intercept or block incoming cellular calls. That requires a native Android call-screening companion and OS permission.
- Malware scanning depends on ClamAV signatures and/or known hash records. Clean is not proof of safety.
- Online use requires deployment; this bundle is deploy-ready but has not been deployed to a live account.
- Do not submit secrets or confidential files. Uploaded files are sent to your server for scanning.
