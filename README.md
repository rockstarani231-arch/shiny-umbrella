# SHIELD

SHIELD is a browser-based scam-awareness demo published with GitHub Pages. It provides local pattern checks for messages and SMS, suspicious URL and dark web address warnings, phone-number reports, file metadata inspection, and a simulated call-screening sample inbox.

## Demo login

- Username: `rocky`
- Password: `ShieldDemo26!`

This is a front-end demonstration only. The app opens directly in guest mode; use the profile icon to open the sample portal. The credentials are visible in the page source and are not authentication. Do not reuse a real password or enter sensitive account information.

## Features

- Message and SMS scans for common urgency, impersonation, payment, identity, investment, job, delivery, and credential theft patterns.
- URL checks for suspicious structure and `.onion` or `.i2p` addresses without opening the destination.
- Local phone-number checks against reports saved in the current browser.
- A fictional call sample inbox with a local demo block list. It does not intercept or block actual phone calls.
- File metadata and SHA-256 fingerprint inspection in the browser. This does not scan files for malware.
- Local activity history, reports, privacy controls, and appearance settings.

## Scope and limitations

The published static site requires no API key or backend. Scans use transparent patterns and do not query live threat feeds. Dark web detection identifies address suffixes; it does not visit, verify, or assess dark web content. SMS and call blocking cannot be performed by a website; use your device or carrier's built-in controls for real blocking. Results are guidance, not a guarantee of safety. Caller IDs can be spoofed.

All scan history, local reports, demo login state, and demo call-block entries are stored in this browser's local storage and can be cleared from the app or browser settings.
