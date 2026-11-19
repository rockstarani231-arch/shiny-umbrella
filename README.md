# SHIELD

SHIELD is a browser-based scam-awareness demo published with GitHub Pages. It provides local pattern checks for messages and SMS, suspicious URL and dark web address warnings, phone-number reports, file metadata inspection, and a simulated call-screening sample inbox.

## Login, sign-up, and logout

- Username: `rocky`
- Password: `ShieldDemo26!`

The account dialog supports login, sign-up, and logout. New demo accounts are stored in this browser, with passwords hashed using PBKDF2; the active session lasts for the current browser tab. This is client-side demo behavior, not production authentication: the sample credentials are visible in the page source, and local browser storage can be changed by its owner. Do not reuse a real password or enter sensitive account information.

The workspace opens in guest mode. Use “Log in / Sign up” to open account options.

Each login has its own local profile (display name and short introduction) and scam-alert inbox. High-risk scan results add an in-app notification and play a short ringing alert. The ringing tone can be muted in Settings. Notifications and profiles are stored in this browser only; they are not sent as device or email notifications.

## Features

- Message and SMS scans for common urgency, impersonation, payment, identity, investment, job, delivery, and credential theft patterns.
- URL checks for suspicious structure and `.onion` or `.i2p` addresses without opening the destination.
- Local phone-number checks against reports saved in the current browser.
- A fictional call sample inbox with a local demo block list. It does not intercept or block actual phone calls.
- File metadata and SHA-256 fingerprint inspection in the browser. This does not scan files for malware.
- Local activity history, reports, privacy controls, and appearance settings.
- Account-specific profiles and an in-app notification tab for high-risk scam detections, with an optional ringing alert.

## Scope and limitations

The published static site requires no API key or backend. Scans use transparent patterns and do not query live threat feeds. Dark web detection identifies address suffixes; it does not visit, verify, or assess dark web content. SMS and call blocking cannot be performed by a website; use your device or carrier's built-in controls for real blocking. Results are guidance, not a guarantee of safety. Caller IDs can be spoofed.

Profiles, scan history, scam notifications, reports, demo account records, and call-block entries stay in this browser. The active login session is cleared when you log out or close the browser tab.

Developed by Dhruv Goyal & Team.

