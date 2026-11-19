# SHIELD

SHIELD is a browser-based scam-awareness demo published with GitHub Pages. It provides local pattern checks for messages and SMS, suspicious URL and dark web address warnings, phone-number reports, file metadata inspection, and a simulated call-screening sample inbox.

## Login, sign-up, and logout

- Username: `shieldadmin` (display name: SHIELD Admin)
- Password: `ShieldDemo26!`

The account dialog supports login, sign-up, and logout. New demo accounts are stored in this browser, with passwords hashed using PBKDF2; the active session lasts for the current browser tab. This is client-side demo behavior, not production authentication: the sample credentials are visible in the page source, and local browser storage can be changed by its owner. Do not reuse a real password or enter sensitive account information.

The workspace opens in guest mode. Use “Log in / Sign up” to open account options.

Each login has its own local profile (display name and short introduction) and scam-alert inbox. High-risk scan results add an in-app notification and play a 5–7 second ringing alert. The ringing tone can be muted in Settings. Five sample messages rotate each time “Try a sample” is clicked. The Ocean appearance adds a blue water theme.

SHIELD can also request browser permission for device notifications. Those alerts appear while this site is open. True background web push after the site is closed requires a push server and VAPID keys, which this static GitHub Pages site does not provide. Profiles and alerts stay in this browser.

## Features

- Message and SMS scans for common urgency, impersonation, payment, identity, investment, job, delivery, and credential theft patterns.
- URL checks for suspicious structure and `.onion` or `.i2p` addresses without opening the destination.
- Live US phone-number lookups against FTC unwanted-call complaint data through the USACallerLookup public API, combined with reports saved in the current browser. The lookup supports US numbers only; complaint records are unverified and caller ID may be spoofed.
- A fictional call sample inbox with a local demo block list. It does not intercept or block actual phone calls.
- File metadata and SHA-256 fingerprint inspection in the browser. This does not scan files for malware.
- Local activity history, reports, privacy controls, and appearance settings.
- Account-specific profiles, sample profile image, and an in-app notification tab with a clear option for high-risk scam detections.
- Optional browser device alerts, configurable sound alerts, and Midnight, Daylight, and Ocean appearance modes.

## Scope and limitations

The GitHub Pages site runs without a backend by default. Phone lookups send a US number to USACallerLookup's public API, which says its complaint data comes from FTC Do Not Call reports and is typically refreshed each weekday. FTC complaint data consists of consumer reports and is not verified; it describes the displayed caller ID, which can be spoofed. A number with no matching complaint is not proven safe. International numbers fall back to local reports only. The URL checker uses local structural analysis and does not send URLs to an external service.



Profiles, scan history, scam notifications, reports, demo account records, and call-block entries stay in this browser. The active login session is cleared when you log out or close the browser tab. The sidebar scrolls independently on shorter desktop displays so its lower controls stay reachable.

Developed by Dhruv Goyal & Team.

