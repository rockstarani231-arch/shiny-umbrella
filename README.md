# SHIELD

SHIELD is a browser based scam awareness workspace published with GitHub Pages. It provides local pattern checks for messages and SMS, local URL structure warnings including dark web address detection, public complaint lookups for US phone numbers, a personal caller watchlist, file metadata and SHA-256 inspection, saved reports, account profiles, alerts, and appearance settings.

## Accounts and privacy

You can create an account, sign in, and sign out. Accounts and profiles are stored in this browser and do not sync to another device or provide server-backed identity or recovery. Passwords are hashed with PBKDF2 before browser storage, but browser storage is controlled by the device owner. Use a unique password and do not store sensitive information here.

Messages, SMS, links, and files are checked in the browser. Phone number lookups send the number to USACallerLookup to retrieve public complaint records; those reports are unverified and caller ID may be spoofed. SHIELD does not connect to live URL threat feeds or an AI service. Its URL and message checks use local rules and cannot guarantee safety.

## Features

- Message and SMS pattern analysis, with rotating example messages
- URL structure inspection and detection of `.onion` and `.i2p` addresses without opening them
- Live US unwanted-call complaint lookup and a personal watchlist
- File metadata and SHA-256 fingerprint inspection in the browser; this is not antivirus scanning
- Local check history, saved reports, profiles, notifications, and clear controls
- 5–7 second ringing alert for high-risk results, optional browser notifications while the page is open, and Midnight, Daylight, and Ocean appearances

A website cannot intercept phone calls or block SMS on your device. The watchlist saves numbers in this browser; use your phone or carrier’s own tools to block calls and messages. Device notifications require browser permission and do not work in the background without a push service.

## Development

This is a static site. Open `index.html` directly or serve this folder with any static web server. The optional Python files are not required for GitHub Pages.

