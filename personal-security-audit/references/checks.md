# Checks reference

Each check has: **What** · **How** (connector → CLI/script → browser → user step) · **Link** (official).
Mark each result Found / Still open / Owner choice / Not checked / Done (sample) and give a date.

## §0 Pre-flight (one interruption)
Ask at most 5 questions, then do not interrupt again:
1. Which 3 accounts would hurt most if lost? (default: main email, bank, phone carrier)
2. Which password manager, if any? Do you use passkeys?
3. Do you own domains, websites, or cloud projects? Which hosts?
4. Which AI agents or automations act on your accounts (email, calendar, browser)?
5. Anyone else who uses your devices or accounts (family, assistant)?

Then ask the user to sign in once (they type credentials; you never do) in the browser you will read:
- Google: https://myaccount.google.com/device-activity and https://passwords.google.com/checkup
- Microsoft: https://account.microsoft.com/security · Apple: https://account.apple.com
- Password manager vault (1Password Watchtower, Bitwarden Reports, Google Password Checkup)
Explain: "These pages re-check your password. Signing in now avoids stops later."

## §1 Asset & identity inventory
- Mail search, all years: `subject:(welcome OR "verify your email" OR "confirm your email")`, plus "is the recovery email for", "Sign in with Google", "You allowed … access". Build a list of services and dates.
- Linked accounts: Google https://myaccount.google.com/connections · Microsoft https://account.live.com/consent/Manage · Apple "Sign in with Apple" (Settings → Apple ID → Sign-In & Security) · GitHub https://github.com/settings/applications · Facebook/X/LinkedIn app settings.
- Git credentials for unknown hosts: `git config --global --list | grep credential`.
- Breach exposure of each email: https://haveibeenpwned.com (user step if no API key). A breach listing is not proof of account use.
- Domains you own: registrar lock, auto-renew, expiry date, registrar 2FA. An expired domain lets anyone receive your mail and reset accounts tied to it.

## §2 Authentication
- Per critical account: factor types (passkey > security key > authenticator > push > SMS), backup codes exist, app passwords (Google: https://myaccount.google.com/apppasswords — they bypass 2FA).
- Password age and reuse from the manager's report. Changing a saved entry is not changing the site password; verify with a fresh sign-in in a private window.

## §3 Recovery chain
- Draw it: main email ← recovery email ← its recovery … Each link must have its own 2FA. Flag security questions.
- Phone carrier: port-out / SIM PIN set (US: T-Mobile, Verizon, AT&T account security pages). SIM swap defeats SMS codes.
- Authenticator backup: is the authenticator synced or exported? Losing the phone must not lock the user out.

## §4 Delegated access
- OAuth apps per account with scopes (open each app page; record mail send/read/delete, Drive full, Contacts delete). Compare against live list before recommending removal.
- Browser extensions: `local_audit.py extensions` → flag `debugger`, `cookies`, all-sites, `management`, `nativeMessaging`, `userScripts`; list disabled-but-installed.
- IDE extensions: `local_audit.py ide` → `publisherVerified=False` or `unknown` (the editor did not record it), `source=vsix` (sideloaded), `OLD>2y` (local install date older than 730 days; this is not the marketplace release date — check the marketplace page before you call it abandoned).
- MCP servers and agent tools: `local_audit.py configs` → servers with whole-home filesystem, browser control, installers; literal secrets in config.
- Third-party automations (Zapier, Make, n8n, Activepieces): list zaps that touch mail or money.

## §5 Attacker persistence (check even when nothing looks wrong)
- Gmail: Settings → Forwarding and POP/IMAP, Filters (auto-forward/delete/mark-read rules), Accounts → "Grant access to your account" (delegates), Send mail as. Outlook: Rules, Forwarding, Connected accounts.
- Active sessions on main accounts; sign out unknown ones, then rotate password (sessions and OAuth tokens can survive a password change — revoke them explicitly).
- Recovery options changed recently? Unknown passkeys or security keys added?

## §6 Secrets lifecycle
- `local_audit.py configs` (distinct vs entries; reused keys across tools).
- `local_audit.py secrets <dirs>` on code, Documents, Desktop, cloud-sync folders (OneDrive/Dropbox/iCloud Drive), agent transcript exports. Run per folder in parallel, in the background.
- Git history, not only current files: `local_audit.py history <repo>..` scans every commit on all branches (types and distinct counts only). For your own public repos, also enable GitHub secret scanning + push protection. A key in history stays exposed after you delete the file: rotate it.
- Plain-text "key folders" and `.env` files outside git (risk when later pushed).
- Per provider console: last-used date, scope, spending limit, IP allowlist. Unused 30 days → revoke.
- CI secrets: GitHub Actions secrets, `workflow` scope tokens, deploy keys.

## §7 Data exposure & sharing
- Drive/OneDrive/Dropbox: search `visibility:anyone_with_link`, `visibility:public`; sample permissions via API.
- Shared AI chats and links: ChatGPT Shared links, Claude shared chats, Gemini public links; training opt-outs (Claude "Help improve Claude", ChatGPT "Improve the model", Gemini Apps Activity, Grok data controls). Menu names change — verify on the page.
- Location sharing, photo-album links, calendar made public.
- Public code repos: count, and which contain personal data or keys.

## §8 Software & supply chain
- OS patch level and pending reboot (Windows: `Get-HotFix`, `winget upgrade`; macOS: `softwareupdate -l`, `brew outdated`; Linux: `apt list --upgradable`).
- Browsers vs current stable; forks (Comet, Arc, Brave) lag Chrome fixes.
- Runtimes: node/python/java/go versions and every extra copy (nvm, pyenv, conda).
- JS: `npm audit --package-lock-only` (no install); pnpm `pnpm audit`; Python: `local_audit.py osv <python.exe>` (osv.dev, no install).
- Known-incident checks from current news (e.g. a compromised package version list) — verify from the vendor advisory, then search lockfiles and site-packages.
- `.npmrc ignore-scripts=false` means install scripts run; recommend `npm config set ignore-scripts true` for untrusted projects (owner choice).
- Deprecated globals: `npm view <pkg> deprecated`.

## §9 Network exposure
- `local_audit.py network` lists ports bound to all interfaces, names known AI-server ports, and (Windows) the network profile.
- Listening sockets on all interfaces (Windows `Get-NetTCPConnection -State Listen`; macOS `lsof -iTCP -sTCP:LISTEN`; Linux `ss -tlnp`) × firewall rules × network profile (Public/Private). Local AI servers (Ollama 11434, LM Studio 1234, ComfyUI 8188, Jupyter 8888) have no auth.
- Tunnels: ngrok/Cloudflare/Tailscale Funnel exposures.
- Router (user step): admin password changed, firmware current, UPnP off, WPS off, guest network for IoT.

## §10 Device & physical
- `local_audit.py device`: firewall profiles, Defender state, every registered AV product, BitLocker (admin needed → user step) / FileVault.
- Disk encryption (BitLocker/Device encryption, FileVault, LUKS), screen lock, Find My / Find My Device, AV state (one active AV; stale entries), firewall, UAC/RDP.
- Infostealers: malware that copies browser session cookies, so the attacker is signed in without the password or 2FA. Signs: sign-in alerts from unknown places right after installing cracked software or a fake update. Fix: clean the device, then sign out all sessions and rotate passwords from a clean device.
- Phone: OS version, Safety Check (iOS), Google Play Protect, SIM PIN, lock-screen notification previews.

## §11 Financial blast radius
- API and cloud spending limits and billing alerts; cards saved in browsers; bank alerts for every transaction; credit freeze (US: Equifax, Experian, TransUnion — free); brokerage document-delivery and address changes.

## §12 AI-agent risk
- Autonomy settings: Claude Code `defaultMode`, bypass prompts; Codex `approval_policy="never"`, `danger-full-access`; Cursor auto-run.
- Injection paths: which agents read untrusted mail/web AND can send mail, push code, or spend money. That pair is the highest-risk combination.
- Agent transcripts and logs contain secrets; check where they sync.
- Agent identities: separate Google account for agents, least-scope OAuth, per-agent API keys with limits.

## §13 Social engineering
- Phishing review: sender domain vs brand, reply-to, link host (read only from headers; never click), look-alike domains.
- Callback/voice-clone scams: family code word; bank never asks for codes.
- Distinguish a reported breach from evidence that the account was used.

## §14 Detection & resilience
- Are security alerts read? (Unread alerts in an "Updates" tab are a detection gap.) Turn on alert forwarding to a watched inbox or phone.
- Backups: 3-2-1, one offline/immutable copy; test a restore. Google Takeout / iCloud export.
- Digital legacy: Google Inactive Account Manager, Apple Legacy Contact, password-manager emergency kit.

## §15 Cadence
- Quick re-run monthly (alerts, linked apps, updates, new keys); full run quarterly and after any incident.
- Save `audit-state.json` next to the report. No secret values, only masked forms. Format:
  `{"date": "YYYY-MM-DD", "findings": [{"id": "F1", "area": 4, "title": "...", "label": "Found", "status": "Still open", "date": "YYYY-MM-DD"}]}`
  Keep each `id` the same across runs. On the next run: `local_audit.py diff OLD.json NEW.json` prints NEW, GONE, and CHANGED findings; show that list at the top of the new report.

## §16 Report spec (local HTML, private)
- Dark or light per user; mask identifiers (email `s***@domain`, phone last 2 digits, project IDs first/last 4).
- Header: date, scope, coverage % per dimension (checked / sampled / not checked).
- Scorecard: one tile per dimension, key number, status (Done / Still open / Not checked).
- "Do in 15 minutes" quick wins, then top 5 fixes by risk = likelihood × impact × exposure; show effort and reversibility.
- Per dimension: 2–3 headline numbers; findings with Affected · Evidence + date · Why · Fix (exact steps/commands) · What could break · Label; Confirmed vs Suspicion separated; "Your check" tip.
- "Checks that stopped me": reason + numbered user steps + official link.
- Approval table with F-numbers, who does it (agent/user), status; later "Changed" with verification evidence.
- Glossary of terms used (OAuth scope, passkey, SIM swap, prompt injection).
- Before saving: `local_audit.py scrub REPORT.html` (key shapes, full emails, full phone numbers; service senders like `no-reply@` are allowed). It exits 1 on any hit; zero hits required.
