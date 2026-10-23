#!/usr/bin/env python3
"""Read-only local checks for the personal-security-audit skill.

Never prints a secret value: only a known format prefix, the length, and a short
hash so the same key can be counted once across files. Stdlib only.

  python -I local_audit.py extensions          # browser extensions + risky permissions
  python -I local_audit.py ide                 # VS Code / Cursor / Windsurf extensions
  python -I local_audit.py configs             # secrets in AI-tool/MCP configs, .npmrc, env
  python -I local_audit.py secrets DIR [DIR..] # strict key-pattern scan (file paths only)
  python -I local_audit.py osv [PYTHON_EXE..]  # installed Python packages vs osv.dev (no install)
  python -I local_audit.py history REPO [REPO..] # key patterns in all git history (types and counts only)
  python -I local_audit.py network             # listening ports open to other machines
  python -I local_audit.py device              # firewall, antivirus, disk encryption (or the user step)
  python -I local_audit.py scrub REPORT.html   # report self-check: key shapes, full emails, full phones
  python -I local_audit.py diff OLD.json NEW.json  # compare two audit-state.json files
  python -I local_audit.py selftest
"""
import datetime, hashlib, json, os, re, shutil, subprocess, sys, time, urllib.request

HOME = os.path.expanduser("~")
PLAT = sys.platform

# Strict shapes. Loose shapes (e.g. any "sk-" + 40 chars) caused many false hits in HTML pages.
PATTERNS = {
    "github_token": r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
    "anthropic": r"\bsk-ant-(api|admin)\d\d-[A-Za-z0-9_\-]{80,}",
    "openai": r"\bsk-(proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",
    "openrouter": r"\bsk-or-v1-[a-f0-9]{64}\b",
    "perplexity": r"\bpplx-[A-Za-z0-9]{48}\b",
    "xai": r"\bxai-[A-Za-z0-9]{70,}",
    "groq": r"\bgsk_[A-Za-z0-9]{50,}",
    "huggingface": r"\bhf_[A-Za-z0-9]{34}\b",
    "elevenlabs": r"\bsk_[a-f0-9]{48}\b",
    "google_api": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "google_oauth_secret": r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
    "aws_access_key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "stripe_live": r"\b(sk|rk)_live_[0-9a-zA-Z]{24,}",
    "slack": r"\bxox[bpas]-\d{8,}-[0-9A-Za-z\-]{10,}",
    "npm_token": r"\bnpm_[A-Za-z0-9]{36}\b",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
}
FIXTURE = re.compile(r"(?i)example|fake|dummy|test[_-]?key|xxxx|redacted|placeholder")
PREFIXES = ["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-ant-", "sk-proj-", "sk-svcacct-",
            "sk-or-v1-", "sk_live_", "sk_test_", "sk-", "sk_", "pplx-", "xai-", "gsk_", "hf_", "npm_",
            "AIza", "AKIA", "ASIA", "GOCSPX-", "BSA", "xox", "fig"]
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "site-packages", "__pycache__", ".cache", ".npm",
             "dist", "build", ".next", "AppData", "Library", ".Trash"}
PLACEHOLDER = re.compile(r"(?i)your|here|xxx|placeholder|example|changeme|<|\$\{|%[A-Z_]+%")


def mask(v):
    """Format prefix + length + hash. Never any character of the secret beyond a public format prefix."""
    v = str(v)
    pre = next((p for p in PREFIXES if v.startswith(p)), "")
    return f"{pre or 'unknown-format'}...len={len(v)} id={hashlib.sha256(v.encode()).hexdigest()[:8]}"


def classify(v):
    v = str(v or "")
    if not v or PLACEHOLDER.search(v) or len(v) < 12:
        return None
    return mask(v)


# ---------- browser extensions ----------
RISKY = {"debugger", "cookies", "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "management",
         "nativeMessaging", "webRequestBlocking", "userScripts", "clipboardRead", "history", "proxy"}


def browser_roots():
    if PLAT.startswith("win"):
        la = os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local"))
        return {"Chrome": os.path.join(la, "Google", "Chrome", "User Data"),
                "Edge": os.path.join(la, "Microsoft", "Edge", "User Data"),
                "Brave": os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data")}
    if PLAT == "darwin":
        a = os.path.join(HOME, "Library", "Application Support")
        return {"Chrome": os.path.join(a, "Google", "Chrome"), "Edge": os.path.join(a, "Microsoft Edge"),
                "Brave": os.path.join(a, "BraveSoftware", "Brave-Browser")}
    c = os.path.join(HOME, ".config")
    return {"Chrome": os.path.join(c, "google-chrome"), "Edge": os.path.join(c, "microsoft-edge"),
            "Brave": os.path.join(c, "BraveSoftware", "Brave-Browser")}


def ext_name(d, m):
    n = m.get("name", "")
    if n.startswith("__MSG_"):
        key = n[6:-2].lower()
        for loc in ("en", "en_US", "en_GB"):
            f = os.path.join(d, "_locales", loc, "messages.json")
            if os.path.exists(f):
                for k, v in json.load(open(f, encoding="utf-8-sig")).items():
                    if k.lower() == key:
                        return v.get("message", n)
    return n


def cmd_extensions():
    for browser, root in browser_roots().items():
        if not os.path.isdir(root):
            continue
        for prof in sorted(os.listdir(root)):
            pdir = os.path.join(root, prof)
            settings = {}
            for fn in ("Secure Preferences", "Preferences"):
                try:
                    s = json.load(open(os.path.join(pdir, fn), encoding="utf-8")).get("extensions", {}).get("settings", {})
                    for k, v in s.items():
                        settings.setdefault(k, v)
                except Exception:
                    pass
            edir = os.path.join(pdir, "Extensions")
            if not os.path.isdir(edir):
                continue
            print(f"== {browser} / {prof}")
            for eid in sorted(os.listdir(edir)):
                vers = sorted(os.listdir(os.path.join(edir, eid)))
                if not vers:
                    continue
                d = os.path.join(edir, eid, vers[-1])
                try:
                    m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8-sig"))
                except Exception:
                    continue
                st = settings.get(eid, {})
                enabled = not st.get("disable_reasons") and st.get("state", 1) == 1
                perms = set(map(str, (m.get("permissions") or []) + (m.get("host_permissions") or [])))
                perms |= {u for c in m.get("content_scripts") or [] for u in c.get("matches", [])}
                risky = sorted(p for p in perms if p in RISKY)
                print(f"{'ON ' if enabled else 'off'} | {ext_name(d, m)} | {m.get('version')} | {eid} | risky={','.join(risky) or '-'}")


# ---------- IDE extensions ----------
def cmd_ide():
    for label, d in [("VS Code", ".vscode"), ("VS Code Insiders", ".vscode-insiders"), ("Cursor", ".cursor"),
                     ("Windsurf", ".windsurf"), ("Antigravity", ".antigravity"), ("Kiro", ".kiro")]:
        f = os.path.join(HOME, d, "extensions", "extensions.json")
        if not os.path.exists(f):
            continue
        items = json.load(open(f, encoding="utf-8"))
        old = 0
        print(f"== {label}: {len(items)} extensions")
        for it in items:
            ident = it.get("identifier", {}).get("id", "?")
            meta = it.get("metadata") or {}
            # installedTimestamp is the local install/update date, not the marketplace release date.
            ts = meta.get("installedTimestamp")
            age = int((time.time() - ts / 1000) // 86400) if ts else None
            flag = " OLD>2y" if age is not None and age > 730 else ""
            old += bool(flag)
            print(f"  {ident} {it.get('version', '')} source={meta.get('source', '?')} "
                  f"publisherVerified={meta.get('isPublisherVerified', 'unknown')} installedDaysAgo={age if age is not None else '?'}{flag}")
        print(f"  installed more than 2 years ago: {old}")


# ---------- configs ----------
def config_files():
    j = lambda *p: os.path.join(HOME, *p)
    files = [j(".claude.json"), j(".claude", "settings.json"), j(".claude", "settings.local.json"),
             j(".cursor", "mcp.json"), j(".codeium", "windsurf", "mcp_config.json"), j(".gemini", "settings.json"),
             j(".kiro", "settings", "mcp.json"), j(".codex", "config.toml"), j(".npmrc"), j(".pypirc"),
             j(".docker", "config.json"), j(".config", "stripe", "config.toml"), j(".netrc"), j("_netrc"),
             j(".aws", "credentials"), j(".config", "gh", "hosts.yml")]
    if PLAT.startswith("win"):
        ad = os.environ.get("APPDATA", j("AppData", "Roaming"))
        files += [os.path.join(ad, "Claude", "claude_desktop_config.json"), os.path.join(ad, "Code", "User", "mcp.json"),
                  os.path.join(ad, "Cursor", "User", "mcp.json"),
                  os.path.join(os.environ.get("LOCALAPPDATA", ""), "ngrok", "ngrok.yml")]
    else:
        files += [j("Library", "Application Support", "Claude", "claude_desktop_config.json"),
                  j(".config", "ngrok", "ngrok.yml"), j("Library", "Application Support", "ngrok", "ngrok.yml")]
    return [f for f in files if os.path.isfile(f)]


KV = re.compile(r"""(?im)^[\s"']*([\w.\-/:]*(?:key|token|secret|password|auth)[\w.\-]*)["']?\s*[:=]\s*["']?([^"'\s,#]+)""")
ARGKEY = re.compile(r"(?i)--?[\w-]*(?:key|token)[\w-]*[= ]([^\s\"',\]]+)")


def cmd_configs():
    seen = {}
    for f in config_files():
        t = open(f, encoding="utf-8", errors="ignore").read()
        hits = [(m.group(1), m.group(2)) for m in KV.finditer(t)] + [("arg", m.group(1)) for m in ARGKEY.finditer(t)]
        for name, val in hits:
            c = classify(val)
            if c:
                hid = c.split("id=")[1]
                seen.setdefault(hid, []).append(f"{f} :: {name}")
                print(f"{f} | {name} | {c}")
    for k in os.environ:
        if re.search(r"(?i)(key|token|secret|password)$", k):
            c = classify(os.environ[k])
            if c:
                seen.setdefault(c.split("id=")[1], []).append(f"env :: {k}")
                print(f"environment | {k} | {c}")
    print(f"\nDISTINCT secrets: {len(seen)}  ENTRIES: {sum(map(len, seen.values()))}")
    for hid, where in seen.items():
        if len(where) > 1:
            print(f"  same secret id={hid} in {len(where)} places")
    for f in (os.path.join(HOME, ".codex", "config.toml"), os.path.join(HOME, ".claude", "settings.json")):
        if os.path.isfile(f):
            t = open(f, encoding="utf-8", errors="ignore").read()
            for pat in (r'approval_policy\s*=\s*"never"', r'danger-full-access', r'"bypassPermissions"',
                        r'skipDangerousModePermissionPrompt"\s*:\s*true', r'"defaultMode"\s*:\s*"(auto|bypassPermissions)"'):
                if re.search(pat, t):
                    print(f"AGENT-AUTONOMY {f}: matches {pat}")


# ---------- secrets scan ----------
def rg_path():
    for c in ("rg", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet", "Links", "rg.exe")):
        p = shutil.which(c) or (c if os.path.isfile(c) else None)
        if p:
            return p


def candidate_files(roots):
    rg = rg_path()
    if rg:
        cmd = [rg, "-l", "--no-messages", "--hidden", "-P", "--max-filesize", "2M"]
        for d in SKIP_DIRS:
            cmd += ["-g", f"!**/{d}/**"]
        cmd += ["(" + "|".join(PATTERNS.values()) + ")", "."]
        files = []
        # Run inside each root so the skip globs apply only below it (a root under AppData returned 0 files).
        for r in roots:
            out = subprocess.run(cmd, cwd=r, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
            files += [os.path.normpath(os.path.join(r, p)) for p in out.splitlines()]
        return files
    files = []  # ponytail: pure-Python walk is slow on big trees; install ripgrep if this is too slow
    for r in roots:
        for dp, dns, fns in os.walk(r):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            files += [os.path.join(dp, f) for f in fns]
    return files


def git_state(path):
    d = os.path.dirname(os.path.abspath(path))
    top = subprocess.run(["git", "-C", d, "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
    if not top:
        return "no-git", ""
    tracked = subprocess.run(["git", "-C", top, "ls-files", "--error-unmatch", os.path.abspath(path)],
                             capture_output=True).returncode == 0
    remote = subprocess.run(["git", "-C", top, "remote", "get-url", "origin"], capture_output=True, text=True).stdout.strip()
    return ("tracked" if tracked else "untracked"), re.sub(r"//[^@/]+@", "//", remote)


def scan_text(t):
    found = {}
    for k, p in PATTERNS.items():
        vals = {m.group(0) for m in re.finditer(p, t)}
        real = {v for v in vals if not FIXTURE.search(v)}
        if real:
            found[k] = real
    return found


def cmd_secrets(roots):
    total, ids = 0, set()
    for f in candidate_files(roots):
        if os.path.getsize(f) > 2_000_000:
            continue
        try:
            t = open(f, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        found = scan_text(t)
        if not found:
            continue
        total += 1
        g, remote = git_state(f)
        for k, vals in found.items():
            ids |= {hashlib.sha256(v.encode()).hexdigest()[:8] for v in vals}
            print(f"{k}\t{len(vals)}\t{g}\t{remote}\t{f}")
    print(f"\nFILES {total}  DISTINCT_VALUES {len(ids)}")


# ---------- OSV (Python) ----------
def cmd_osv(pythons):
    pythons = pythons or [sys.executable]
    for py in pythons:
        r = subprocess.run([py, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
                           capture_output=True, text=True)
        try:
            pkgs = json.loads(r.stdout)
        except Exception:
            print(f"== {py}: pip list failed")
            continue
        q = {"queries": [{"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]} for p in pkgs]}
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", json.dumps(q).encode(),
                                     {"Content-Type": "application/json"})
        res = json.load(urllib.request.urlopen(req, timeout=60))["results"]
        bad = [(p, r.get("vulns", [])) for p, r in zip(pkgs, res) if r.get("vulns")]
        print(f"== {py}: {len(pkgs)} packages, {len(bad)} with known advisories")
        for p, v in bad:
            print(f"  {p['name']}=={p['version']}  {len(v)} advisories: {', '.join(x['id'] for x in v[:5])}")


# ---------- git history ----------
def cmd_history(repos):
    for repo in repos:
        p = subprocess.Popen(["git", "-C", repo, "log", "-p", "--all", "--no-color"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
        found = {}
        for line in p.stdout:
            if line.startswith(("+", "-")):
                for k, vals in scan_text(line).items():
                    found.setdefault(k, set()).update(hashlib.sha256(v.encode()).hexdigest()[:8] for v in vals)
        p.wait()
        print(f"== {repo}: " + (", ".join(f"{k} {len(v)} distinct" for k, v in found.items()) or "no key patterns in history"))


# ---------- network ----------
AI_PORTS = {"11434": "Ollama", "1234": "LM Studio", "8188": "ComfyUI", "8888": "Jupyter", "7860": "Gradio", "3000": "dev server"}


def open_listeners(text):
    """Listening sockets bound to every interface, from `netstat -an` output (Windows, macOS, Linux)."""
    res = []
    for line in text.splitlines():
        if "LISTEN" not in line.upper():
            continue
        # The first address:port token is the local address; the second is the remote one.
        local = next((t for t in line.split() if re.match(r"^\S+[:.]\d+$", t)), "")
        m = re.match(r"^(0\.0\.0\.0|\[::\]|\*|::|:::)[:.](\d+)$", local)
        if m:
            res.append(m.group(2))
    return sorted(set(res), key=int)


def cmd_network():
    ports = open_listeners(subprocess.run(["netstat", "-an"], capture_output=True, text=True, errors="replace").stdout)
    print(f"Ports listening on all interfaces: {len(ports)}")
    for pt in ports:
        print(f"  {pt}" + (f"  <- {AI_PORTS[pt]} (no password by default)" if pt in AI_PORTS else ""))
    if PLAT.startswith("win"):
        print(subprocess.run(["powershell", "-NoProfile", "-c", "Get-NetConnectionProfile | ft Name,NetworkCategory -auto | Out-String"],
                             capture_output=True, text=True, errors="replace").stdout.strip())
    print("Match each port to its program and the firewall rules (checks.md §9).")


# ---------- device ----------
def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return (r.stdout or r.stderr).strip()


def cmd_device():
    if PLAT.startswith("win"):
        print(run(["netsh", "advfirewall", "show", "allprofiles", "state"]))
        print(run(["powershell", "-NoProfile", "-c", "Get-MpComputerStatus | fl AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Out-String"]))
        print(run(["powershell", "-NoProfile", "-c", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | ft displayName,productState -auto | Out-String"]))
        bl = run(["manage-bde", "-status", "C:"])
        print(bl if "Protection" in bl else "BitLocker: needs admin. User step: run `manage-bde -status` in an admin terminal.")
    elif PLAT == "darwin":
        print(run(["fdesetup", "status"]))
        print(run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]))
    else:
        print("User step: run `lsblk -o NAME,TYPE,FSTYPE` (look for crypt), `sudo ufw status`, and check the screen-lock setting.")


# ---------- report self-check ----------
EMAIL = re.compile(r"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"\(\d{3}\)\s?\d{3}-\d{4}|\b\d{3}[-.]\d{3}[-.]\d{4}\b|\+\d{10,14}\b")
SERVICE_SENDER = re.compile(r"(?i)^(no-?reply|security|support|alerts?)[\w.-]*@")


def scrub_text(t):
    hits = [f"key:{k}" for k, v in scan_text(t).items() for _ in v]
    hits += [f"email:{mask(e)}" for e in EMAIL.findall(t) if not SERVICE_SENDER.match(e)]
    hits += [f"phone:len={len(p)}" for p in PHONE.findall(t)]
    return hits


def cmd_scrub(path):
    hits = scrub_text(open(path, encoding="utf-8", errors="ignore").read())
    print(f"{path}: {len(hits)} hits" + "".join(f"\n  {h}" for h in hits))
    sys.exit(1 if hits else 0)


# ---------- state diff ----------
def state_diff(old, new):
    o = {f["id"]: f for f in old.get("findings", [])}
    n = {f["id"]: f for f in new.get("findings", [])}
    out = [f"NEW     {i} {n[i].get('title', '')}" for i in n if i not in o]
    out += [f"GONE    {i} {o[i].get('title', '')}" for i in o if i not in n]
    out += [f"CHANGED {i} {o[i].get('status')} -> {n[i].get('status')}" for i in n if i in o and o[i].get("status") != n[i].get("status")]
    return out


def cmd_diff(a, b):
    old, new = (json.load(open(p, encoding="utf-8")) for p in (a, b))
    print(f"{old.get('date')} -> {new.get('date')}")
    print("\n".join(state_diff(old, new)) or "no changes")


def selftest():
    assert mask("ghp_" + "a" * 36).startswith("ghp_...len=40")
    assert "abc" not in mask("abcdefghijklmnop")  # unknown format shows no characters
    assert classify("YOUR_API_KEY_HERE") is None and classify("") is None
    assert "github_token" in scan_text("x ghp_" + "A1b2" * 9 + " y")
    assert scan_text("AKIAIOSFODNN7EXAMPLE") == {}  # documented fixture filtered
    assert "openai" not in scan_text("sk-" + "a" * 60)  # loose shape no longer matches
    assert scrub_text("u***@example.com (555) ***-**00 no-reply@accounts.google.com") == []  # masked forms pass
    assert len(scrub_text("user@example.com (555) 555-0100 ghp_" + "A1b2" * 9)) == 3  # full forms fail
    assert open_listeners("  TCP    0.0.0.0:11434  0.0.0.0:0  LISTENING\n  TCP  127.0.0.1:5000  0.0.0.0:0  LISTENING\n"
                          "tcp6  0  0 :::8888  :::*  LISTEN\ntcp4 0 0 *.1234 *.* LISTEN") == ["1234", "8888", "11434"]
    d = state_diff({"findings": [{"id": "F1", "status": "Still open"}, {"id": "F2", "status": "Found"}]},
                   {"findings": [{"id": "F1", "status": "Changed"}, {"id": "F3", "status": "Found"}]})
    assert sorted(x.split()[0] for x in d) == ["CHANGED", "GONE", "NEW"]
    print("selftest ok")


if __name__ == "__main__":
    a = sys.argv[1:] or ["-h"]
    {"extensions": lambda: cmd_extensions(), "ide": lambda: cmd_ide(), "configs": lambda: cmd_configs(),
     "secrets": lambda: cmd_secrets(a[1:] or [HOME]), "osv": lambda: cmd_osv(a[1:]),
     "history": lambda: cmd_history(a[1:] or ["."]), "network": cmd_network, "device": cmd_device,
     "scrub": lambda: cmd_scrub(a[1]), "diff": lambda: cmd_diff(a[1], a[2]),
     "selftest": selftest}.get(a[0], lambda: print(__doc__))()
