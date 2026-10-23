# Personal Security Audit

A read-only security review of one person's accounts, devices, API keys, and AI agents. It ends with a private local HTML report and a numbered list of fixes. Nothing changes until you approve a fix by its number.

It covers 14 areas: inventory, sign-in, recovery chain, delegated access (OAuth apps, AI agents, browser and IDE extensions, MCP servers), attacker leftovers, secrets, sharing, software, network, device, money, AI-agent risk, messages and phone scams, and detection and recovery.

## Two ways to use it

**1. Paste the prompt.** Copy `prompt.txt` into any AI assistant that can use your email, browser, or terminal. Fill in or delete the optional profile block at the end.

**2. Install the Claude Code skill.**

1. Copy the `personal-security-audit` folder into `~/.claude/skills/`.
2. Start Claude Code and ask for a security audit, or paste the prompt.

## The helper script

`personal-security-audit/scripts/local_audit.py` uses only the Python standard library. It is read-only. It never prints a secret: for a key it shows only the public format prefix (such as `ghp_`), the length, and a short hash, so one key is counted once.

```
python -I local_audit.py extensions          # browser extensions and risky permissions
python -I local_audit.py ide                 # VS Code / Cursor / Windsurf extensions
python -I local_audit.py configs             # secrets in AI-tool and MCP configs, .npmrc, environment
python -I local_audit.py secrets DIR [DIR..] # strict key-pattern scan (file paths only)
python -I local_audit.py osv [PYTHON_EXE..]  # installed Python packages against osv.dev (no install)
python -I local_audit.py history REPO [REPO..] # key patterns in all git history (types and counts only)
python -I local_audit.py network             # ports open to other machines
python -I local_audit.py device              # firewall, antivirus, disk encryption
python -I local_audit.py scrub REPORT.html   # report self-check: key shapes, full emails, full phones
python -I local_audit.py diff OLD.json NEW.json  # compare two audit-state.json files
python -I local_audit.py selftest
```

`ripgrep` (`rg`) makes the `secrets` scan much faster. Without it, the script walks the folders in Python.

## Limits

- The audit reads what the agent can reach. It reports each area as checked, sampled, or not checked. It never says you are "secure".
- `scrub` finds key shapes, full emails, and full phone numbers. It does not find names, domains, or folder paths. Read a report yourself before you share it.
- Pages that ask for your password are your step. The agent never types a password.

## Credit

The starting point was the six-area "Be my security reviewer" prompt from the video at youtube.com/watch?v=nXMlSq4aFBg. This version adds 8 areas, 22 commonly missed risks, and fixes from a real run.
