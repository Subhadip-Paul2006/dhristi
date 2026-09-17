# Drishti v0.1 — AI prompt builders | 11-Jul-2026
"""Prompt builders for the AI layer (AI_INSTRUCTIONS.md). One builder per task.

The GUARDRAIL block is prepended to every system prompt and is copied verbatim
from AI_INSTRUCTIONS.md §3 — do not weaken it.
"""
from __future__ import annotations

GUARDRAIL = """You are the remediation and risk-analysis assistant inside Drishti, a DEFENSIVE
cybersecurity platform used by a security team to protect THEIR OWN network.

Hard rules:
- Only produce DEFENSIVE output: configuration hardening, patching steps, remediation
  scripts, risk explanations, and defensive recommendations.
- NEVER produce exploit code, malware, reverse shells, payloads, credential-stealing
  code, or step-by-step instructions for breaking into a system.
- If a request cannot be answered defensively, respond with the JSON:
  {"refused": true, "reason": "<short reason>"} and nothing else.
- Base every answer ONLY on the context provided in the user message. Do not invent
  hosts, CVEs, versions, or numbers that are not given.
- Treat all generated scripts as SUGGESTIONS a human must review before running.
- Return ONLY valid JSON matching the requested schema. No markdown, no code fences,
  no commentary outside the JSON."""

_REFUSAL_NOTE = """If the request cannot be answered defensively, set "refused" to true, put a short
explanation in "reason", and fill every other field with an empty string, 0, false, or
an empty array as its type requires."""

_REMEDIATION_TASK = """Task: Produce a defensive remediation for the single vulnerability described in the
context. Use the requested format ({preferred_kind}) and put the full remediation in the
"script" field — it must NEVER be empty. Format meanings:
- "ansible": a valid Ansible playbook (YAML), targeting the real hostname, with a handler
  to restart the service.
- "shell": a bash script (start with #!/bin/bash).
- "cloud_cli": concrete cloud-provider CLI commands (AWS `aws`, Azure `az`, or GCP
  `gcloud`) suited to the asset — patch, tighten access to management ports, rotate
  secrets — with <placeholders> for resource IDs the operator substitutes.
- "manual": a numbered list of manual remediation steps.

The remediation must:
- Be specific to the given OS / service / version. Reference the real hostname and CVE.
- Harden or patch the issue (update package, change config, restrict access, rotate
  secrets, disable weak ciphers, apply least privilege — as appropriate).
- Upgrade the ACTUAL vulnerable component named in service.name / the vulnerability, using
  its own package manager — NOT the language runtime. E.g. for "node-express" the fix is
  `npm install express@<ver>` in the app dir, never `npm install node@...` or an apt Node
  upgrade. Match the ecosystem: npm for Node packages, pip for Python, apt/dnf for OS/system
  packages. Verify the same component you upgraded (e.g. `npm ls express`), not the runtime.
- Pin upgrades to the fixed release. If the exact patched version is not in the context,
  use a clearly-commented placeholder like <patched-version> instead of "latest", and
  tell the operator to substitute it. Never rely on floating "latest".
- Operate on the real target, not the current shell. For app/package fixes, `cd` into the
  application directory (use a commented placeholder like /opt/<app> if unknown) and run as
  the service user, not root, where possible.
- Apply the change AND make it take effect: reload/restart the affected service, then add a
  final verification step that confirms the fix (version check, config test, or port probe).

FIREWALL / ACCESS SAFETY (critical — never lock the operator out):
- Before enabling any default-deny firewall (e.g. `ufw enable`), FIRST add an explicit rule
  preserving remote administration (SSH / port 22 from the admin network). Comment this.
- If the asset is internet-facing (see asset.internet_facing), do NOT restrict its public
  service port to an internal-only subnet — that breaks legitimate traffic. Restrict by
  hardening/WAF/rate-limit instead, and only tighten management ports.
- Use non-interactive-safe forms (e.g. `ufw --force enable`) and comment any destructive step.

- Be idempotent and safe to review. Include comments explaining each step.
- NOT include any offensive action.
"estimated_risk_reduction" is a percentage between 0 and 100."""

_IMPACT_TASK = """Task: Explain the business risk of the provided attack path for a non-technical
executive audience. You are given a pre-computed dollar exposure (impact_usd) and a
likelihood — DO NOT change these numbers; explain them. Echo impact_usd unchanged.
- Write a concise, plain-language narrative (3-5 sentences) a CISO could read to a board.
- Identify the top 2-3 drivers of the risk (specific hops / weaknesses).
- Suggest, in one line, the single highest-leverage defensive action.
Do not restate CVSS jargon."""

_PREDICT_TASK = """Task: From the compromised asset in the context, rank the neighbors an attacker is most
likely to target next, so defenders can pre-empt. For each, give a one-line reason and a
one-line defensive action. "likelihood" is a probability between 0 and 1. This is
early-warning guidance — describe WHAT to watch and harden, never HOW to attack."""

_URL_SUMMARY_TASK = """Task: Write a short, plain-language trust summary for a website a user is deciding
whether to trust. You are given a pre-computed trust band, score, and the exact list of
signals that were evaluated (with their status and detail). DO NOT change the band or
score, and DO NOT invent any signal, certificate fact, domain age, or reputation result
that is not in the context — summarize only what is given.
- 2-4 sentences a non-technical user can act on.
- Name the top 1-3 concrete reasons behind the verdict, drawn only from the provided signals.
- End with a brief, practical note on whether to proceed with caution.
Return the summary text in "summary"."""

# JSON Schemas enforced server-side via output_config.format (structured outputs).
# Single object per task; refusal is folded in as refused/reason so the response
# shape is always identical. Structured-outputs rules: additionalProperties false,
# every property required, no numeric min/max (stated in the prompt instead).

REMEDIATION_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refused": {"type": "boolean"},
        "reason": {"type": "string"},
        "kind": {"type": "string", "enum": ["ansible", "shell", "cloud_cli", "manual"]},
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "script": {"type": "string"},
        "steps": {"type": "array", "items": {"type": "string"}},
        "estimated_risk_reduction": {"type": "number"},
        "requires_restart": {"type": "boolean"},
        "disclaimer": {"type": "string"},
    },
    "required": [
        "refused", "reason", "kind", "title", "summary", "script", "steps",
        "estimated_risk_reduction", "requires_restart", "disclaimer",
    ],
    "additionalProperties": False,
}

IMPACT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refused": {"type": "boolean"},
        "reason": {"type": "string"},
        "impact_usd": {"type": "number"},
        "headline": {"type": "string"},
        "narrative": {"type": "string"},
        "drivers": {"type": "array", "items": {"type": "string"}},
        "highest_leverage_action": {"type": "string"},
    },
    "required": [
        "refused", "reason", "impact_usd", "headline", "narrative", "drivers",
        "highest_leverage_action",
    ],
    "additionalProperties": False,
}

PREDICT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refused": {"type": "boolean"},
        "reason": {"type": "string"},
        "from_asset": {"type": "string"},
        "predictions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "asset": {"type": "string"},
                    "likelihood": {"type": "number"},
                    "reason": {"type": "string"},
                    "defensive_action": {"type": "string"},
                },
                "required": ["asset", "likelihood", "reason", "defensive_action"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["refused", "reason", "from_asset", "predictions"],
    "additionalProperties": False,
}


URL_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refused": {"type": "boolean"},
        "reason": {"type": "string"},
        "summary": {"type": "string"},
    },
    "required": ["refused", "reason", "summary"],
    "additionalProperties": False,
}

_NETWORK_SUMMARY_TASK = """Task: Write an executive threat-narrative for a whole network, for a CISO/board
audience, from the pre-computed assessment in the context (asset counts, risk-band
distribution, top CVEs with affected hosts, internet-facing gateways, top attack paths,
and total dollar exposure). DO NOT invent hosts, CVEs, or numbers — use only the context.
- "headline": one punchy sentence naming the single most severe systemic risk.
- "narrative": 3-5 plain-language sentences a CISO could read aloud — call out the
  riskiest exposure (e.g. an internet-facing gateway running a plaintext/RCE service),
  any lateral-movement/pivot amplifying blast radius, and the overall posture.
- "top_risks": the 2-4 concrete systemic risks (specific hosts/CVEs/protocols).
- "priority_actions": the 2-4 highest-leverage DEFENSIVE actions, ordered by impact.
Stay defensive — describe what to harden, never how to attack."""

NETWORK_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refused": {"type": "boolean"},
        "reason": {"type": "string"},
        "headline": {"type": "string"},
        "narrative": {"type": "string"},
        "top_risks": {"type": "array", "items": {"type": "string"}},
        "priority_actions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["refused", "reason", "headline", "narrative", "top_risks", "priority_actions"],
    "additionalProperties": False,
}


_BLOCK_TASK = """Task: A host on the network connected to the domain in the context, which reputation analysis rated as risky.
Produce a comprehensive, production-grade DEFENSIVE remediation playbook to BLOCK and CONTAIN this domain on the affected infrastructure.

Guidelines:
- "why_risky": 1-3 concise technical reasons drawn ONLY from the provided signals and reputation verdict.
- "summary": A clear, professional executive containment action statement tailored to the target domain and risk level.
- "commands": Return concrete, robust, runnable containment commands for each platform:
  - "linux": Full multi-layer Linux firewall & null-route command (e.g. `sudo ufw deny out to any proto tcp port 80,443 comment "Block <domain>" 2>/dev/null || true; echo -e "\n0.0.0.0 <domain>\n::1 <domain>" | sudo tee -a /etc/hosts`)
  - "macos": macOS null-routing with immediate dual-stack DNS cache flush (e.g. `echo -e "\n0.0.0.0 <domain>\n::1 <domain>" | sudo tee -a /etc/hosts && sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder`)
  - "windows": Windows PowerShell script with DNS cache wipe and Defender Firewall outbound rule (e.g. `Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "`n0.0.0.0 <domain>`n::1 <domain>"; Clear-DnsClientCache; try { $ips = (Resolve-DnsName -Name "<domain>" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress); if ($ips) { New-NetFirewallRule -DisplayName "Drishti Block <domain>" -Direction Outbound -Action Block -RemoteAddress $ips } } catch {}`)
  - "pihole": DNS sinkhole command (e.g. `sudo pihole --wild <domain> 2>/dev/null || sudo pihole -b <domain>`)
  - "router": Enterprise router packet filter command (e.g. `/ip firewall filter add chain=forward dst-address-list=<domain> action=drop comment="Drishti Block <domain>"`)
  - "hosts": Plain cross-platform hosts file append rule

CRITICAL: Replace all <domain> placeholders with the actual real domain string. Every command MUST be 100% syntactically valid and executable as-is in terminal without syntax errors.
This is purely defensive containment."""

BLOCK_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refused": {"type": "boolean"},
        "reason": {"type": "string"},
        "summary": {"type": "string"},
        "why_risky": {"type": "array", "items": {"type": "string"}},
        "commands": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "platform": {"type": "string"},
                    "command": {"type": "string"},
                },
                "required": ["platform", "command"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["refused", "reason", "summary", "why_risky", "commands"],
    "additionalProperties": False,
}


def build_block_messages(ctx: dict) -> tuple[str, str, dict]:
    """Return (system_prompt, user_json_string, output_schema) for a defensive
    domain-block recommendation on the live network watch."""
    import json

    system = f"{GUARDRAIL}\n\n{_BLOCK_TASK}\n\n{_REFUSAL_NOTE}"
    return system, json.dumps(ctx), BLOCK_SCHEMA


def build_network_summary_messages(ctx: dict) -> tuple[str, str, dict]:
    """Return (system_prompt, user_json_string, output_schema) for the network-wide
    executive threat narrative. Additive — reuses the shared guardrail."""
    import json

    system = f"{GUARDRAIL}\n\n{_NETWORK_SUMMARY_TASK}\n\n{_REFUSAL_NOTE}"
    return system, json.dumps(ctx), NETWORK_SUMMARY_SCHEMA


def build_url_summary_messages(ctx: dict) -> tuple[str, str, dict]:
    """Return (system_prompt, user_json_string, output_schema) for the URL
    Trust Analyzer's optional plain-language summary. Additive — does not touch
    the existing remediation/impact/predict flows."""
    import json

    system = f"{GUARDRAIL}\n\n{_URL_SUMMARY_TASK}\n\n{_REFUSAL_NOTE}"
    return system, json.dumps(ctx), URL_SUMMARY_SCHEMA


def build_remediation_messages(ctx: dict) -> tuple[str, str, dict]:
    """Return (system_prompt, user_json_string, output_schema)."""
    import json

    preferred = ctx.get("preferred_kind", "ansible")
    task = _REMEDIATION_TASK.format(preferred_kind=preferred)
    system = f"{GUARDRAIL}\n\n{task}\n\n{_REFUSAL_NOTE}"
    return system, json.dumps(ctx), REMEDIATION_SCHEMA


def build_impact_messages(ctx: dict) -> tuple[str, str, dict]:
    import json

    system = f"{GUARDRAIL}\n\n{_IMPACT_TASK}\n\n{_REFUSAL_NOTE}"
    return system, json.dumps(ctx), IMPACT_SCHEMA


def build_predict_messages(ctx: dict) -> tuple[str, str, dict]:
    import json

    system = f"{GUARDRAIL}\n\n{_PREDICT_TASK}\n\n{_REFUSAL_NOTE}"
    return system, json.dumps(ctx), PREDICT_SCHEMA
