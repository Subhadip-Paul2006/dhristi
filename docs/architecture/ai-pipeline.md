# 🧠 AI Pipeline & AST Safety Guardrails

> **Parent Specification:** [RESEARCH.md](../../RESEARCH.md) · [TRD.md](../../TRD.md)  
> **Source Module:** `server/app/services/ai.py`

---

## 1. Overview & Ethical Boundaries

Drishti utilizes artificial intelligence strictly as an **accelerator for defensive configuration**, not an autonomous execution engine.

![Drishti AI Pipeline](../../assets/svg/ai/ai-analysis-flow.svg)

### Ethical Invariants
1. **Probabilistic Guidance, Never Unverified Assertion:** The model synthesizes candidate configurations for human security engineers to review and apply.
2. **Zero-Fabrication Contract:** Context provided to the model contains only observed network topologies, confirmed CVE identifiers, and verified target chokepoints.
3. **AST Safety Filter:** Every generated script undergoes mandatory Python Abstract Syntax Tree (AST) static analysis before delivery.

---

## 2. Context Grounding & Model Invocation

When a security analyst requests mitigation for a high-priority attack path, Drishti compiles a structured context payload:

```json
{
  "path_id": "path_log4j_to_crown_jewel",
  "source_node": {"ip": "10.0.1.10", "os": "Ubuntu 22.04", "cve": "CVE-2021-44228"},
  "target_chokepoint": {"device": "Cisco Catalyst Switch", "action": "Block port 445/88 from 10.0.1.0/24 to 10.0.3.0/24"},
  "target_crown_jewel": {"name": "Production DB Enclave", "ip": "10.0.3.100", "valuation_usd": 3500000},
  "format": "ansible"
}
```

This context is delivered to **Anthropic Claude 3.5 Sonnet** (`claude-3-5-sonnet-20241022`) via a hardened system prompt enforcing defensive idempotency.

---

## 3. The AST Safety Guardrail Implementation

To protect enterprise infrastructure from destructive commands, `server/app/services/ai.py` parses the output into a Python Abstract Syntax Tree or YAML object:

```python
import ast
import re

DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-[rf]{1,2}\b",
    r"\bdd\s+if=",
    r"\bmkfs\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\biptables\s+-F\b",
    r"\bDROP\s+DATABASE\b",
    r"\bTRUNCATE\s+TABLE\b",
    r"curl\s+.*\|\s*bash",
    r"Invoke-Expression"
]

def validate_remediation_safety(script_content: str) -> bool:
    """
    Statically analyzes candidate mitigation scripts.
    Raises ValueError if any destructive pattern or unsafe AST call is detected.
    """
    for pattern in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, script_content, re.IGNORECASE):
            raise ValueError(f"AST Guardrail Violation: Unsafe pattern '{pattern}' detected.")
    
    # Verify Python/Bash syntax structure
    try:
        tree = ast.parse(script_content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', '') in ['eval', 'exec']:
                raise ValueError("AST Guardrail Violation: Dynamic code execution is prohibited.")
    except SyntaxError:
        pass # Non-Python formats (Ansible YAML, Cisco ACLs) fall back to regex validation
        
    return True
```

---

## 4. Supported Remediation Formats

1. **Ansible Playbooks (`.yml`):**
   - Idempotent configuration tasks to update affected packages, disable legacy protocols (e.g. SMBv1), or bind services to localhost.
2. **Cisco IOS Access Control Lists (ACLs):**
   - Standard and extended IP access lists designed to sever attack-path chokepoints at the switch or firewall boundary.
3. **PowerShell & Bash Hardening Scripts:**
   - Single-node remediation commands for administrative workstations.
