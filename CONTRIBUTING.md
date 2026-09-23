# 🤝 Contributing to Drishti

Thank you for your interest in contributing to **Drishti — AI-Powered Defensive Attack-Path Intelligence**.

We welcome pull requests from security researchers, network engineers, frontend designers, and data scientists. Because Drishti is deployed in high-security environments, all contributions must adhere to our **Defensive-Only Invariant** and **Zero-Fabrication Contract**.

---

## 1. Core Contribution Invariants

Before submitting code, ensure your contribution respects the following invariants:

1. **Defensive Only:** Under no circumstances will code containing automated exploit payloads, brute-force cracking tools, denial-of-service triggers, or unauthorized port floods be accepted.
2. **Zero-Fabrication Contract:** Never simulate or synthesize security telemetry, CVEs, or open ports when real data is missing. If telemetry is unavailable, output `UNAVAILABLE`.
3. **AST Guardrail Compliance:** Any PR modifying AI or script generation must ensure all synthesized playbooks continue to be validated via the AST safety filter.
4. **Credential Isolation:** Never commit `.env`, API keys, Telegram tokens, passwords, or test credentials.

---

## 2. Development Setup

### Prerequisites
- **Python:** 3.11+ (Backend)
- **Node.js:** 18+ or 20+ (Frontend)
- **Git**

### Step-by-Step Local Setup
```bash
# 1. Clone repository
git clone https://github.com/Subhadip-Paul2006/dhristi.git
cd dhristi

# 2. Setup Python backend virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r server/requirements.txt

# 3. Setup React web frontend
cd web
npm install
cd ..
```

---

## 3. Running Automated Tests

All tests must pass 100% before opening a Pull Request:

### Backend Test Suite (Pytest)
```bash
# Run all 408 unit and integration tests
pytest server/tests/ -v
```

### Frontend Test Suite (Vitest)
```bash
# Run all 82 frontend unit and component tests
cd web
npm test
```

### Frontend Typecheck & Build
```bash
# Ensure strict TypeScript compliance and production build success
cd web
npm run build
```

---

## 4. Git Workflow & Commit Conventions

We follow the **Conventional Commits** specification:

```text
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

### Allowed Types
- `feat`: A new user-facing feature or enhancement.
- `fix`: A bug fix or defect resolution.
- `docs`: Documentation changes only.
- `style`: Formatting, whitespace, semicolon changes.
- `refactor`: Code restructuring without functional alterations.
- `test`: Adding or correcting tests.
- `chore`: Tooling, dependency, or configuration updates.

### Examples
- `feat(paths): optimize Yen's k-shortest deviation loop for large digraphs`
- `fix(agent): handle missing WMI service gracefully on Windows Home`
- `docs(api): document new /api/paths/chokepoints response schema`

---

## 5. Branch Naming Standard

Create feature branches off `main`:
- `feature/<short-description>` (e.g. `feature/mincut-visualization`)
- `fix/<issue-description>` (e.g. `fix/bpf-permission-handling`)
- `docs/<doc-name>` (e.g. `docs/evaluator-guide-update`)

---

## 6. Pull Request Checklist

Before submitting a PR, verify:
- [ ] Code strictly follows defensive invariants (no attack tooling).
- [ ] Unit tests added for new services or components.
- [ ] All 408 backend tests pass (`pytest server/tests/`).
- [ ] All 82 frontend tests pass (`npm test --prefix web`).
- [ ] Frontend builds with zero TypeScript errors (`npm run build --prefix web`).
- [ ] Documentation updated where relevant.
- [ ] No secrets, tokens, or credentials committed.
