"""
RepoSentinel — Static Security Analysis Engine
FastAPI service. Receives a repository path or code snippet,
runs language-aware heuristic rules, returns structured findings.

This is a HEURISTIC / STATIC ANALYSIS engine — NOT machine learning.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("reposentinel.engine")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_FILE_SIZE_BYTES = 500_000        # skip files > 500 KB
MAX_FILES_PER_SCAN  = 500            # safety cap
MAX_SNIPPET_SIZE    = 200_000

IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", "coverage",
    "__pycache__", ".venv", "venv", "target", ".next",
    ".nuxt", "out", "vendor", ".idea", ".vscode",
}

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".js":  "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts":  "TypeScript",
    ".tsx": "TypeScript",
    ".py":  "Python",
    ".java":"Java",
}

# ── Pydantic models ───────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    repositoryPath: Optional[str] = None
    repositoryUrl: Optional[str] = None
    code: Optional[str] = None
    inputType: str = "repo"           # "repo" | "snippet"


class Finding(BaseModel):
    id: str
    type: str
    severity: str                     # CRITICAL HIGH MEDIUM LOW INFO
    confidence: float                 # 0.0 – 1.0  (heuristic, not calibrated ML)
    cwe: Optional[str]
    file: Optional[str]
    line: Optional[int]
    codeSnippet: str
    description: str
    impact: str
    recommendation: str
    language: Optional[str]


class AnalyzeResponse(BaseModel):
    findings: list[Finding]
    filesScanned: int
    totalFiles: int
    languageSummary: dict[str, int]
    repoInsights: Optional[dict] = None


# ── Rule definitions ──────────────────────────────────────────────────────────
# Each rule:
#   type, severity, cwe, confidence, description, impact, recommendation
#   patterns: list of (compiled_regex, optional_confidence_override)
#   languages: None = universal, or set of language names

RULES: list[dict] = [

    # ── SQL Injection ─────────────────────────────────────────────────────────
    {
        "type": "SQL Injection",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "confidence": 0.90,
        "description": "Unsanitized input is concatenated directly into a SQL query string.",
        "impact": "Attackers can read, modify, or delete database records, bypass authentication, or execute admin operations.",
        "recommendation": "Use parameterized queries or prepared statements. Never build SQL strings with string concatenation or f-strings.",
        "languages": None,
        "patterns": [
            # db.query("SELECT..." + variable)
            re.compile(r'(\.query|\.execute)\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)[^"\']*["\'\s]\s*\+', re.I),
            # Python cursor.execute with f-string
            re.compile(r'cursor\.execute\s*\(\s*f["\']', re.I),
            # Python cursor.execute("..." + var)
            re.compile(r'cursor\.execute\s*\(\s*["\'][^"\']*["\'\s]\s*\+', re.I),
            # SELECT ... WHERE ... + var (multi-word SQL)
            re.compile(r'["\']SELECT\s.{0,60}WHERE\s.{0,40}["\'\s]\s*\+\s*\w', re.I),
            # Java Statement.executeQuery("..." + var)
            re.compile(r'executeQuery\s*\(\s*["\'][^"\']*["\'\s]\s*\+', re.I),
        ],
    },

    # ── Cross-Site Scripting (XSS) ────────────────────────────────────────────
    {
        "type": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "confidence": 0.88,
        "description": "User-controlled data is written to the DOM without sanitization.",
        "impact": "Attackers can inject scripts to steal session cookies, redirect users, or perform actions on their behalf.",
        "recommendation": "Use textContent instead of innerHTML. Sanitize output with DOMPurify before rendering user content. Avoid document.write().",
        "languages": {"JavaScript", "TypeScript"},
        "patterns": [
            # element.innerHTML = variable (not a string literal)
            re.compile(r'\.innerHTML\s*=\s*(?!["\'\s]*[<`])\s*\w', re.I),
            # element.outerHTML = variable
            re.compile(r'\.outerHTML\s*=\s*(?!["\'\s]*<)\s*\w', re.I),
            # document.write(variable) — not write("")
            re.compile(r'document\.write\s*\(\s*(?!["\'])\w', re.I),
            # React dangerouslySetInnerHTML
            re.compile(r'dangerouslySetInnerHTML\s*=\s*\{', re.I),
            # jQuery $(el).html(variable) — not .html("literal")
            re.compile(r'\$\([^)]+\)\.html\s*\(\s*(?!["\'])\w', re.I),
        ],
    },

    # ── Hardcoded Secrets ─────────────────────────────────────────────────────
    {
        "type": "Hardcoded Secret",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "confidence": 0.82,
        "description": "A secret key, password, or credential appears to be hardcoded in source code.",
        "impact": "If code is pushed to a public repository or shared, credentials are permanently exposed.",
        "recommendation": "Move secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
        "languages": None,
        # Exclusion list — skip obvious placeholders
        "exclude_pattern": re.compile(
            r'(your[_\-]?|example|sample|test|dummy|fake|placeholder|changeme|<|>|\{|\}|xxx|todo|secret_here|password_here)',
            re.I
        ),
        "patterns": [
            # password = "realvalue" (min 6 chars, not a placeholder)
            re.compile(r'\b(password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']', re.I),
            # api_key / secret / token = "value"
            re.compile(r'\b(api_key|apikey|api_secret|auth_token|access_token|private_key|client_secret)\s*[:=]\s*["\'][^"\']{8,}["\']', re.I),
            # AWS access key pattern
            re.compile(r'\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b'),
            # Generic bearer/secret token in strings (high entropy, 32+ chars)
            re.compile(r'["\'][A-Za-z0-9+/]{32,}={0,2}["\']'),
        ],
    },

    # ── Command Injection ─────────────────────────────────────────────────────
    {
        "type": "Command Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "confidence": 0.87,
        "description": "Unsanitized user input is passed to a shell command execution function.",
        "impact": "An attacker can execute arbitrary OS commands with the privileges of the server process.",
        "recommendation": "Avoid shell=True. Use subprocess with an argument list. Validate and whitelist inputs. Use shlex.quote() if shell is unavoidable.",
        "languages": None,
        "patterns": [
            # Python os.system with concatenation or f-string
            re.compile(r'\bos\.system\s*\(\s*(f["\']|["\'][^"\']*["\'\s]*\+)', re.I),
            # subprocess with shell=True and a variable
            re.compile(r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\)', re.I),
            # subprocess.call/run with string concat (not a list)
            re.compile(r'subprocess\.(call|run)\s*\(\s*["\'][^"\']*["\'\s]*\+\s*\w', re.I),
            # Java Runtime.exec with concatenation
            re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', re.I),
            # JS child_process.exec/execSync with template literal or concat
            re.compile(r'(child_process\.)?(exec|execSync)\s*\(\s*[`"\'][^`"\']*\$\{', re.I),
            re.compile(r'(child_process\.)?(exec|execSync)\s*\(\s*["\'][^"\']*["\'\s]*\+\s*\w', re.I),
        ],
    },

    # ── Path Traversal ────────────────────────────────────────────────────────
    {
        "type": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "confidence": 0.82,
        "description": "A filesystem operation uses a path influenced by user-controlled input.",
        "impact": "An attacker could read arbitrary server files including config files or private keys.",
        "recommendation": "Validate and canonicalize file paths. Verify the resolved path stays within the intended directory.",
        "languages": None,
        "patterns": [
            # readFile(req.query.x) / readFile(req.params.x)
            re.compile(r'\b(readFile|readFileSync|createReadStream|sendFile)\s*\(\s*(req\.|request\.)(query|params|body)\b', re.I),
            # path.join(..., req.params.x)
            re.compile(r'path\.join\s*\([^)]*\b(req|request)\.(query|params|body)\b', re.I),
            # Python open(request.args / request.form)
            re.compile(r'\bopen\s*\([^)]*\b(request\.(args|form|values|data)|input\(\))\b', re.I),
            # os.path.join with user/input/param keyword (Python)
            re.compile(r'os\.path\.join\s*\([^)]*\b(user_input|user_file|filename|filepath)\b', re.I),
            # Java new File(request.getParameter)
            re.compile(r'new\s+File\s*\([^)]*request\.getParameter', re.I),
        ],
    },

    # ── Insecure Deserialization ──────────────────────────────────────────────
    {
        "type": "Insecure Deserialization",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "confidence": 0.92,
        "description": "A known insecure deserialization function is called.",
        "impact": "Deserializing untrusted data can lead to remote code execution or privilege escalation.",
        "recommendation": "Use yaml.safe_load(). Avoid pickle for untrusted data. Prefer JSON.",
        "languages": None,
        "patterns": [
            re.compile(r'\bpickle\.loads?\s*\(', re.I),
            # yaml.load without safe Loader argument
            re.compile(r'\byaml\.load\s*\([^)]+\)(?!\s*#\s*safe)', re.I),
            # PHP unserialize($var)
            re.compile(r'\bunserialize\s*\(\s*\$\w+', re.I),
            # Java ObjectInputStream
            re.compile(r'\bnew\s+ObjectInputStream\s*\(', re.I),
            re.compile(r'\.readObject\s*\(\s*\)', re.I),
        ],
    },

    # ── Insecure Randomness (context-sensitive only) ──────────────────────────
    {
        "type": "Insecure Randomness",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "confidence": 0.72,
        "description": "A weak PRNG is used in a security-sensitive context (token, session, password generation).",
        "impact": "Predictable values allow attackers to guess session tokens or password reset links.",
        "recommendation": "Use crypto.randomBytes() in Node.js, secrets module in Python, SecureRandom in Java.",
        "languages": None,
        "patterns": [
            # Math.random() on same line as security-sensitive identifier
            re.compile(r'(token|sessionId|csrf|nonce|salt|otp)[^;{]*Math\.random\(\)', re.I),
            re.compile(r'Math\.random\(\)[^;{]*(token|sessionId|csrf|nonce|salt|otp)', re.I),
            # Python random.random()/randint in security context
            re.compile(r'(token|session|password|secret)\s*=.*\brandom\.(random|randint|choice)\(', re.I),
        ],
    },

    # ── eval() / Code Injection ───────────────────────────────────────────────
    {
        "type": "Code Injection via eval()",
        "severity": "CRITICAL",
        "cwe": "CWE-95",
        "confidence": 0.88,
        "description": "eval() or equivalent dynamic code execution is called with a non-literal argument.",
        "impact": "An attacker who controls the input can execute arbitrary code in the application context.",
        "recommendation": "Eliminate eval(). Use JSON.parse() for data. If dynamic code is unavoidable, use a sandboxed runtime.",
        "languages": {"JavaScript", "TypeScript", "Python"},
        "patterns": [
            # JS/TS: eval(variable) — not eval("literal")
            re.compile(r'\beval\s*\(\s*(?!["\'`])\w', re.I),
            # JS: new Function(variable)  — e.g. new Function(userInput)
            re.compile(r'\bnew\s+Function\s*\([^)]*\+', re.I),
            re.compile(r'\bnew\s+Function\s*\(\s*\w+\s*\)', re.I),
            # Python exec(variable) — not exec("literal")
            re.compile(r'\bexec\s*\(\s*(?!["\'])[a-zA-Z_]\w*\s*\)', re.I),
        ],
    },

    # ── Open Redirect ─────────────────────────────────────────────────────────
    {
        "type": "Open Redirect",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "confidence": 0.75,
        "description": "A redirect uses a URL from user-controlled input without validation.",
        "impact": "Attackers can craft phishing links that appear to come from a trusted domain.",
        "recommendation": "Validate redirect targets against a whitelist. Never redirect to user-supplied URLs directly.",
        "languages": {"JavaScript", "TypeScript", "Python"},
        "patterns": [
            # Express res.redirect(req.query.x)
            re.compile(r'\bres\.redirect\s*\(\s*(req\.|request\.)(query|params|body)\b', re.I),
            # Flask redirect(request.args.get(...))
            re.compile(r'\bredirect\s*\(\s*request\.(args|form|values)\.get\b', re.I),
            # window.location = req param
            re.compile(r'window\.location\s*(?:\.href)?\s*=\s*(req\.|request\.)(query|params)', re.I),
        ],
    },

    # ── Sensitive Data in Logs ────────────────────────────────────────────────
    {
        "type": "Sensitive Data in Logs",
        "severity": "LOW",
        "cwe": "CWE-532",
        "confidence": 0.65,
        "description": "A password, token, or secret appears to be passed to a logging function.",
        "impact": "Log files may be stored insecurely, exposing credentials to anyone with log access.",
        "recommendation": "Never log passwords, tokens, or credentials. Mask or omit sensitive fields.",
        "languages": None,
        "patterns": [
            # console.log / logger.info / print with password/token/secret variable nearby
            re.compile(r'(console\.(log|info|debug|error|warn)|logger\.(info|debug|warn|error))\s*\([^)]{0,80}(password|passwd|token|secret|api_key|apikey)\b', re.I),
            re.compile(r'\bprint\s*\([^)]{0,80}(password|passwd|token|secret)\b', re.I),
        ],
    },
]

# ── Fingerprint for deduplication ─────────────────────────────────────────────

def fingerprint(rule_type: str, file_path: str, line_no: int) -> str:
    raw = f"{rule_type}::{file_path}::{line_no}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


# ── Core scanner ──────────────────────────────────────────────────────────────

def scan_lines(
    lines: list[str],
    language: str,
    file_path: str,
) -> list[dict]:
    """Scan a list of source code lines and return raw finding dicts."""
    results = []
    seen_fingerprints: set[str] = set()

    for rule in RULES:
        # Skip language-specific rules that don't apply
        if rule["languages"] and language not in rule["languages"]:
            continue

        exclude = rule.get("exclude_pattern")

        for line_no, line_text in enumerate(lines, start=1):
            # Skip blank lines and pure comments early
            stripped = line_text.strip()
            if not stripped or stripped.startswith(("//", "#", "*", "/*")):
                continue

            for pattern in rule["patterns"]:
                if pattern.search(line_text):
                    # Apply exclusion filter (e.g. placeholder secrets)
                    if exclude and exclude.search(line_text):
                        break

                    fp = fingerprint(rule["type"], file_path, line_no)
                    if fp in seen_fingerprints:
                        break
                    seen_fingerprints.add(fp)

                    results.append({
                        "id": str(uuid.uuid4()),
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "cwe": rule["cwe"],
                        "file": file_path,
                        "line": line_no,
                        "codeSnippet": line_text.strip()[:300],
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "recommendation": rule["recommendation"],
                        "language": language,
                    })
                    break  # one match per rule per line

    return results


def scan_file(file_path: str, repo_root: str) -> tuple[list[dict], str | None]:
    """Read a file and scan it. Returns (findings, language)."""
    ext = Path(file_path).suffix.lower()
    language = LANGUAGE_EXTENSIONS.get(ext)
    if not language:
        return [], None

    try:
        size = os.path.getsize(file_path)
        if size > MAX_FILE_SIZE_BYTES:
            logger.debug(f"Skipping large file: {file_path} ({size} bytes)")
            return [], language

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Relative path for display
        rel_path = os.path.relpath(file_path, repo_root)
        return scan_lines(lines, language, rel_path), language

    except Exception as e:
        logger.warning(f"Could not read {file_path}: {e}")
        return [], language


def scan_repository(repo_path: str) -> tuple[list[dict], int, int, dict]:
    """Walk a repository directory, scan supported files."""
    all_findings: list[dict] = []
    language_summary: dict[str, int] = {}
    total_files = 0
    files_scanned = 0
    global_seen: set[str] = set()  # cross-file deduplication by fingerprint

    for root, dirs, files in os.walk(repo_path):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for fname in files:
            total_files += 1
            if files_scanned >= MAX_FILES_PER_SCAN:
                continue

            fpath = os.path.join(root, fname)
            findings, language = scan_file(fpath, repo_path)

            if language:
                files_scanned += 1
                language_summary[language] = language_summary.get(language, 0) + 1

            for f in findings:
                fp = fingerprint(f["type"], f["file"], f["line"])
                if fp not in global_seen:
                    global_seen.add(fp)
                    all_findings.append(f)

    return all_findings, files_scanned, total_files, language_summary


def scan_snippet(code: str) -> list[dict]:
    """Scan a raw code snippet (language unknown — run all rules)."""
    lines = code.splitlines()
    results = []
    seen: set[str] = set()

    for rule in RULES:
        for line_no, line_text in enumerate(lines, start=1):
            for pattern in rule["patterns"]:
                if pattern.search(line_text):
                    fp = fingerprint(rule["type"], "snippet", line_no)
                    if fp in seen:
                        break
                    seen.add(fp)
                    results.append({
                        "id": str(uuid.uuid4()),
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "cwe": rule["cwe"],
                        "file": None,
                        "line": line_no,
                        "codeSnippet": line_text.strip()[:300],
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "recommendation": rule["recommendation"],
                        "language": None,
                    })
                    break

    return results


# ── Repo Insights Extraction ──────────────────────────────────────────────────

import json

# ── 1. Dependency Audit ───────────────────────────────────────────────────────

def _parse_package_json(path: str) -> list[dict]:
    """Parse npm dependencies from package.json."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        deps = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in (data.get(section) or {}).items():
                deps.append({
                    "name": name,
                    "version": version,
                    "section": section,
                    "unpinned": version.startswith(("^", "~", ">", "*", "latest")),
                })
        return deps
    except Exception:
        return []


def _parse_requirements_txt(path: str) -> list[dict]:
    """Parse Python dependencies from requirements.txt."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                # e.g. requests==2.28.0 or requests>=2.0
                match = re.match(r'^([A-Za-z0-9_.\-]+)\s*([=<>!~].+)?$', line)
                if match:
                    name = match.group(1)
                    version = (match.group(2) or "").strip() or "unspecified"
                    deps.append({
                        "name": name,
                        "version": version,
                        "section": "dependencies",
                        "unpinned": not version.startswith("=="),
                    })
    except Exception:
        pass
    return deps


def _parse_pom_xml(path: str) -> list[dict]:
    """Parse Java dependencies from pom.xml (basic regex, no XML parser needed)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        # Extract <dependency> blocks
        blocks = re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL)
        for block in blocks:
            group = re.search(r'<groupId>(.*?)</groupId>', block)
            artifact = re.search(r'<artifactId>(.*?)</artifactId>', block)
            version = re.search(r'<version>(.*?)</version>', block)
            if group and artifact:
                ver = version.group(1).strip() if version else "unspecified"
                deps.append({
                    "name": f"{group.group(1).strip()}:{artifact.group(1).strip()}",
                    "version": ver,
                    "section": "dependencies",
                    "unpinned": "${" in ver or not ver or ver == "unspecified",
                })
    except Exception:
        pass
    return deps


def extract_dependencies(repo_path: str) -> dict:
    """Find and parse dependency files in the repo root and one level deep."""
    dep_files_found = []
    all_deps = []

    # Files to look for and their parsers
    PARSERS = {
        "package.json":    _parse_package_json,
        "requirements.txt": _parse_requirements_txt,
        "pom.xml":         _parse_pom_xml,
    }

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        depth = root.replace(repo_path, "").count(os.sep)
        if depth > 1:
            continue  # only look in root and one level deep

        for fname, parser in PARSERS.items():
            if fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, repo_path)
                parsed = parser(fpath)
                dep_files_found.append(rel)
                all_deps.extend(parsed)

    unpinned = [d for d in all_deps if d["unpinned"]]
    return {
        "depFiles": dep_files_found,
        "totalDependencies": len(all_deps),
        "unpinnedCount": len(unpinned),
        "unpinnedDeps": [d["name"] for d in unpinned[:20]],  # cap list
        "dependencies": all_deps[:100],  # cap for storage
    }


# ── 2. Repo Health Checklist ──────────────────────────────────────────────────

HEALTH_CHECKS = [
    # (id, label, description, files_or_dirs_that_pass)
    ("readme",       "README present",         "Project has a README file",                    ["README.md", "README.rst", "README.txt", "README"]),
    ("license",      "LICENSE present",         "Project has an open source license",           ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]),
    ("contributing", "CONTRIBUTING guide",      "Project has contribution guidelines",          ["CONTRIBUTING.md", "CONTRIBUTING.rst", "CONTRIBUTING"]),
    ("security",     "SECURITY policy",         "Project has a responsible disclosure policy",  ["SECURITY.md", "SECURITY.txt", ".github/SECURITY.md"]),
    ("ci",           "CI/CD configured",        "Continuous integration is set up",             [".github/workflows", ".travis.yml", "Jenkinsfile", ".circleci", ".gitlab-ci.yml", "azure-pipelines.yml"]),
    ("lockfile",     "Dependency lock file",    "Exact dependency versions are locked",         ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"]),
    ("tests",        "Test files present",      "Project has at least one test file",           ["test", "tests", "__tests__", "spec", "src/test"]),
    ("changelog",    "CHANGELOG present",       "Project maintains a changelog",                ["CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG", "CHANGES.md"]),
    ("dockerfile",   "Docker support",          "Project includes Docker configuration",        ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]),
    ("env_example",  ".env.example present",    "Environment variable template is documented",  [".env.example", ".env.sample", ".env.template"]),
]

def check_repo_health(repo_path: str) -> dict:
    """Check repo root for health indicator files/dirs."""
    all_entries = set()
    # Collect top-level entries
    try:
        for entry in os.listdir(repo_path):
            all_entries.add(entry)
            all_entries.add(entry.lower())
        # Also collect .github/ contents
        gh_path = os.path.join(repo_path, ".github")
        if os.path.isdir(gh_path):
            for entry in os.listdir(gh_path):
                all_entries.add(f".github/{entry}")
                all_entries.add(f".github/{entry.lower()}")
            wf_path = os.path.join(gh_path, "workflows")
            if os.path.isdir(wf_path):
                all_entries.add(".github/workflows")
    except Exception:
        pass

    checks = []
    passed = 0
    for check_id, label, description, indicators in HEALTH_CHECKS:
        hit = any(ind in all_entries or ind.lower() in all_entries for ind in indicators)
        checks.append({
            "id": check_id,
            "label": label,
            "description": description,
            "passed": hit,
        })
        if hit:
            passed += 1

    health_score = round((passed / len(HEALTH_CHECKS)) * 100)
    return {
        "score": health_score,
        "passed": passed,
        "total": len(HEALTH_CHECKS),
        "checks": checks,
    }


# ── 3. Accidental Sensitive File Detection ────────────────────────────────────

SENSITIVE_FILE_PATTERNS = [
    # .env files (actual, not examples)
    (re.compile(r'^\.env$', re.I),                  "Environment file (.env)",          "CRITICAL"),
    (re.compile(r'^\.env\.(local|prod|production|staging|live)$', re.I), "Production .env file", "CRITICAL"),
    # Private keys / certificates
    (re.compile(r'.*\.(pem|key|p12|pfx|jks|keystore)$', re.I), "Private key or certificate", "CRITICAL"),
    (re.compile(r'^id_rsa$|^id_dsa$|^id_ecdsa$|^id_ed25519$', re.I), "SSH private key", "CRITICAL"),
    # Credential files
    (re.compile(r'^credentials(\.json|\.yml|\.yaml|\.xml)?$', re.I), "Credentials file", "HIGH"),
    (re.compile(r'^(secrets|secret)(\.json|\.yml|\.yaml)?$', re.I),  "Secrets file",     "HIGH"),
    (re.compile(r'^auth(\.json|\.yml|\.yaml)?$', re.I),               "Auth config file", "HIGH"),
    # Cloud / service credentials
    (re.compile(r'^(service.?account|gcp.?key|aws.?credentials)(\.json)?$', re.I), "Cloud credential file", "CRITICAL"),
    (re.compile(r'^\.aws$', re.I),                  "AWS credentials directory",        "CRITICAL"),
    # Database dumps
    (re.compile(r'.*\.(sql|dump|bak|backup)$', re.I), "Database dump or backup file",  "HIGH"),
    # Password files
    (re.compile(r'^(passwords?|passwd)(\.txt|\.csv|\.json)?$', re.I), "Password file",  "CRITICAL"),
]

def detect_sensitive_files(repo_path: str) -> dict:
    """Walk repo tree looking for sensitive file names."""
    flagged = []
    seen_paths = set()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git"}]

        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, repo_path)

            if rel_path in seen_paths:
                continue

            for pattern, label, severity in SENSITIVE_FILE_PATTERNS:
                if pattern.match(fname):
                    seen_paths.add(rel_path)
                    flagged.append({
                        "file": rel_path,
                        "label": label,
                        "severity": severity,
                    })
                    break

    return {
        "flaggedFiles": flagged,
        "count": len(flagged),
        "hasCritical": any(f["severity"] == "CRITICAL" for f in flagged),
    }


# ── 4. Tech Stack Fingerprint ─────────────────────────────────────────────────

TECH_INDICATORS = {
    # Runtime / Language
    "Node.js":      [("file", "package.json")],
    "Python":       [("file", "requirements.txt"), ("file", "setup.py"), ("file", "pyproject.toml")],
    "Java":         [("file", "pom.xml"), ("file", "build.gradle")],
    "Go":           [("file", "go.mod")],
    "Ruby":         [("file", "Gemfile")],
    "PHP":          [("file", "composer.json")],
    "Rust":         [("file", "Cargo.toml")],
    # Frameworks (detected from package.json deps)
    "React":        [("dep", "react")],
    "Vue":          [("dep", "vue")],
    "Angular":      [("dep", "@angular/core")],
    "Next.js":      [("dep", "next")],
    "Express":      [("dep", "express")],
    "Fastify":      [("dep", "fastify")],
    "NestJS":       [("dep", "@nestjs/core")],
    "Django":       [("dep_txt", "Django"), ("dep_txt", "django")],
    "FastAPI":      [("dep_txt", "fastapi")],
    "Flask":        [("dep_txt", "Flask"), ("dep_txt", "flask")],
    "Spring":       [("dep_pom", "org.springframework")],
    # Databases
    "MongoDB":      [("dep", "mongoose"), ("dep", "mongodb")],
    "PostgreSQL":   [("dep", "pg"), ("dep", "postgres"), ("dep_txt", "psycopg2")],
    "MySQL":        [("dep", "mysql"), ("dep", "mysql2")],
    "Redis":        [("dep", "ioredis"), ("dep", "redis")],
    "SQLite":       [("dep", "better-sqlite3"), ("dep_txt", "sqlite3")],
    # Infra / tooling
    "Docker":       [("file", "Dockerfile"), ("file", "docker-compose.yml")],
    "Kubernetes":   [("file", "k8s"), ("ext_dir", "k8s")],
    "Webpack":      [("dep_dev", "webpack")],
    "Vite":         [("dep_dev", "vite")],
    "TypeScript":   [("dep_dev", "typescript"), ("file", "tsconfig.json")],
    "Jest":         [("dep_dev", "jest")],
    "ESLint":       [("dep_dev", "eslint")],
}

def detect_tech_stack(repo_path: str, dep_audit: dict) -> list[str]:
    """Detect technologies from file presence and dependency names."""
    detected = []

    # Collect top-level files/dirs
    try:
        top_entries = set(os.listdir(repo_path))
    except Exception:
        top_entries = set()

    # Collect dep names from audit
    all_dep_names = {d["name"].lower() for d in dep_audit.get("dependencies", [])}
    dev_dep_names = {
        d["name"].lower() for d in dep_audit.get("dependencies", [])
        if d.get("section") == "devDependencies"
    }

    for tech, indicators in TECH_INDICATORS.items():
        for kind, value in indicators:
            hit = False
            if kind == "file":
                hit = value in top_entries
            elif kind == "ext_dir":
                hit = any(e.lower() == value for e in top_entries)
            elif kind == "dep":
                hit = value.lower() in all_dep_names
            elif kind == "dep_dev":
                hit = value.lower() in dev_dep_names
            elif kind in ("dep_txt", "dep_pom"):
                hit = value.lower() in all_dep_names
            if hit:
                detected.append(tech)
                break

    return detected


# ── Master insights extractor ─────────────────────────────────────────────────

def extract_repo_insights(repo_path: str) -> dict:
    """Run all three insight extractors and return combined result."""
    dep_audit   = extract_dependencies(repo_path)
    health      = check_repo_health(repo_path)
    sensitive   = detect_sensitive_files(repo_path)
    tech_stack  = detect_tech_stack(repo_path, dep_audit)

    return {
        "dependencyAudit": dep_audit,
        "repoHealth":      health,
        "sensitiveFiles":  sensitive,
        "techStack":       tech_stack,
    }


# ── FastAPI app ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("RepoSentinel Static Analysis Engine ready.")
    yield


app = FastAPI(
    title="RepoSentinel Static Analysis Engine",
    version="2.0.0",
    description="Heuristic static analysis for security vulnerabilities. NOT a machine learning model.",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {"ok": True, "service": "reposentinel-engine"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    if req.inputType == "repo":
        temp_dir = None
        try:
            if req.repositoryUrl:
                # Clone the repo here on the engine
                import subprocess, tempfile, uuid
                temp_dir = os.path.join(tempfile.gettempdir(), f"reposentinel-{uuid.uuid4().hex}")
                os.makedirs(temp_dir, exist_ok=True)
                logger.info(f"Cloning {req.repositoryUrl}")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", "--single-branch", req.repositoryUrl, temp_dir],
                    capture_output=True, text=True, timeout=90
                )
                if result.returncode != 0:
                    raise HTTPException(400, f"Clone failed: {result.stderr[:200]}")
                repo_path = temp_dir
            elif req.repositoryPath:
                if not os.path.isdir(req.repositoryPath):
                    raise HTTPException(400, f"Path does not exist: {req.repositoryPath}")
                repo_path = req.repositoryPath
            else:
                raise HTTPException(400, "'repositoryUrl' or 'repositoryPath' required for repo scan.")

            logger.info(f"Scanning repository: {repo_path}")
            findings, files_scanned, total_files, lang_summary = scan_repository(repo_path)
            insights = extract_repo_insights(repo_path)
        finally:
            if temp_dir and os.path.isdir(temp_dir):
                import shutil
                try: shutil.rmtree(temp_dir)
                except: pass

    else:  # snippet
        if not req.code or not req.code.strip():
            raise HTTPException(400, "'code' must not be empty for snippet scan.")
        if len(req.code) > MAX_SNIPPET_SIZE:
            raise HTTPException(413, "Code snippet too large (max 200 KB).")

        logger.info("Scanning code snippet")
        findings = scan_snippet(req.code)
        files_scanned = 1
        total_files = 1
        lang_summary = {}
        insights = None

    logger.info(
        f"Analysis complete — {len(findings)} findings across {files_scanned} files"
    )

    return AnalyzeResponse(
        findings=findings,
        filesScanned=files_scanned,
        totalFiles=total_files,
        languageSummary=lang_summary,
        repoInsights=insights,
    )
