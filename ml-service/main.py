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
        if not req.repositoryPath:
            raise HTTPException(400, "'repositoryPath' required for repo scan.")
        if not os.path.isdir(req.repositoryPath):
            raise HTTPException(400, f"Path does not exist: {req.repositoryPath}")

        logger.info(f"Scanning repository: {req.repositoryPath}")
        findings, files_scanned, total_files, lang_summary = scan_repository(req.repositoryPath)

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

    logger.info(
        f"Analysis complete — {len(findings)} findings across {files_scanned} files"
    )

    return AnalyzeResponse(
        findings=findings,
        filesScanned=files_scanned,
        totalFiles=total_files,
        languageSummary=lang_summary,
    )
