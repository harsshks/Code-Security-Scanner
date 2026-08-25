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
            re.compile(r'(query|execute|exec)\s*\(\s*["\'].*?\+', re.I),
            re.compile(r'(query|execute|exec)\s*\(\s*f["\']', re.I),
            re.compile(r'SELECT\s.+FROM\s.+WHERE\s.+["\'\s]\s*\+', re.I),
            re.compile(r'(cursor\.execute|db\.query|connection\.query)\s*\(.*?%\s*\(', re.I),
            re.compile(r'(cursor\.execute|db\.query|\.query)\s*\(\s*["\'].*?\+\s*\w+', re.I),
            re.compile(r'Statement\(\)\s*;\s*\w+\.execute\s*\(.*?\+', re.I),  # Java
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
            re.compile(r'innerHTML\s*=\s*(?!["\'\s]*<)', re.I),
            re.compile(r'outerHTML\s*=\s*(?!["\'\s]*<)', re.I),
            re.compile(r'document\.write\s*\(', re.I),
            re.compile(r'dangerouslySetInnerHTML\s*=\s*\{', re.I),
            re.compile(r'\.html\s*\(\s*(?!["\'])', re.I),
        ],
    },

    # ── Hardcoded Secrets ─────────────────────────────────────────────────────
    {
        "type": "Hardcoded Secret",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "confidence": 0.82,
        "description": "A secret key, password, or credential appears to be hardcoded in source code.",
        "impact": "If code is pushed to a public repository or shared, credentials are permanently exposed and cannot be safely rotated without a code change.",
        "recommendation": "Move secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
        "languages": None,
        "patterns": [
            # password = "something" (not placeholders)
            re.compile(r'(?i)\b(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\'](?!.*(?:your|example|test|change|placeholder|<|>|\{|\}))', re.I),
            # secret / api_key / token assignments
            re.compile(r'(?i)\b(secret|api_key|apikey|auth_token|access_token|private_key)\s*=\s*["\'][^"\']{8,}["\']'),
            # AWS-style keys
            re.compile(r'(?i)(AKIA|ASIA)[A-Z0-9]{16}'),
            # Generic high-entropy strings assigned to credential names
            re.compile(r'(?i)\b(token|key|secret|credential)\s*[:=]\s*["\'][A-Za-z0-9/+_\-]{20,}["\']'),
        ],
    },

    # ── Command Injection ─────────────────────────────────────────────────────
    {
        "type": "Command Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "confidence": 0.85,
        "description": "Unsanitized user input is passed to a shell command execution function.",
        "impact": "An attacker can execute arbitrary operating system commands with the privileges of the server process.",
        "recommendation": "Avoid shell=True. Validate and whitelist all inputs. Use subprocess with argument lists, not strings. Use shlex.quote() if shell invocation is unavoidable.",
        "languages": None,
        "patterns": [
            re.compile(r'os\.system\s*\(\s*[^"\'\)]*[\+\%]', re.I),
            re.compile(r'os\.system\s*\(\s*f["\']', re.I),
            re.compile(r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', re.I),
            re.compile(r'subprocess\.(call|run)\s*\(\s*[^"\'\[)]*[\+\%]', re.I),
            re.compile(r'(shell_exec|passthru|system)\s*\(\s*\$', re.I),  # PHP
            re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(.*?\+', re.I),  # Java
            re.compile(r'exec\s*\(\s*[`\$]', re.I),  # JS template literals
        ],
    },

    # ── Path Traversal ────────────────────────────────────────────────────────
    {
        "type": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "confidence": 0.80,
        "description": "A file system operation uses a path that may be influenced by user-controlled input.",
        "impact": "An attacker could read arbitrary files on the server, including configuration files, private keys, or /etc/passwd.",
        "recommendation": "Validate and canonicalize file paths. Use path.resolve() and verify the result is within the intended base directory. Never trust user-supplied paths directly.",
        "languages": None,
        "patterns": [
            re.compile(r'(readFile|createReadStream|open|sendFile)\s*\(\s*(req\.|request\.|params\.|query\.|body\.)', re.I),
            re.compile(r'path\.join\s*\([^)]*req\.', re.I),
            re.compile(r'os\.path\.(join|open)\s*\([^)]*(?:request|input|user|param)', re.I),
            re.compile(r'\.\./.*\.\./'),  # literal traversal sequences
        ],
    },

    # ── Insecure Deserialization ──────────────────────────────────────────────
    {
        "type": "Insecure Deserialization",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "confidence": 0.92,
        "description": "A known insecure deserialization function is called.",
        "impact": "Deserializing untrusted data can lead to remote code execution, denial of service, or privilege escalation.",
        "recommendation": "Use yaml.safe_load() instead of yaml.load(). Avoid pickle for untrusted data. Prefer JSON. If using Java, avoid ObjectInputStream on untrusted streams.",
        "languages": None,
        "patterns": [
            re.compile(r'\bpickle\.loads?\s*\(', re.I),
            re.compile(r'\byaml\.load\s*\([^)]+\)(?!\s*#.*safe)', re.I),
            re.compile(r'\bunserialize\s*\(\s*\$', re.I),  # PHP
            re.compile(r'ObjectInputStream\s*\(', re.I),   # Java
            re.compile(r'readObject\s*\(\s*\)', re.I),     # Java
        ],
    },

    # ── Insecure Randomness (context-sensitive) ───────────────────────────────
    {
        "type": "Insecure Randomness",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "confidence": 0.70,
        "description": "A non-cryptographic PRNG is used in a context that appears security-sensitive (token, session, password, auth).",
        "impact": "Predictable random values can allow attackers to guess session tokens, password reset links, or CSRF tokens.",
        "recommendation": "Use crypto.randomBytes() or crypto.getRandomValues() in JS/TS. Use the secrets module in Python. Use SecureRandom in Java.",
        "languages": None,
        "patterns": [
            # Only flag Math.random when near security-sensitive keywords
            re.compile(r'(token|session|password|secret|auth|csrf|nonce|key).*Math\.random\(\)', re.I),
            re.compile(r'Math\.random\(\).*(token|session|password|secret|auth|csrf|nonce|key)', re.I),
            re.compile(r'random\.random\(\).*(token|session|password|secret|auth)', re.I),
            re.compile(r'(token|password|secret).*random\.random\(\)', re.I),
            re.compile(r'\bnew Random\(\).*\.(next|generate)', re.I),
        ],
    },

    # ── Eval / Code Injection ─────────────────────────────────────────────────
    {
        "type": "Code Injection via eval()",
        "severity": "CRITICAL",
        "cwe": "CWE-95",
        "confidence": 0.88,
        "description": "eval() or equivalent dynamic code execution is called with a non-literal argument.",
        "impact": "An attacker who controls the input can execute arbitrary code in the application's context.",
        "recommendation": "Eliminate eval() entirely. Use JSON.parse() for data, or structured configuration. If dynamic code is unavoidable, use a sandboxed runtime.",
        "languages": {"JavaScript", "TypeScript", "Python"},
        "patterns": [
            re.compile(r'\beval\s*\(\s*(?!["\'])', re.I),
            re.compile(r'\bexec\s*\(\s*(?!["\'])[^)]+\)', re.I),
            re.compile(r'\bnew\s+Function\s*\(', re.I),  # JS
            re.compile(r'compile\s*\(\s*(?!["\'])', re.I),  # Python
        ],
    },

    # ── Open Redirect ─────────────────────────────────────────────────────────
    {
        "type": "Open Redirect",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "confidence": 0.72,
        "description": "A redirect uses a URL derived from user-controlled input without validation.",
        "impact": "Attackers can craft links that redirect users to malicious sites while appearing to originate from a trusted domain (phishing).",
        "recommendation": "Validate redirect targets against a whitelist of allowed domains. Never redirect to user-supplied URLs directly.",
        "languages": {"JavaScript", "TypeScript", "Python"},
        "patterns": [
            re.compile(r'res\.redirect\s*\(\s*(req\.|request\.)', re.I),
            re.compile(r'redirect\s*\(\s*(request\.|req\.)', re.I),
            re.compile(r'window\.location\s*=\s*(?!["\'])', re.I),
            re.compile(r'location\.href\s*=\s*(req\.|request\.|params\.|query\.)', re.I),
        ],
    },

    # ── Sensitive Data Logging ────────────────────────────────────────────────
    {
        "type": "Sensitive Data in Logs",
        "severity": "LOW",
        "cwe": "CWE-532",
        "confidence": 0.65,
        "description": "Password, token, or secret appears to be logged.",
        "impact": "Log files may be stored insecurely or transmitted to logging services, exposing sensitive data.",
        "recommendation": "Never log passwords, tokens, or credentials. Mask or omit sensitive fields before logging.",
        "languages": None,
        "patterns": [
            re.compile(r'(console\.(log|info|debug|error)|logger\.(info|debug|warn|error)|print)\s*\([^)]*(?:password|passwd|token|secret|api_key)', re.I),
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

        for line_no, line_text in enumerate(lines, start=1):
            for pattern in rule["patterns"]:
                if pattern.search(line_text):
                    fp = fingerprint(rule["type"], file_path, line_no)
                    if fp in seen_fingerprints:
                        break  # deduplicate same rule+file+line
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
