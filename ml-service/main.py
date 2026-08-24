"""
Python ML Microservice — Code Security Analyzer
FastAPI app with heuristic + transformer-based vulnerability detection.

Detects:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Hardcoded Secrets / Credentials
"""

from __future__ import annotations

import re
import logging
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ml-service")

# ── Pydantic models ───────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    code: str
    inputType: Optional[str] = "code"


class Vulnerability(BaseModel):
    type: str
    severity: str          # Low | Medium | High
    line: Optional[int]
    description: str
    suggestedFix: str
    snippet: str


class AnalyzeResponse(BaseModel):
    vulnerabilities: list[Vulnerability]
    riskScore: float       # 0-100


# ── Heuristic rules ───────────────────────────────────────────────────────────

RULES: list[dict] = [
    # SQL Injection
    {
        "type": "SQL Injection",
        "severity": "High",
        "patterns": [
            re.compile(r'(query|execute|exec)\s*\(\s*["\'].*?\+', re.IGNORECASE),
            re.compile(r'(query|execute|exec)\s*\(\s*f["\']', re.IGNORECASE),
            re.compile(r'SELECT\s.+FROM\s.+WHERE\s.+["\'\s]\s*\+', re.IGNORECASE),
            re.compile(r'(cursor\.execute|db\.query|connection\.query)\s*\(.*%s', re.IGNORECASE),
            re.compile(r'(cursor\.execute|db\.query)\s*\(\s*["\'].*?\+\s*\w+', re.IGNORECASE),
        ],
        "description": "Unsanitized user input concatenated directly into a SQL query, enabling injection attacks.",
        "suggestedFix": "Use parameterized queries or a prepared statement. Never concatenate user input into SQL strings directly.",
    },
    # XSS
    {
        "type": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "patterns": [
            re.compile(r'innerHTML\s*=\s*(?![\s]*["\'])', re.IGNORECASE),
            re.compile(r'document\.write\s*\(', re.IGNORECASE),
            re.compile(r'dangerouslySetInnerHTML', re.IGNORECASE),
            re.compile(r'eval\s*\(\s*\w+', re.IGNORECASE),
            re.compile(r'\.html\s*\(\s*(?![\s]*["\'])', re.IGNORECASE),
        ],
        "description": "Unescaped user-controlled data rendered into the DOM, allowing script injection.",
        "suggestedFix": "Sanitize all user input before rendering. Use textContent instead of innerHTML, or a library like DOMPurify.",
    },
    # Hardcoded Secrets
    {
        "type": "Hardcoded Secret",
        "severity": "High",
        "patterns": [
            re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'),
            re.compile(r'(?i)(secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{6,}["\']'),
            re.compile(r'(?i)(aws_secret_access_key|aws_access_key_id)\s*=\s*["\'][^"\']{10,}["\']'),
            re.compile(r'(?i)(private_key|privatekey)\s*=\s*["\'][^"\']{10,}["\']'),
            re.compile(r'["\']?[A-Za-z0-9/+]{40}["\']?'),  # generic long base64-like token
        ],
        "description": "Credentials or secret keys are hardcoded in source code and may be exposed in version control.",
        "suggestedFix": "Move secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Never commit credentials.",
    },
    # Insecure Randomness
    {
        "type": "Insecure Randomness",
        "severity": "Medium",
        "patterns": [
            re.compile(r'\bMath\.random\(\)', re.IGNORECASE),
            re.compile(r'\brandom\.random\(\)', re.IGNORECASE),
            re.compile(r'\bnew Random\(\)', re.IGNORECASE),
        ],
        "description": "Weak PRNG used in a potentially security-sensitive context (token generation, session IDs).",
        "suggestedFix": "Use a cryptographically secure RNG: crypto.getRandomValues() in JS, secrets module in Python, SecureRandom in Java.",
    },
    # Command Injection
    {
        "type": "Command Injection",
        "severity": "High",
        "patterns": [
            re.compile(r'(os\.system|subprocess\.call|subprocess\.run|exec|shell_exec|popen)\s*\(\s*[^"\'\)]*\+', re.IGNORECASE),
            re.compile(r'(os\.system|subprocess\.call)\s*\(\s*f["\']', re.IGNORECASE),
        ],
        "description": "Unsanitized input passed to a shell command, enabling OS command injection.",
        "suggestedFix": "Avoid shell=True in subprocess calls. Validate and whitelist all inputs. Use shlex.quote() if shell invocation is unavoidable.",
    },
    # Insecure Deserialization
    {
        "type": "Insecure Deserialization",
        "severity": "High",
        "patterns": [
            re.compile(r'\bpickle\.loads?\s*\(', re.IGNORECASE),
            re.compile(r'\byaml\.load\s*\([^,)]+\)', re.IGNORECASE),  # yaml.load without Loader
            re.compile(r'\bunserialize\s*\(', re.IGNORECASE),
        ],
        "description": "Deserialization of untrusted data can lead to remote code execution.",
        "suggestedFix": "Use yaml.safe_load() instead of yaml.load(). Avoid pickle for untrusted data. Prefer JSON for data interchange.",
    },
    # Path Traversal
    {
        "type": "Path Traversal",
        "severity": "Medium",
        "patterns": [
            re.compile(r'open\s*\(\s*(?:request|req|input|user)', re.IGNORECASE),
            re.compile(r'(readFile|createReadStream)\s*\(\s*(?:req|request|params|query)', re.IGNORECASE),
            re.compile(r'\.\./|\.\.\\', re.IGNORECASE),
        ],
        "description": "User-controlled file paths may allow access to arbitrary files on the server.",
        "suggestedFix": "Validate and sanitize all file paths. Use path.resolve() and verify the result is within the intended directory.",
    },
]

# ── Severity weights for risk score ──────────────────────────────────────────

SEVERITY_WEIGHT = {"High": 30, "Medium": 15, "Low": 5}


# ── Detection logic ───────────────────────────────────────────────────────────

def scan_code(code: str) -> tuple[list[Vulnerability], float]:
    """Run all heuristic rules across each line of code."""
    lines = code.splitlines()
    found: list[Vulnerability] = []
    seen: set[tuple[str, int]] = set()  # deduplicate (type, line)

    for rule in RULES:
        for line_no, line_text in enumerate(lines, start=1):
            for pattern in rule["patterns"]:
                if pattern.search(line_text):
                    key = (rule["type"], line_no)
                    if key not in seen:
                        seen.add(key)
                        found.append(
                            Vulnerability(
                                type=rule["type"],
                                severity=rule["severity"],
                                line=line_no,
                                description=rule["description"],
                                suggestedFix=rule["suggestedFix"],
                                snippet=line_text.strip()[:200],
                            )
                        )
                    break  # one match per rule per line is enough

    # Risk score: capped at 100
    raw = sum(SEVERITY_WEIGHT.get(v.severity, 0) for v in found)
    risk_score = min(round(raw, 2), 100.0)
    return found, risk_score


# ── FastAPI app ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ML service ready.")
    yield
    logger.info("ML service shutting down.")


app = FastAPI(title="Code Security ML Service", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    if not req.code or not req.code.strip():
        raise HTTPException(status_code=400, detail="'code' field must not be empty.")

    if len(req.code) > 200_000:
        raise HTTPException(status_code=413, detail="Code payload too large (max 200 KB).")

    vulnerabilities, risk_score = scan_code(req.code)

    logger.info(
        "Scan complete — %d vulnerabilities found, risk score: %.1f",
        len(vulnerabilities),
        risk_score,
    )

    return AnalyzeResponse(vulnerabilities=vulnerabilities, riskScore=risk_score)
