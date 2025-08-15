"""
KISS PowerShell MCP Server (Python)
───────────────────────────────────
Minimal, safe-by-default MCP server that exposes a tiny set of Windows / PowerShell tools.
Transport: stdio (ideal for VS Code MCP). No nonstandard deps beyond the official MCP SDK.
Runs on Windows; will also work on macOS/Linux if `pwsh` is available.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sys
import tempfile
from pathlib import Path
from subprocess import CompletedProcess, run
from typing import List, Optional

# MCP SDK (Python)
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pwsh-kiss")

# ────────────────────────────────────────────────────────────────────────────────
# Utilities
# ────────────────────────────────────────────────────────────────────────────────

def which_shell() -> tuple[str, list[str]]:
    is_win = os.name == "nt"
    candidates = [
        ("pwsh.exe" if is_win else "pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]),
    ]
    if is_win:
        candidates.append(("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]))

    for exe, args in candidates:
        path = shutil.which(exe)
        if path:
            return path, args

    return ("cmd.exe", ["/c"]) if is_win else ("sh", ["-c"])


def ps_invoke(command: str, timeout: int = 15) -> tuple[int, str, str]:
    exe, base = which_shell()
    try:
        cp: CompletedProcess[bytes] = run(
            [exe, *base, command],
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        return cp.returncode, cp.stdout.decode(errors="ignore"), cp.stderr.decode(errors="ignore")
    except Exception as e:
        return 1, "", f"Invocation error: {e}"

ALLOWLIST = {
    "Get-Process",
    "Get-Service",
    "Get-ComputerInfo",
    "Get-ChildItem",
    "Get-ItemProperty",
    "Get-Command",
}

def is_allowed(ps_command: str) -> bool:
    head = ps_command.strip().split()[0] if ps_command.strip() else ""
    return head in ALLOWLIST

# ────────────────────────────────────────────────────────────────────────────────
# Tools
# ────────────────────────────────────────────────────────────────────────────────

@mcp.tool(description="Return basic system info (platform, arch, CPUs, memory hint) + $PSVersionTable.")
async def system_info() -> str:
    node_info = {
        "platform": sys.platform,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "user": os.getlogin() if hasattr(os, "getlogin") else "",
    }
    code, ps, _ = ps_invoke("$PSVersionTable | Out-String")
    return "node:\n" + json.dumps(node_info, indent=2) + "\n\nps:\n" + (ps if ps else f"(ps exitCode={code})")

@mcp.tool(description="List Windows services with Status, Name, DisplayName (read-only).")
async def list_services(filter: Optional[str] = None) -> str:
    if filter:
        cmd = (
            f"Get-Service -Name \"{filter}\" | "
            "Select-Object Status,Name,DisplayName | Format-Table -AutoSize | Out-String"
        )
    else:
        cmd = (
            "Get-Service | Select-Object Status,Name,DisplayName | "
            "Sort-Object Name | Format-Table -AutoSize | Out-String"
        )
    _, out, err = ps_invoke(cmd)
    return err or out

@mcp.tool(description="List running processes with Name, Id, CPU, WS (read-only).")
async def list_processes() -> str:
    cmd = (
        "Get-Process | Select-Object Name,Id,CPU,WS | "
        "Sort-Object CPU -Descending | Format-Table -AutoSize | Out-String"
    )
    _, out, err = ps_invoke(cmd)
    return err or out

@mcp.tool(description="Run a single PowerShell command from a safe allowlist.")
async def run_ps(command: str) -> str:
    if not is_allowed(command):
        return (
            f"Command not allowed: {command}. Allowed: "
            + ", ".join(sorted(ALLOWLIST))
        )
    code, out, err = ps_invoke(command)
    prefix = f"exitCode={code}\n"
    if err:
        return prefix + "stderr:\n" + err + ("\nstdout:\n" + out if out else "")
    return prefix + "stdout:\n" + out

@mcp.tool(description="Run a local .ps1 with optional arguments (intended read-only scripts).")
async def run_script(path: str, args: Optional[List[str]] = None) -> str:
    args = args or []
    p = Path(path)
    if not p.suffix.lower() == ".ps1":
        return "Only .ps1 scripts are supported."
    if not p.is_absolute():
        return "Please provide an absolute path to the .ps1 script."
    esc = lambda s: s.replace("'", "''")
    arglist = " ".join(f"'{esc(a)}'" for a in args)
    cmd = f"& '{esc(str(p))}' {arglist}".strip()
    code, out, err = ps_invoke(cmd, timeout=20)
    prefix = f"exitCode={code}\n"
    if err:
        return prefix + "stderr:\n" + err + ("\nstdout:\n" + out if out else "")
    return prefix + "stdout:\n" + out

@mcp.tool(description="Run a short, read-only PowerShell snippet by writing it to a temp .ps1 (<=2000 chars).")
async def run_snippet(script: str) -> str:
    if len(script) > 2000:
        return "Script too long (max 2000 chars)."
    deny = [
        r"Invoke-WebRequest",
        r"Invoke-Expression",
        r"Set-ItemProperty",
        r"Remove-Item",
        r"Start-Process",
        r"Stop-Process",
        r"New-Item",
        r"Set-Service",
        r"Start-Service",
        r"Stop-Service",
        r"Restart-Computer",
    ]
    if any(re.search(p, script, re.IGNORECASE) for p in deny):
        return "Disallowed content in script."
    with tempfile.TemporaryDirectory(prefix="mcp-ps-") as d:
        ps1 = Path(d) / "snippet.ps1"
        ps1.write_text(script, encoding="utf-8")
        code, out, err = ps_invoke(f"& '{str(ps1).replace("'", "''")}'")
        prefix = f"exitCode={code}\n"
        if err:
            return prefix + "stderr:\n" + err + ("\nstdout:\n" + out if out else "")
        return prefix + "stdout:\n" + out

# ────────────────────────────────────────────────────────────────────────────────
# Entrypoint (stdio)
# ────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run()
