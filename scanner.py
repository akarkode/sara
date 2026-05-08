import asyncio
import json
import os
import re
import time
import platform
import shutil
import subprocess
from dotenv import load_dotenv
from db import insert_result, update_scan_status
from vuln_react2shell import run_as_argus_tool as _run_react2shell

load_dotenv()

WORDLIST = os.getenv("WORDLIST_PATH", "wordlists/common.txt")
TIMEOUT  = int(os.getenv("SCAN_TIMEOUT", "1800"))

TOOLS_INFO = {
    "whois": {
        "name": "WHOIS",
        "description": "Domain registration & ownership lookup",
        "depends": [],
        "order": 1,
        "binary": "whois",
    },
    "dig": {
        "name": "DNS Records",
        "description": "DNS enumeration (A, MX, NS, TXT, CNAME)",
        "depends": [],
        "order": 2,
        "binary": "dig",
    },
    "httpx": {
        "name": "HTTPX",
        "description": "Subdomain discovery & HTTP probing",
        "depends": [],
        "order": 3,
        "binary": "httpx",
    },
    "wafw00f": {
        "name": "WAFw00f",
        "description": "Web Application Firewall detection",
        "depends": ["httpx"],
        "order": 4,
        "binary": "wafw00f",
    },
    "whatweb": {
        "name": "WhatWeb",
        "description": "Web technology fingerprinting",
        "depends": ["httpx"],
        "order": 5,
        "binary": "whatweb",
    },
    "ffuf": {
        "name": "FFUF",
        "description": "Directory & file fuzzing",
        "depends": ["httpx"],
        "order": 6,
        "binary": "ffuf",
    },
    "nmap": {
        "name": "Nmap",
        "description": "Port scanning & service detection",
        "depends": [],
        "order": 7,
        "binary": "nmap",
    },
    "react2shell": {
        "name": "React2Shell",
        "description": "CVE-2025-55182 — React Server Components RCE detection",
        "depends": ["httpx"],
        "order": 8,
        "binary": None,
        "python": True,
    },
}

DEFAULT_TOOLS = ["httpx", "ffuf", "whatweb", "wafw00f"]

_lock   = asyncio.Lock()
_queues: dict[str, list[asyncio.Queue]] = {}
_procs:  dict[str, asyncio.subprocess.Process] = {}
_tasks:  dict[str, asyncio.Task] = {}

def get_os_info():
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "distro": "",
    }
    if info["system"] == "Linux":
        try:
            with open("/etc/os-release") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("PRETTY_NAME="):
                        info["distro"] = line.split("=")[1].strip().strip('"')
                        break
        except Exception:
            pass
    return info

def is_tool_available(tool_id: str) -> bool:
    tool = TOOLS_INFO.get(tool_id, {})
    binary = tool.get("binary")
    if binary is None:
        return tool.get("python", False)
    return shutil.which(binary) is not None

def get_tools_info() -> dict:
    tools = {}
    for tid, info in TOOLS_INFO.items():
        tools[tid] = {**info, "available": is_tool_available(tid)}
    return tools

async def check_permissions():
    """Checks if we have root or passwordless sudo access."""
    if os.name == 'nt': # Windows
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    # Check if root
    if os.getuid() == 0:
        return True
    
    # Check if sudo works without password
    try:
        proc = await asyncio.create_subprocess_exec("sudo", "-n", "true", stderr=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        await proc.wait()
        return proc.returncode == 0
    except Exception:
        return False

async def install_tool(tool_id: str, password: str = None):
    os_info = get_os_info()
    system = os_info["system"]
    
    has_perm = await check_permissions()
    
    commands = []
    if system == "Linux":
        distro = os_info["distro"].lower()
        # If password is provided, we use sudo -S to read from stdin
        sudo_prefix = ["sudo", "-S"] if password else (["sudo", "-n"] if not (os.getuid() == 0 if hasattr(os, 'getuid') else False) else [])
        
        if not has_perm and not password and sudo_prefix and "-n" in sudo_prefix:
            # We don't have passwordless sudo, so we need to tell the frontend to ask for a password
            raise Exception("SUDO_PASSWORD_REQUIRED")

        if "debian" in distro or "ubuntu" in distro:
            pkg_map = {
                "whois": "whois",
                "dig": "dnsutils",
                "nmap": "nmap",
                "whatweb": "whatweb",
                "wafw00f": "wafw00f",
                "ffuf": "ffuf",
                "httpx": "httpx",
            }
            pkg = pkg_map.get(tool_id)
            if pkg:
                if tool_id == "httpx":
                    commands = ["/bin/bash", "-c", f"echo '{password}' | {' '.join(sudo_prefix)} apt-get update -y && echo '{password}' | {' '.join(sudo_prefix)} apt-get install -y curl unzip && curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip -o httpx.zip && unzip -o httpx.zip && echo '{password}' | {' '.join(sudo_prefix)} mv httpx /usr/local/bin/ && rm httpx.zip"]
                else:
                    commands = [f"echo '{password}' | " + " ".join(sudo_prefix + ["apt-get", "update", "-y"])] + [f"echo '{password}' | " + " ".join(sudo_prefix + ["apt-get", "install", "-y", pkg])]
        elif "arch" in distro:
            pkg_map = {
                "whois": "whois",
                "dig": "bind",
                "nmap": "nmap",
                "whatweb": "whatweb",
                "wafw00f": "wafw00f",
                "ffuf": "ffuf",
                "httpx": "httpx",
            }
            pkg = pkg_map.get(tool_id)
            if pkg:
                commands = [f"echo '{password}' | " + " ".join(sudo_prefix + ["pacman", "-Sy", "--noconfirm", pkg])]
    elif system == "Darwin": # macOS
        # Homebrew doesn't usually want sudo
        pkg_map = {"whois":"whois","dig":"bind","nmap":"nmap","whatweb":"whatweb","wafw00f":"wafw00f","ffuf":"ffuf","httpx":"projectdiscovery/tap/httpx"}
        pkg = pkg_map.get(tool_id)
        if pkg: commands = ["brew", "install", pkg]
            
    if not commands:
        raise Exception(f"Installation not supported for {tool_id} on {system}")

    for cmd in commands:
        cmd_str = cmd if isinstance(cmd, str) else " ".join([str(c) for c in cmd])
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            err_msg = stderr.decode().strip()
            if "sudo: a password is required" in err_msg or "sudo: 1 incorrect password attempt" in err_msg:
                raise Exception("SUDO_PASSWORD_REQUIRED" if not password else "INCORRECT_PASSWORD")
            raise Exception(f"Installation failed: {err_msg}")
    return True

async def stop_scan(scan_id: str):
    if scan_id in _tasks:
        _tasks[scan_id].cancel()
        # Also kill subprocess if running
        if scan_id in _procs:
            try:
                _procs[scan_id].kill()
            except Exception:
                pass
        await update_scan_status(scan_id, "cancelled")
        await _broadcast(scan_id, {"type": "status", "status": "cancelled"})
        return True
    return False

def resolve_tools(selected: list[str]) -> list[str]:
    resolved = set(selected)
    changed = True
    while changed:
        changed = False
        for tool in list(resolved):
            for dep in TOOLS_INFO.get(tool, {}).get("depends", []):
                if dep not in resolved:
                    resolved.add(dep)
                    changed = True
    return sorted(resolved, key=lambda t: TOOLS_INFO.get(t, {}).get("order", 99))

def validate_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain)) and len(domain) <= 253

async def _broadcast(scan_id: str, event: dict):
    if scan_id in _queues:
        for q in _queues[scan_id]:
            await q.put(event)

def subscribe(scan_id: str) -> asyncio.Queue:
    q = asyncio.Queue()
    _queues.setdefault(scan_id, []).append(q)
    return q

def unsubscribe(scan_id: str, q: asyncio.Queue):
    if scan_id in _queues:
        _queues[scan_id] = [x for x in _queues[scan_id] if x is not q]
        if not _queues[scan_id]:
            del _queues[scan_id]

async def _run_tool(
    scan_id: str,
    tool: str,
    cmd: list[str],
    timeout: float,
    parser=None,
    broadcast: bool = True,
    emit_steps: bool = True,
) -> list[dict]:
    if broadcast and emit_steps:
        await _broadcast(scan_id, {"type": "step_start", "tool": tool})
        ev = await insert_result(scan_id, "system", f"Running {tool}...")
        await _broadcast(scan_id, {"type": "line", **ev})
    collected = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _procs[scan_id] = proc
        async def _read():
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                text = raw.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                line, data = parser(text) if parser else (text, {})
                collected.append({"line": line, "data": data, "raw": text})
                if broadcast:
                    ev = await insert_result(scan_id, tool, line, data)
                    await _broadcast(scan_id, {"type": "line", **ev})
        try:
            await asyncio.wait_for(_read(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            if broadcast:
                ev = await insert_result(scan_id, "system", f"{tool} timed out after {int(timeout)}s")
                await _broadcast(scan_id, {"type": "line", **ev})
        await proc.wait()
    except FileNotFoundError:
        if broadcast:
            ev = await insert_result(scan_id, "system", f"{tool} not found in PATH — skipping")
            await _broadcast(scan_id, {"type": "line", **ev})
    finally:
        _procs.pop(scan_id, None)
    if broadcast and emit_steps:
        count = len(collected)
        await _broadcast(scan_id, {"type": "step_done", "tool": tool, "count": count})
        ev = await insert_result(scan_id, "system", f"{tool} finished — {count} results", {"summary": True, "count": count})
        await _broadcast(scan_id, {"type": "line", **ev})
    return collected

async def _subfinder(scan_id: str, domain: str, timeout: float) -> list[str]:
    results = await _run_tool(scan_id, "subfinder", ["subfinder", "-d", domain, "-silent"], timeout=timeout, parser=_parse_subfinder, broadcast=False)
    return [r["data"].get("subdomain", r["line"]) for r in results if r["line"]]

def _parse_whois(line: str) -> tuple[str, dict]:
    data = {}
    if ":" in line:
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if any(k in key for k in ["registrar", "creation", "expir", "name server", "registrant", "org", "country", "dnssec", "updated"]):
            data = {"field": key, "value": val}
    return line, data

def _parse_dig(line: str) -> tuple[str, dict]:
    data = {}
    m = re.match(r"^(\S+)\s+(\d+)\s+IN\s+(\w+)\s+(.+)$", line)
    if m:
        data = {"name": m.group(1), "ttl": int(m.group(2)), "type": m.group(3), "value": m.group(4).strip()}
    return line, data

def _parse_subfinder(line: str) -> tuple[str, dict]:
    s = line.strip()
    return s, {"subdomain": s}

def _parse_httpx_json(line: str) -> tuple[str, dict]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return line, {}
    url    = obj.get("url", "")
    status = obj.get("status_code") or obj.get("status-code", 0)
    title  = obj.get("title", "")
    tech   = obj.get("tech") or obj.get("technologies") or []
    server = obj.get("webserver") or obj.get("web-server", "")
    cl     = obj.get("content_length") or obj.get("content-length", 0)
    final  = obj.get("final_url", "")
    host   = obj.get("host", "")
    scheme = obj.get("scheme", "")
    port   = obj.get("port", "")
    tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
    parts = [url]
    if status: parts.append(f"[{status}]")
    if title: parts.append(f"[{title}]")
    if tech_str: parts.append(f"[{tech_str}]")
    if server: parts.append(f"[{server}]")
    if cl: parts.append(f"[{cl} bytes]")
    data = {"url": url, "status_code": int(status) if status else 0, "title": title, "tech": tech if isinstance(tech, list) else [], "server": server, "content_length": int(cl) if cl else 0, "host": host, "scheme": scheme, "port": port}
    if final and final != url:
        data["redirect_to"] = final
    return "  ".join(parts), data

def _parse_wafw00f(line: str) -> tuple[str, dict]:
    m = re.search(r"(https?://\S+)\s+is behind\s+(.+?)(?:\s*\((.+?)\))?$", line)
    if m:
        return line, {"url": m.group(1), "waf_detected": True, "waf_name": m.group(2).strip(), "waf_vendor": (m.group(3) or "").strip()}
    m2 = re.search(r"(https?://\S+)\s+.*[Nn]o WAF", line)
    if m2:
        return line, {"url": m2.group(1), "waf_detected": False, "waf_name": "", "waf_vendor": ""}
    return line, {}

def _parse_whatweb(line: str) -> tuple[str, dict]:
    m = re.match(r"(https?://\S+)\s+\[(\d+)\s*([^\]]*)\]\s*(.*)", line)
    if m:
        techs = re.findall(r"([A-Za-z0-9_\-]+(?:\[.*?\])?)", m.group(4))
        return line, {"url": m.group(1), "status_code": int(m.group(2)), "technologies": techs}
    return line, {}

def _parse_ffuf(line: str) -> tuple[str, dict]:
    m = re.match(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)", line)
    if m:
        return line, {"path": m.group(1), "status_code": int(m.group(2)), "size": int(m.group(3)), "words": int(m.group(4)), "lines": int(m.group(5))}
    if line.startswith(("http://", "https://")):
        return line, {"url": line, "path": line}
    return line, {}

def _parse_nmap(line: str) -> tuple[str, dict]:
    m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
    if m:
        return line, {"port": int(m.group(1)), "protocol": m.group(2), "state": m.group(3), "service": m.group(4), "version": m.group(5).strip()}
    if "scan report for" in line:
        m2 = re.search(r"for\s+(\S+)\s*(?:\(([^)]+)\))?", line)
        if m2:
            return line, {"host": m2.group(1), "ip": (m2.group(2) or "").strip()}
    return line, {}

async def run_scan(scan_id: str, domain: str, selected_tools: list[str], wordlist: str = "default"):
    # Register this task
    _tasks[scan_id] = asyncio.current_task()
    
    async with _lock:
        try:
            await update_scan_status(scan_id, "running")
            await _broadcast(scan_id, {"type": "status", "status": "running"})
            plan = resolve_tools(selected_tools)
            await _broadcast(scan_id, {"type": "plan", "tools": plan, "tools_info": {t: TOOLS_INFO[t] for t in plan}})
            t0 = time.time()
            def time_left() -> float:
                return max(60.0, TIMEOUT - (time.time() - t0))
            wl  = WORDLIST if wordlist == "default" else wordlist
            ctx = {"domain": domain, "subdomains": [], "live_hosts": [], "sub_file": None}
            
            for tool in plan:
                if tool == "httpx":
                    await _broadcast(scan_id, {"type": "step_start", "tool": "httpx"})
                    ev = await insert_result(scan_id, "system", "Enumerating subdomains...")
                    await _broadcast(scan_id, {"type": "line", **ev})
                    subs = await _subfinder(scan_id, domain, timeout=time_left())
                    ctx["subdomains"] = subs
                    ev = await insert_result(scan_id, "system", f"Discovered {len(subs)} subdomains — probing with httpx...", {"summary": True, "count": len(subs)})
                    await _broadcast(scan_id, {"type": "line", **ev})
                    if not subs:
                        await _broadcast(scan_id, {"type": "step_done", "tool": "httpx", "count": 0})
                        continue
                    sub_file = os.path.join(os.environ.get("TEMP", "/tmp") if os.name == 'nt' else "/tmp", f"argus_{scan_id}_subs.txt")
                    with open(sub_file, "w") as f:
                        f.write("\n".join(subs))
                    ctx["sub_file"] = sub_file
                    probe_results = await _run_tool(scan_id, "httpx", ["httpx", "-l", sub_file, "-json", "-tech-detect", "-follow-redirects"], timeout=time_left(), parser=_parse_httpx_json, broadcast=True, emit_steps=False)
                    live = [r["data"]["url"].rstrip("/") for r in probe_results if r["data"].get("url")]
                    ctx["live_hosts"] = live
                    ev = await insert_result(scan_id, "system", f"httpx finished — {len(subs)} subdomains, {len(live)} live hosts", {"summary": True, "subdomains": len(subs), "live_hosts": len(live)})
                    await _broadcast(scan_id, {"type": "line", **ev})
                    await _broadcast(scan_id, {"type": "step_done", "tool": "httpx", "count": len(live)})
                elif tool == "ffuf":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "ffuf"})
                        continue
                    await _broadcast(scan_id, {"type": "step_start", "tool": "ffuf"})
                    ffuf_results = []
                    for host in hosts[:20]:
                        results = await _run_tool(scan_id, "ffuf", ["ffuf", "-u", f"{host}/FUZZ", "-w", wl, "-mc", "all", "-fc", "404", "-se"], timeout=time_left(), parser=_parse_ffuf, broadcast=True, emit_steps=False)
                        for r in results:
                            if r["data"].get("status_code"):
                                r["data"]["host"] = host
                        ffuf_results.extend(results)
                    await _broadcast(scan_id, {"type": "step_done", "tool": "ffuf", "count": len(ffuf_results)})
                elif tool == "wafw00f":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "wafw00f"})
                        continue
                    await _run_tool(scan_id, "wafw00f", ["wafw00f"] + hosts[:30], timeout=time_left(), parser=_parse_wafw00f)
                elif tool == "whatweb":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "whatweb"})
                        continue
                    await _run_tool(scan_id, "whatweb", ["whatweb", "--color=never", "-q"] + hosts[:30], timeout=time_left(), parser=_parse_whatweb)
                elif tool == "whois":
                    await _run_tool(scan_id, "whois", ["whois", domain], timeout=time_left(), parser=_parse_whois)
                elif tool == "dig":
                    await _run_tool(scan_id, "dig", ["dig", domain, "ANY", "+noall", "+answer"], timeout=time_left(), parser=_parse_dig)
                elif tool == "nmap":
                    await _run_tool(scan_id, "nmap", ["nmap", "-sV", "--top-ports", "100", "-T4", "--open", domain], timeout=time_left(), parser=_parse_nmap)
                elif tool == "react2shell":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "react2shell"})
                        continue
                    await _broadcast(scan_id, {"type": "step_start", "tool": "react2shell"})
                    ev = await insert_result(scan_id, "system", f"Scanning {len(hosts)} live hosts for {TOOLS_INFO['react2shell']['description']}...")
                    await _broadcast(scan_id, {"type": "line", **ev})
                    results = await _run_react2shell(scan_id, hosts, insert_result, _broadcast)
                    vuln_count = sum(1 for r in results if r.status in ("VULNERABLE", "EXPOSED"))
                    ev = await insert_result(scan_id, "system", f"react2shell finished — {vuln_count}/{len(results)} potentially vulnerable", {"summary": True, "count": vuln_count})
                    await _broadcast(scan_id, {"type": "line", **ev})
                    await _broadcast(scan_id, {"type": "step_done", "tool": "react2shell", "count": vuln_count})
            
            if ctx.get("sub_file") and os.path.exists(ctx["sub_file"]):
                try: os.remove(ctx["sub_file"])
                except OSError: pass
                
            await update_scan_status(scan_id, "completed")
            await _broadcast(scan_id, {"type": "status", "status": "completed"})
            
        except asyncio.CancelledError:
            # Clean up subprocess if cancelled from here too
            if scan_id in _procs:
                try: _procs[scan_id].kill()
                except: pass
            await update_scan_status(scan_id, "cancelled")
            await _broadcast(scan_id, {"type": "status", "status": "cancelled"})
            raise # Re-raise to ensure proper task completion
        except Exception as exc:
            ev = await insert_result(scan_id, "system", f"Error: {exc}")
            await _broadcast(scan_id, {"type": "line", **ev})
            await update_scan_status(scan_id, "error")
            await _broadcast(scan_id, {"type": "status", "status": "error"})
        finally:
            # Cleanup custom wordlist if it was an uploaded file
            if wordlist and wordlist.startswith(os.path.join("wordlists", "uploads")):
                try:
                    if os.path.exists(wordlist):
                        os.remove(wordlist)
                except OSError:
                    pass
                    
            _tasks.pop(scan_id, None)
            await _broadcast(scan_id, {"type": "done"})
