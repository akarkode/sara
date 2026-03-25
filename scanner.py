import asyncio
import json
import os
import re
import time
from dotenv import load_dotenv
from db import insert_result, update_scan_status

load_dotenv()

WORDLIST_PATH = os.getenv("WORDLIST_PATH", "wordlists/common.txt")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "1800"))

# ---------------------------------------------------------------------------
# Tool registry  (subfinder is internal — merged into httpx)
# ---------------------------------------------------------------------------

TOOLS_INFO = {
    "whois": {
        "name": "WHOIS",
        "description": "Domain registration & ownership lookup",
        "depends": [],
        "order": 1,
    },
    "dig": {
        "name": "DNS Records",
        "description": "DNS enumeration (A, MX, NS, TXT, CNAME)",
        "depends": [],
        "order": 2,
    },
    "httpx": {
        "name": "HTTPX",
        "description": "Subdomain discovery & HTTP probing",
        "depends": [],
        "order": 3,
    },
    "wafw00f": {
        "name": "WAFw00f",
        "description": "Web Application Firewall detection",
        "depends": ["httpx"],
        "order": 4,
    },
    "whatweb": {
        "name": "WhatWeb",
        "description": "Web technology fingerprinting",
        "depends": ["httpx"],
        "order": 5,
    },
    "ffuf": {
        "name": "FFUF",
        "description": "Directory & file fuzzing",
        "depends": ["httpx"],
        "order": 6,
    },
    "nmap": {
        "name": "Nmap",
        "description": "Port scanning & service detection",
        "depends": [],
        "order": 7,
    },
}

DEFAULT_TOOLS = ["httpx", "ffuf", "whatweb", "wafw00f"]

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_scan_lock = asyncio.Lock()
_subscribers: dict[str, list[asyncio.Queue]] = {}
_active_process: dict[str, asyncio.subprocess.Process] = {}


def get_tools_info() -> dict:
    return TOOLS_INFO


def resolve_tools(selected: list[str]) -> list[str]:
    """Add missing dependencies and return tools in execution order."""
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


# ---------------------------------------------------------------------------
# SSE pub/sub
# ---------------------------------------------------------------------------

async def _broadcast(scan_id: str, event: dict):
    for queue in _subscribers.get(scan_id, []):
        await queue.put(event)


def subscribe(scan_id: str) -> asyncio.Queue:
    queue = asyncio.Queue()
    _subscribers.setdefault(scan_id, []).append(queue)
    return queue


def unsubscribe(scan_id: str, queue: asyncio.Queue):
    if scan_id in _subscribers:
        _subscribers[scan_id] = [q for q in _subscribers[scan_id] if q is not queue]
        if not _subscribers[scan_id]:
            del _subscribers[scan_id]


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

async def _run_tool(scan_id: str, tool_name: str, cmd: list[str],
                    timeout: float, parser=None, broadcast: bool = True,
                    emit_step_events: bool = True) -> list[dict]:
    """Run a subprocess, stream stdout, parse each line, return parsed results.

    When broadcast=False the lines are collected but NOT sent to the SSE stream
    or persisted in the database (used for silent subfinder phase).
    When emit_step_events=False, step_start/step_done are suppressed (caller manages them).
    """
    if broadcast and emit_step_events:
        await _broadcast(scan_id, {"type": "step_start", "tool": tool_name})
        sys_event = await insert_result(scan_id, "system", f"Running {tool_name}...")
        await _broadcast(scan_id, {"type": "line", **sys_event})

    parsed_results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _active_process[scan_id] = proc

        async def read_stream():
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                text = raw.decode("utf-8", errors="replace").strip()
                if not text:
                    continue

                display_line, data = parser(text) if parser else (text, {})
                parsed_results.append({"line": display_line, "data": data, "raw": text})

                if broadcast:
                    event = await insert_result(scan_id, tool_name, display_line, data)
                    await _broadcast(scan_id, {"type": "line", **event})

        try:
            await asyncio.wait_for(read_stream(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            if broadcast:
                ev = await insert_result(scan_id, "system",
                    f"{tool_name} timed out after {int(timeout)}s")
                await _broadcast(scan_id, {"type": "line", **ev})

        await proc.wait()

    except FileNotFoundError:
        if broadcast:
            ev = await insert_result(scan_id, "system",
                f"{tool_name} not found in PATH — skipping")
            await _broadcast(scan_id, {"type": "line", **ev})
    finally:
        _active_process.pop(scan_id, None)

    if broadcast and emit_step_events:
        count = len(parsed_results)
        await _broadcast(scan_id, {"type": "step_done", "tool": tool_name, "count": count})
        summary = await insert_result(scan_id, "system",
            f"{tool_name} finished — {count} results", {"summary": True, "count": count})
        await _broadcast(scan_id, {"type": "line", **summary})

    return parsed_results


async def _run_subfinder_silent(scan_id: str, domain: str, timeout: float) -> list[str]:
    """Run subfinder silently — no log output, just collect subdomains."""
    results = await _run_tool(
        scan_id, "subfinder",
        ["subfinder", "-d", domain, "-silent"],
        timeout=timeout,
        parser=_parse_subfinder,
        broadcast=False,
    )
    return [r["data"].get("subdomain", r["line"]) for r in results if r["line"]]


# ---------------------------------------------------------------------------
# Per-tool parsers
# ---------------------------------------------------------------------------

def _parse_whois(line: str) -> tuple[str, dict]:
    data = {}
    if ":" in line:
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if any(k in key for k in ["registrar", "creation", "expir", "name server",
                                    "registrant", "org", "country", "dnssec", "updated"]):
            data = {"field": key, "value": val}
    return line, data


def _parse_dig(line: str) -> tuple[str, dict]:
    data = {}
    m = re.match(r"^(\S+)\s+(\d+)\s+IN\s+(\w+)\s+(.+)$", line)
    if m:
        data = {"name": m.group(1), "ttl": int(m.group(2)),
                "type": m.group(3), "value": m.group(4).strip()}
    return line, data


def _parse_subfinder(line: str) -> tuple[str, dict]:
    subdomain = line.strip()
    return subdomain, {"subdomain": subdomain}


def _parse_httpx_json(line: str) -> tuple[str, dict]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return line, {}

    url = obj.get("url", "")
    status = obj.get("status_code") or obj.get("status-code", 0)
    title = obj.get("title", "")
    tech = obj.get("tech") or obj.get("technologies") or []
    server = obj.get("webserver") or obj.get("web-server", "")
    cl = obj.get("content_length") or obj.get("content-length", 0)
    final_url = obj.get("final_url", "")
    host = obj.get("host", "")
    scheme = obj.get("scheme", "")
    port = obj.get("port", "")

    if isinstance(tech, list):
        tech_str = ", ".join(tech) if tech else ""
    else:
        tech_str = str(tech)

    parts = [url]
    if status:
        parts.append(f"[{status}]")
    if title:
        parts.append(f"[{title}]")
    if tech_str:
        parts.append(f"[{tech_str}]")
    if server:
        parts.append(f"[{server}]")
    if cl:
        parts.append(f"[{cl} bytes]")

    display = "  ".join(parts)
    data = {
        "url": url, "status_code": int(status) if status else 0,
        "title": title, "tech": tech if isinstance(tech, list) else [],
        "server": server, "content_length": int(cl) if cl else 0,
        "host": host, "scheme": scheme, "port": port,
    }
    if final_url and final_url != url:
        data["redirect_to"] = final_url
    return display, data


def _parse_wafw00f(line: str) -> tuple[str, dict]:
    data = {}
    m = re.search(r"(https?://\S+)\s+is behind\s+(.+?)(?:\s*\((.+?)\))?$", line)
    if m:
        data = {"url": m.group(1), "waf_detected": True,
                "waf_name": m.group(2).strip(),
                "waf_vendor": (m.group(3) or "").strip()}
        return line, data

    m2 = re.search(r"(https?://\S+)\s+.*[Nn]o WAF", line)
    if m2:
        data = {"url": m2.group(1), "waf_detected": False, "waf_name": "", "waf_vendor": ""}

    return line, data


def _parse_whatweb(line: str) -> tuple[str, dict]:
    data = {}
    m = re.match(r"(https?://\S+)\s+\[(\d+)\s*([^\]]*)\]\s*(.*)", line)
    if m:
        url = m.group(1)
        status = int(m.group(2))
        plugins_raw = m.group(4)
        techs = re.findall(r"([A-Za-z0-9_\-]+(?:\[.*?\])?)", plugins_raw)
        data = {"url": url, "status_code": status, "technologies": techs}
    return line, data


def _parse_ffuf(line: str) -> tuple[str, dict]:
    data = {}
    m = re.match(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)", line)
    if m:
        data = {
            "path": m.group(1),
            "status_code": int(m.group(2)),
            "size": int(m.group(3)),
            "words": int(m.group(4)),
            "lines": int(m.group(5)),
        }
        return line, data

    if line.startswith("http://") or line.startswith("https://"):
        data = {"url": line, "path": line}

    return line, data


def _parse_nmap(line: str) -> tuple[str, dict]:
    data = {}
    m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
    if m:
        data = {
            "port": int(m.group(1)),
            "protocol": m.group(2),
            "state": m.group(3),
            "service": m.group(4),
            "version": m.group(5).strip(),
        }
    elif "scan report for" in line:
        m2 = re.search(r"for\s+(\S+)\s*(?:\(([^)]+)\))?", line)
        if m2:
            data = {"host": m2.group(1), "ip": (m2.group(2) or "").strip()}
    return line, data


# ---------------------------------------------------------------------------
# Main scan runner
# ---------------------------------------------------------------------------

async def run_scan(scan_id: str, domain: str, selected_tools: list[str],
                   wordlist: str = "default"):
    """Execute the full recon pipeline sequentially."""
    async with _scan_lock:
        await update_scan_status(scan_id, "running")
        await _broadcast(scan_id, {"type": "status", "status": "running"})

        execution_plan = resolve_tools(selected_tools)
        await _broadcast(scan_id, {
            "type": "plan",
            "tools": execution_plan,
            "tools_info": {t: TOOLS_INFO[t] for t in execution_plan},
        })

        start_time = time.time()
        remaining = lambda: max(60, SCAN_TIMEOUT - (time.time() - start_time))

        wordlist_path = WORDLIST_PATH if wordlist == "default" else wordlist
        context = {"domain": domain, "subdomains": [], "live_hosts": [], "_sub_file": None}

        try:
            for tool_id in execution_plan:

                # --- HTTPX (includes silent subfinder) ---
                if tool_id == "httpx":
                    await _broadcast(scan_id, {"type": "step_start", "tool": "httpx"})

                    # Phase 1: run subfinder silently
                    ev = await insert_result(scan_id, "system",
                        "Enumerating subdomains...")
                    await _broadcast(scan_id, {"type": "line", **ev})

                    subdomains = await _run_subfinder_silent(
                        scan_id, domain, timeout=remaining())
                    context["subdomains"] = subdomains

                    ev = await insert_result(scan_id, "system",
                        f"Discovered {len(subdomains)} subdomains — probing with httpx...",
                        {"summary": True, "count": len(subdomains)})
                    await _broadcast(scan_id, {"type": "line", **ev})

                    if not subdomains:
                        ev = await insert_result(scan_id, "system",
                            "No subdomains found — skipping HTTP probing")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_done", "tool": "httpx", "count": 0})
                        continue

                    # Write subdomains to temp file
                    sub_file = os.path.join(
                        os.environ.get("TEMP", "/tmp"),
                        f"argus_{scan_id}_subs.txt",
                    )
                    with open(sub_file, "w") as f:
                        f.write("\n".join(subdomains))
                    context["_sub_file"] = sub_file

                    # Phase 2: run httpx — lines are logged, but step events managed here
                    httpx_cmd = [
                        "httpx", "-l", sub_file, "-json",
                        "-tech-detect", "-follow-redirects",
                    ]
                    results = await _run_tool(
                        scan_id, "httpx", httpx_cmd,
                        timeout=remaining(), parser=_parse_httpx_json,
                        broadcast=True, emit_step_events=False,
                    )

                    live_hosts = []
                    for r in results:
                        url = r["data"].get("url", "")
                        if url:
                            live_hosts.append(url.rstrip("/"))
                    context["live_hosts"] = live_hosts

                    # Summary: subdomains found + live hosts probed
                    summary = await insert_result(scan_id, "system",
                        f"httpx finished — {len(subdomains)} subdomains, {len(live_hosts)} live hosts",
                        {"summary": True, "subdomains": len(subdomains), "live_hosts": len(live_hosts)})
                    await _broadcast(scan_id, {"type": "line", **summary})
                    await _broadcast(scan_id, {"type": "step_done", "tool": "httpx", "count": len(live_hosts)})

                # --- FFUF (per host) ---
                elif tool_id == "ffuf":
                    hosts = context.get("live_hosts", [])
                    if not hosts:
                        ev = await insert_result(scan_id, "system",
                            "ffuf skipped — no live hosts")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "ffuf"})
                        continue

                    await _broadcast(scan_id, {"type": "step_start", "tool": "ffuf"})
                    ev = await insert_result(scan_id, "system",
                        f"Fuzzing {min(len(hosts), 20)} hosts with {os.path.basename(wordlist_path)}...")
                    await _broadcast(scan_id, {"type": "line", **ev})

                    all_ffuf = []
                    for host in hosts[:20]:
                        fuzz_url = f"{host}/FUZZ"
                        results = await _run_tool(
                            scan_id, "ffuf",
                            ["ffuf", "-u", fuzz_url, "-w", wordlist_path,
                             "-mc", "all", "-fc", "404", "-se"],
                            timeout=remaining(), parser=_parse_ffuf,
                            broadcast=True,
                        )
                        for r in results:
                            if r["data"].get("status_code"):
                                r["data"]["host"] = host
                        all_ffuf.extend(results)

                    summary = await insert_result(scan_id, "system",
                        f"ffuf finished — {len(all_ffuf)} total results across {min(len(hosts), 20)} hosts",
                        {"summary": True, "count": len(all_ffuf)})
                    await _broadcast(scan_id, {"type": "line", **summary})
                    await _broadcast(scan_id, {"type": "step_done", "tool": "ffuf", "count": len(all_ffuf)})

                # --- WAFW00F ---
                elif tool_id == "wafw00f":
                    hosts = context.get("live_hosts", [])
                    if not hosts:
                        ev = await insert_result(scan_id, "system",
                            "wafw00f skipped — no live hosts")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "wafw00f"})
                        continue
                    await _run_tool(scan_id, "wafw00f",
                                    ["wafw00f"] + hosts[:30],
                                    timeout=remaining(), parser=_parse_wafw00f)

                # --- WHATWEB ---
                elif tool_id == "whatweb":
                    hosts = context.get("live_hosts", [])
                    if not hosts:
                        ev = await insert_result(scan_id, "system",
                            "whatweb skipped — no live hosts")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "whatweb"})
                        continue
                    await _run_tool(scan_id, "whatweb",
                                    ["whatweb", "--color=never", "-q"] + hosts[:30],
                                    timeout=remaining(), parser=_parse_whatweb)

                # --- WHOIS ---
                elif tool_id == "whois":
                    await _run_tool(scan_id, "whois",
                                    ["whois", domain],
                                    timeout=remaining(), parser=_parse_whois)

                # --- DIG ---
                elif tool_id == "dig":
                    await _run_tool(scan_id, "dig",
                                    ["dig", domain, "ANY", "+noall", "+answer"],
                                    timeout=remaining(), parser=_parse_dig)

                # --- NMAP ---
                elif tool_id == "nmap":
                    await _run_tool(scan_id, "nmap",
                                    ["nmap", "-sV", "--top-ports", "100", "-T4", "--open", domain],
                                    timeout=remaining(), parser=_parse_nmap)

            # Cleanup temp files
            sub_file = context.get("_sub_file")
            if sub_file:
                try:
                    os.remove(sub_file)
                except OSError:
                    pass

            await update_scan_status(scan_id, "completed")
            await _broadcast(scan_id, {"type": "status", "status": "completed"})

        except asyncio.CancelledError:
            await update_scan_status(scan_id, "error")
            await _broadcast(scan_id, {"type": "status", "status": "error"})
        except Exception as e:
            ev = await insert_result(scan_id, "system", f"Error: {str(e)}")
            await _broadcast(scan_id, {"type": "line", **ev})
            await update_scan_status(scan_id, "error")
            await _broadcast(scan_id, {"type": "status", "status": "error"})
        finally:
            await _broadcast(scan_id, {"type": "done"})
