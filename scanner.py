import asyncio
import os
import re
import time
from dotenv import load_dotenv
from db import insert_result, update_scan_status

load_dotenv()

WORDLIST_PATH = os.getenv("WORDLIST_PATH", "wordlists/common.txt")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "1800"))

# Global scan lock -- only 1 concurrent scan
_scan_lock = asyncio.Lock()
# Active subscribers: scan_id -> list of asyncio.Queue
_subscribers: dict[str, list[asyncio.Queue]] = {}
# Track running scan for cancellation
_active_process: dict[str, asyncio.subprocess.Process] = {}


def validate_domain(domain: str) -> bool:
    """Validate domain to prevent command injection."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain)) and len(domain) <= 253


async def _broadcast(scan_id: str, event: dict):
    """Send event to all SSE subscribers for this scan."""
    for queue in _subscribers.get(scan_id, []):
        await queue.put(event)


async def _run_tool(scan_id: str, tool_name: str, cmd: list[str], timeout: float) -> list[str]:
    """Run a subprocess, stream stdout line by line, return collected lines."""
    await _broadcast(scan_id, {"type": "step_start", "tool": tool_name})
    await insert_result(scan_id, "system", f"Starting {tool_name}...")

    lines = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _active_process[scan_id] = proc

        async def read_stream():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    lines.append(text)
                    event = await insert_result(scan_id, tool_name, text)
                    await _broadcast(scan_id, {"type": "line", **event})

        try:
            await asyncio.wait_for(read_stream(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await insert_result(scan_id, "system", f"{tool_name} timed out")
            await _broadcast(scan_id, {"type": "line", "tool": "system", "line": f"{tool_name} timed out", "ts": time.time()})

        await proc.wait()

    except FileNotFoundError:
        msg = f"{tool_name} not found in PATH. Skipping."
        await insert_result(scan_id, "system", msg)
        await _broadcast(scan_id, {"type": "line", "tool": "system", "line": msg, "ts": time.time()})
    finally:
        _active_process.pop(scan_id, None)

    await _broadcast(scan_id, {"type": "step_done", "tool": tool_name, "count": len(lines)})
    return lines


async def run_scan(scan_id: str, domain: str):
    """Execute the full recon pipeline sequentially."""
    async with _scan_lock:
        await update_scan_status(scan_id, "running")
        await _broadcast(scan_id, {"type": "status", "status": "running"})

        start_time = time.time()
        remaining = lambda: max(60, SCAN_TIMEOUT - (time.time() - start_time))

        try:
            # Step 1: subfinder
            subdomains = await _run_tool(
                scan_id, "subfinder",
                ["subfinder", "-d", domain, "-silent"],
                timeout=remaining(),
            )

            if not subdomains:
                await insert_result(scan_id, "system", "No subdomains found. Scan complete.")
                await _broadcast(scan_id, {"type": "line", "tool": "system", "line": "No subdomains found. Scan complete.", "ts": time.time()})
                await update_scan_status(scan_id, "completed")
                await _broadcast(scan_id, {"type": "status", "status": "completed"})
                return

            # Write subdomains to temp file for httpx input
            sub_file = f"/tmp/sara_{scan_id}_subs.txt"
            with open(sub_file, "w") as f:
                f.write("\n".join(subdomains))

            # Step 2: httpx
            httpx_lines = await _run_tool(
                scan_id, "httpx",
                ["httpx", "-l", sub_file, "-tech-detect", "-status-code", "-title", "-silent"],
                timeout=remaining(),
            )

            # Step 3: ffuf on each live subdomain (up to 20 to stay within resource limits)
            live_hosts = []
            for line in httpx_lines:
                # httpx output contains URLs -- extract the host
                match = re.search(r"https?://([^\s/\[\]]+)", line)
                if match:
                    live_hosts.append(match.group(0).rstrip("/"))

            ffuf_results = []
            targets = live_hosts[:20]  # cap to prevent resource exhaustion
            if targets:
                await _broadcast(scan_id, {"type": "step_start", "tool": "ffuf"})
                await insert_result(scan_id, "system", f"Fuzzing {len(targets)} hosts...")
                await _broadcast(scan_id, {"type": "line", "tool": "system", "line": f"Fuzzing {len(targets)} hosts...", "ts": time.time()})

                for host in targets:
                    fuzz_url = f"{host}/FUZZ"
                    lines = await _run_tool(
                        scan_id, "ffuf",
                        ["ffuf", "-u", fuzz_url, "-w", WORDLIST_PATH, "-mc", "200,301,302,403", "-s"],
                        timeout=remaining(),
                    )
                    ffuf_results.extend(lines)

            if not targets:
                await _broadcast(scan_id, {"type": "step_skip", "tool": "ffuf"})
                await insert_result(scan_id, "system", "No live hosts for ffuf. Skipping.")
                await _broadcast(scan_id, {"type": "line", "tool": "system", "line": "No live hosts for ffuf. Skipping.", "ts": time.time()})

            # Step 4: Conditional nuclei
            # Check if httpx detected any technology versions
            tech_detected = False
            version_pattern = re.compile(r"[a-zA-Z]+/\d+[\.\d]*")
            for line in httpx_lines:
                if version_pattern.search(line):
                    tech_detected = True
                    break

            if tech_detected:
                await insert_result(scan_id, "system", "Technology versions detected. Running nuclei...")
                await _broadcast(scan_id, {"type": "line", "tool": "system", "line": "Technology versions detected. Running nuclei...", "ts": time.time()})
                await _run_tool(
                    scan_id, "nuclei",
                    ["nuclei", "-l", sub_file, "-tags", "tech", "-severity", "medium,high,critical"],
                    timeout=remaining(),
                )
            else:
                await _broadcast(scan_id, {"type": "step_skip", "tool": "nuclei"})
                await insert_result(scan_id, "system", "No technology versions detected. Skipping nuclei.")
                await _broadcast(scan_id, {"type": "line", "tool": "system", "line": "No technology versions detected. Skipping nuclei.", "ts": time.time()})

            # Cleanup temp file
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
            await insert_result(scan_id, "system", f"Error: {str(e)}")
            await _broadcast(scan_id, {"type": "line", "tool": "system", "line": f"Error: {str(e)}", "ts": time.time()})
            await update_scan_status(scan_id, "error")
            await _broadcast(scan_id, {"type": "status", "status": "error"})
        finally:
            # Signal end of stream to all subscribers
            await _broadcast(scan_id, {"type": "done"})


def subscribe(scan_id: str) -> asyncio.Queue:
    """Register a new SSE subscriber for a scan."""
    queue = asyncio.Queue()
    _subscribers.setdefault(scan_id, []).append(queue)
    return queue


def unsubscribe(scan_id: str, queue: asyncio.Queue):
    """Remove an SSE subscriber."""
    if scan_id in _subscribers:
        _subscribers[scan_id] = [q for q in _subscribers[scan_id] if q is not queue]
        if not _subscribers[scan_id]:
            del _subscribers[scan_id]
