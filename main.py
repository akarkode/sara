import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Query, UploadFile, File
from fastapi.responses import StreamingResponse, Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from db import init_db, create_scan, get_scan, get_scan_results, get_all_scans, DB_PATH
from scanner import (
    validate_domain, classify_target, run_scan, subscribe, unsubscribe,
    get_tools_info, resolve_tools, DEFAULT_TOOLS, stop_scan,
    get_os_info, install_tool
)
from exporter import export_pdf, export_csv

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="ARGUS", version="1.1", lifespan=lifespan)

class ScanRequest(BaseModel):
    domain: str
    tools: list[str] | None = None
    wordlist: str = "default"

@app.get("/os")
async def os_info():
    return get_os_info()

@app.get("/tools")
async def list_tools():
    return {
        "tools": get_tools_info(),
        "defaults": DEFAULT_TOOLS,
        "os": get_os_info()
    }

class InstallRequest(BaseModel):
    password: Optional[str] = None

@app.post("/install-tool/{tool_id}")
async def install_tool_route(tool_id: str, req: InstallRequest):
    tools = get_tools_info()
    if tool_id not in tools:
        raise HTTPException(status_code=404, detail="Tool not found")
    try:
        await install_tool(tool_id, password=req.password)
        return {"status": "success", "message": f"Tool {tool_id} installed successfully"}
    except Exception as e:
        msg = str(e)
        if msg in ["SUDO_PASSWORD_REQUIRED", "INCORRECT_PASSWORD"]:
            return {"status": "error", "code": msg}
        raise HTTPException(status_code=500, detail=msg)

@app.post("/scan")
async def start_scan(req: ScanRequest):
    target = req.domain.strip().lower()
    target_type = classify_target(target)
    if target_type == "invalid":
        raise HTTPException(status_code=400, detail="Invalid target: must be a domain (example.com), URL (https://example.com), or IP address (1.2.3.4)")

    selected = req.tools or DEFAULT_TOOLS
    tools_info = get_tools_info()
    for t in selected:
        if t not in tools_info:
            raise HTTPException(status_code=400, detail=f"Unknown tool: {t}")
        if not tools_info[t]["available"]:
            raise HTTPException(status_code=400, detail=f"Tool {t} is not installed on this system")
    resolved = resolve_tools(selected)
    for t in resolved:
        if not tools_info[t]["available"]:
            raise HTTPException(status_code=400, detail=f"Required dependency '{t}' is not installed (needed by selected tools)")

    scan_id = uuid.uuid4().hex[:12]
    await create_scan(scan_id, target, resolved, req.wordlist)
    asyncio.create_task(run_scan(scan_id, target, selected, req.wordlist, target_type=target_type))
    return {"scan_id": scan_id, "domain": target, "status": "queued", "tools": resolved, "target_type": target_type}

@app.post("/scan/{scan_id}/stop")
async def stop_scan_route(scan_id: str):
    success = await stop_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or not running")
    return {"status": "cancelled", "scan_id": scan_id}

@app.get("/scan/{scan_id}/stream")
async def scan_stream(scan_id: str, request: Request):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    queue = subscribe(scan_id)
    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    break
        finally:
            unsubscribe(scan_id, queue)
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@app.get("/scan/{scan_id}/result")
async def scan_result(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = await get_scan_results(scan_id)
    return {"scan": scan, "results": results}

@app.delete("/scan/{scan_id}")
async def delete_scan_route(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            # Delete all results related to this scan
            await db.execute("DELETE FROM results WHERE scan_id = ?", (scan_id,))
            # Delete the scan itself
            await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await db.commit()
        return {"status": "success", "message": f"Scan {scan_id} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")

@app.get("/scan/{scan_id}/export/pdf")
async def scan_export_pdf(
    scan_id: str,
    tools: Optional[str] = Query(None),
    status_codes: Optional[str] = Query(None),
):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    tool_filter = [t.strip() for t in tools.split(",") if t.strip()] if tools else None
    sc_filter   = [int(s.strip()) for s in status_codes.split(",") if s.strip()] if status_codes else None
    results     = await get_scan_results(scan_id, tools=tool_filter, status_codes=sc_filter)
    pdf_bytes   = export_pdf(scan, results)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=argus_{scan_id}.pdf"},
    )

@app.get("/scan/{scan_id}/export/csv")
async def scan_export_csv(
    scan_id: str,
    tools: Optional[str] = Query(None),
    status_codes: Optional[str] = Query(None),
):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    tool_filter = [t.strip() for t in tools.split(",") if t.strip()] if tools else None
    sc_filter   = [int(s.strip()) for s in status_codes.split(",") if s.strip()] if status_codes else None
    results     = await get_scan_results(scan_id, tools=tool_filter, status_codes=sc_filter)
    csv_str     = export_csv(scan, results)
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{scan_id}.csv"},
    )

@app.post("/upload-wordlist")
async def upload_wordlist(file: UploadFile = File(...)):
    if not file.filename.endswith(".txt"):
        raise HTTPException(status_code=400, detail="Only .txt files are allowed")
    
    upload_dir = os.path.join("wordlists", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    
    file_id = uuid.uuid4().hex[:8]
    file_path = os.path.join(upload_dir, f"custom_{file_id}.txt")
    
    try:
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)
        return {"path": file_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

@app.get("/scans")
async def list_scans(limit: int = 50, offset: int = 0):
    return {"scans": await get_all_scans(limit=limit, offset=offset)}

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

app.mount(
    "/static",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")),
    name="static",
)
