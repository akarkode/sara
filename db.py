import aiosqlite
import time
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "sara.db")


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at REAL NOT NULL,
                finished_at REAL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                line TEXT NOT NULL,
                ts REAL NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id)
        """)
        await db.commit()


async def create_scan(scan_id: str, domain: str) -> dict:
    now = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scans (id, domain, status, created_at) VALUES (?, ?, 'queued', ?)",
            (scan_id, domain, now),
        )
        await db.commit()
    return {"id": scan_id, "domain": domain, "status": "queued", "created_at": now}


async def update_scan_status(scan_id: str, status: str):
    async with aiosqlite.connect(DB_PATH) as db:
        if status in ("completed", "error", "timeout"):
            await db.execute(
                "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
                (status, time.time(), scan_id),
            )
        else:
            await db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status, scan_id),
            )
        await db.commit()


async def insert_result(scan_id: str, tool: str, line: str) -> dict:
    ts = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO results (scan_id, tool, line, ts) VALUES (?, ?, ?, ?)",
            (scan_id, tool, line, ts),
        )
        await db.commit()
    return {"tool": tool, "line": line, "ts": ts}


async def get_scan(scan_id: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return dict(row)


async def get_scan_results(scan_id: str) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT tool, line, ts FROM results WHERE scan_id = ? ORDER BY ts ASC",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_all_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
