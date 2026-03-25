import csv
import io
import time
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def export_csv(scan: dict, results: list[dict]) -> str:
    """Generate CSV string from scan results."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["tool", "output", "timestamp"])
    for r in results:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        writer.writerow([r["tool"], r["line"], ts])
    return output.getvalue()


def export_pdf(scan: dict, results: list[dict]) -> bytes:
    """Generate PDF bytes from scan results."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SaraTitle", parent=styles["Title"], fontSize=20, spaceAfter=12,
        textColor=colors.HexColor("#6366f1"),
    )
    heading_style = ParagraphStyle(
        "SaraHeading", parent=styles["Heading2"], fontSize=13, spaceAfter=8,
        textColor=colors.HexColor("#f0f0f5"),
    )
    body_style = ParagraphStyle(
        "SaraBody", parent=styles["Normal"], fontSize=9, leading=12,
        textColor=colors.HexColor("#333333"),
    )

    elements = []

    # Title
    elements.append(Paragraph("SARA Scan Report", title_style))
    elements.append(Spacer(1, 4 * mm))

    # Scan metadata
    created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan["created_at"]))
    finished = ""
    if scan.get("finished_at"):
        finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan["finished_at"]))

    meta_data = [
        ["Domain", scan["domain"]],
        ["Scan ID", scan["id"]],
        ["Status", scan["status"]],
        ["Started", created],
        ["Finished", finished or "N/A"],
    ]
    meta_table = Table(meta_data, colWidths=[80, 400])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 6 * mm))

    # Group results by tool
    tools_order = ["subfinder", "httpx", "ffuf", "nuclei", "system"]
    grouped = {}
    for r in results:
        grouped.setdefault(r["tool"], []).append(r)

    for tool in tools_order:
        if tool not in grouped or tool == "system":
            continue
        tool_results = grouped[tool]
        elements.append(Paragraph(f"{tool.upper()} ({len(tool_results)} results)", heading_style))

        table_data = [["#", "Output", "Time"]]
        for i, r in enumerate(tool_results, 1):
            ts = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
            line_text = r["line"][:120]  # truncate long lines
            table_data.append([str(i), line_text, ts])

        if len(table_data) > 1:
            t = Table(table_data, colWidths=[30, 390, 60])
            t.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f8fc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(t)
        elements.append(Spacer(1, 4 * mm))

    doc.build(elements)
    return buf.getvalue()
