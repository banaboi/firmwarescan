from __future__ import annotations

from datetime import date

from fpdf import FPDF # type: ignore

from models import Dependency, Finding, SEVERITY_ORDER

SEVERITY_COLOURS = {
    "CRITICAL": (180, 0,   0),
    "HIGH":     (220, 80,  0),
    "MEDIUM":   (200, 150, 0),
    "LOW":      (50,  120, 50),
    "NONE":     (120, 120, 120),
}


def create_pdf(
    dependencies: list[Dependency],
    findings: list[Finding],
    output_path: str = "report.pdf",
    scanned_path: str = "",
) -> None:
    pdf = FPDF()
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    _header(pdf, scanned_path)
    _summary(pdf, findings)
    _findings_table(pdf, findings)
    _dependencies_table(pdf, dependencies)

    pdf.output(output_path)


def _header(pdf: FPDF, scanned_path: str) -> None:
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "FirmwareScan Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Generated: {date.today().isoformat()}", new_x="LMARGIN", new_y="NEXT")
    if scanned_path:
        pdf.cell(0, 6, f"Scanned:   {scanned_path}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(6)


def _summary(pdf: FPDF, findings: list[Finding]) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    pdf.set_font("Helvetica", "B", 10)
    col_w = 44
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        r, g, b = SEVERITY_COLOURS[severity]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_w, 10, f"  {severity}: {counts[severity]}", fill=True, border=0)
    pdf.ln(14)


def _findings_table(pdf: FPDF, findings: list[Finding]) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, f"Findings ({len(findings)})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, "No vulnerabilities found.", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
        return

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)

    headers = ["CVE ID", "Component", "Ver", "Sev", "CVSS", "Description"]
    col_widths = [32, 28, 18, 20, 14, 68]

    pdf.set_fill_color(50, 50, 50)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    for header, w in zip(headers, col_widths):
        pdf.cell(w, 7, f" {header}", fill=True, border=0)
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for i, f in enumerate(sorted_findings):
        fill_colour = (245, 245, 245) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*fill_colour)
        pdf.set_text_color(30, 30, 30)

        score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
        desc = f.description[:95] + "…" if len(f.description) > 95 else f.description
        version = (f.dependency.version or "?")[:10]

        r, g, b = SEVERITY_COLOURS.get(f.severity, (120, 120, 120))

        pdf.cell(col_widths[0], 6, f" {f.cve_id}", fill=True, border=0)
        pdf.cell(col_widths[1], 6, f" {f.dependency.name}", fill=True, border=0)
        pdf.cell(col_widths[2], 6, f" {version}", fill=True, border=0)

        pdf.set_text_color(r, g, b)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(col_widths[3], 6, f" {f.severity}", fill=True, border=0)

        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_widths[4], 6, f" {score}", fill=True, border=0)
        pdf.cell(col_widths[5], 6, f" {desc}", fill=True, border=0)
        pdf.ln()

    pdf.ln(6)


def _dependencies_table(pdf: FPDF, dependencies: list[Dependency]) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, f"Dependencies Scanned ({len(dependencies)})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    headers = ["Name", "Version", "Source File", "Confidence"]
    col_widths = [40, 25, 95, 20]

    pdf.set_fill_color(50, 50, 50)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    for header, w in zip(headers, col_widths):
        pdf.cell(w, 7, f" {header}", fill=True, border=0)
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for i, dep in enumerate(dependencies):
        fill_colour = (245, 245, 245) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*fill_colour)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(col_widths[0], 6, f" {dep.name}", fill=True, border=0)
        pdf.cell(col_widths[1], 6, f" {dep.version or '?'}", fill=True, border=0)
        pdf.cell(col_widths[2], 6, f" {dep.source_file}", fill=True, border=0)
        pdf.cell(col_widths[3], 6, f" {dep.confidence}", fill=True, border=0)
        pdf.ln()
