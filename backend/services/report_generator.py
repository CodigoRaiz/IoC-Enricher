"""report_generator.py — Generación de reportes .docx con resultados de enriquecimiento de IoCs."""

import os
from datetime import datetime
from docx import Document
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn, nsdecls
from docx.oxml import parse_xml


VERDICT_COLORS = {
    "malicious":  "FF0000",   # Red
    "suspicious": "FFD700",   # Yellow/Gold
    "clean":      "00AA00",   # Green
    "unknown":    "C0C0C0",   # Gray
}


def _set_cell_shading(cell, hex_color: str):
    """Set background color of a table cell."""
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)


def _set_cell_text(cell, text: str, bold: bool = False, size: int = 10, color: str = None, alignment: int = None):
    """Set text in a table cell with formatting."""
    cell.text = ""
    p = cell.paragraphs[0]
    if alignment is not None:
        p.alignment = alignment
    run = p.add_run(text)
    run.font.size = Pt(size)
    run.bold = bold
    if color:
        run.font.color.rgb = RGBColor.from_string(color)


def _add_cover_page(doc: Document, ioc: str, ioc_type: str):
    """Build the cover page (Page 1)."""
    # Logo placeholder row
    logo_paragraph = doc.add_paragraph()
    logo_paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT

    # Gray rectangle placeholder "LOGO"
    run = logo_paragraph.add_run("LOGO")
    run.font.size = Pt(24)
    run.font.color.rgb = RGBColor(0xAA, 0xAA, 0xAA)
    run.bold = True

    # Add spacing
    doc.add_paragraph()

    # Title
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("Reporte de Inteligencia de Amenazas")
    run.font.size = Pt(26)
    run.bold = True

    # Date/time right-aligned
    date_para = doc.add_paragraph()
    date_para.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    run = date_para.add_run(now)
    run.font.size = Pt(11)
    run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    doc.add_paragraph()  # spacer

    # Metadata table
    table = doc.add_table(rows=1, cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"

    headers = ["IoC", "Tipo", "Fecha", "Analista"]
    values = [ioc, ioc_type.upper(), now, ""]

    for i, (header, value) in enumerate(zip(headers, values)):
        cell = table.rows[0].cells[i]
        _set_cell_shading(cell, "E0E0E0")
        _set_cell_text(cell, f"{header}\n{value}", bold=True, size=10, alignment=WD_ALIGN_PARAGRAPH.CENTER)

    # Set column widths
    widths = [Cm(5), Cm(3), Cm(4), Cm(4)]
    for row in table.rows:
        for idx, width in enumerate(widths):
            row.cells[idx].width = width

    doc.add_page_break()


def _add_executive_summary(doc: Document, ai_summary: str, results: dict):
    """Build the executive summary page (Page 2)."""
    # Section title
    heading = doc.add_heading("Resumen Ejecutivo IA", level=1)

    # AI summary text
    p = doc.add_paragraph()
    run = p.add_run(ai_summary if ai_summary else "No disponible.")
    run.font.size = Pt(11)

    doc.add_paragraph()  # spacer

    # Verdict table
    table = doc.add_table(rows=1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"

    # Header row
    for idx, header in enumerate(["Fuente", "Veredicto", "Detalle"]):
        cell = table.rows[0].cells[idx]
        _set_cell_shading(cell, "333333")
        _set_cell_text(cell, header, bold=True, size=10, color="FFFFFF", alignment=WD_ALIGN_PARAGRAPH.CENTER)

    # Data rows
    for source_name, result in results.items():
        verdict = result.get("verdict", "unknown").lower()
        detail = result.get("detail", "Sin detalle")
        color_hex = VERDICT_COLORS.get(verdict, "C0C0C0")

        row = table.add_row()
        _set_cell_text(row.cells[0], source_name, bold=True, size=10)
        _set_cell_text(row.cells[1], verdict.upper(), bold=True, size=10, alignment=WD_ALIGN_PARAGRAPH.CENTER)
        _set_cell_text(row.cells[2], str(detail), size=9)

        # Color the verdict cell
        _set_cell_shading(row.cells[1], color_hex)
        # Text color for readability on dark backgrounds
        if verdict in ("malicious",):
            _set_cell_text(row.cells[1], verdict.upper(), bold=True, size=10,
                           color="FFFFFF", alignment=WD_ALIGN_PARAGRAPH.CENTER)

    doc.add_page_break()


def _add_source_evidence(doc: Document, source_name: str, result: dict, screenshot_bytes: bytes = None):
    """Add evidence section for one source (Pages 3+)."""
    # Source heading
    doc.add_heading(source_name, level=2)

    # Web URL
    web_url = result.get("web_url", "")
    if web_url:
        p = doc.add_paragraph()
        run = p.add_run(f"URL: {web_url}")
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0x00, 0x00, 0xCC)

    if screenshot_bytes:
        # Add screenshot as full-width image
        from docx.shared import Cm
        from io import BytesIO
        image_stream = BytesIO(screenshot_bytes)
        paragraph = doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run()
        # Add image with width matching page margins (approx 15cm for A4)
        run.add_picture(image_stream, width=Cm(15))
    else:
        # No screenshot: show API result text
        detail = result.get("detail", "Sin detalle")
        p = doc.add_paragraph()
        run = p.add_run(f"Resultado: {detail}")
        run.font.size = Pt(10)

    doc.add_paragraph()  # space between sources


def _add_footer(section):
    """Add footer with text and page number to a section."""
    footer = section.footer
    footer.is_linked_to_previous = False

    p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Footer text
    run = p.add_run("IOC Enricher — Uso interno SOC  |  ")
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(0x88, 0x88, 0x88)

    # Page number field
    fld_char_begin = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>')
    run_fld = p.add_run()
    run_fld._r.append(fld_char_begin)

    run_page = p.add_run()
    instr = parse_xml(f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>')
    run_page._r.append(instr)

    fld_char_end = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>')
    run_end = p.add_run()
    run_end._r.append(fld_char_end)


def generate_word_report(ioc: str, ioc_type: str, results: dict, ai_summary: str,
                         screenshots_dict: dict) -> bytes:
    """
    Generate a .docx report for a single IoC.

    Args:
        ioc: The indicator of compromise string.
        ioc_type: Type of IoC (ip, domain, url, hash).
        results: Dictionary mapping source_name -> {verdict, detail, web_url, ...}.
        ai_summary: Executive summary text from AI.
        screenshots_dict: Dictionary mapping source_name -> PNG bytes (or None).

    Returns:
        .docx file as bytes.
    """
    doc = Document()

    # Default font
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    # --- Page 1: Cover ---
    _add_cover_page(doc, ioc, ioc_type)

    # --- Page 2: Executive Summary ---
    _add_executive_summary(doc, ai_summary, results)

    # --- Pages 3+: Evidence per source ---
    for source_name, result in results.items():
        screenshot_bytes = screenshots_dict.get(source_name)
        _add_source_evidence(doc, source_name, result, screenshot_bytes)

    # Apply footer to all sections
    for section in doc.sections:
        _add_footer(section)

    # Save to bytes
    from io import BytesIO
    buf = BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()