#!/usr/bin/env python3
"""Build the student execution runbook DOCX from its reviewed Markdown source."""

from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/Student_Experiment_Execution_Runbook.md"
OUTPUT = ROOT / "docs/VPNGUARD_X_Student_Experiment_Runbook.docx"


def _font(run, name: str, size: float | None = None, bold: bool | None = None) -> None:
    run.font.name = name
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), name)
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), name)
    run.font.color.rgb = RGBColor(0, 0, 0)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold


def _cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shading = tc_pr.find(qn("w:shd"))
    if shading is None:
        shading = OxmlElement("w:shd")
        tc_pr.append(shading)
    shading.set(qn("w:fill"), fill)


def _cell_margin(cell, top: int = 90, start: int = 100, bottom: int = 90, end: int = 100) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    margins = tc_pr.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        tc_pr.append(margins)
    for name, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        element = margins.find(qn(f"w:{name}"))
        if element is None:
            element = OxmlElement(f"w:{name}")
            margins.append(element)
        element.set(qn("w:w"), str(value))
        element.set(qn("w:type"), "dxa")


def _set_table_borders(table) -> None:
    table_pr = table._tbl.tblPr
    borders = table_pr.find(qn("w:tblBorders"))
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        table_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        tag = borders.find(qn(f"w:{edge}"))
        if tag is None:
            tag = OxmlElement(f"w:{edge}")
            borders.append(tag)
        tag.set(qn("w:val"), "single")
        tag.set(qn("w:sz"), "5")
        tag.set(qn("w:color"), "D9D9D9")


def _set_repeat_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    repeat = OxmlElement("w:tblHeader")
    repeat.set(qn("w:val"), "true")
    tr_pr.append(repeat)


def _prevent_row_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    if tr_pr.find(qn("w:cantSplit")) is None:
        tr_pr.append(OxmlElement("w:cantSplit"))


def _remove_paragraph_border(paragraph_or_style) -> None:
    paragraph_format_owner = getattr(paragraph_or_style, "_p", None)
    if paragraph_format_owner is not None:
        p_pr = paragraph_format_owner.get_or_add_pPr()
    else:
        p_pr = paragraph_or_style.element.get_or_add_pPr()
    border = p_pr.find(qn("w:pBdr"))
    if border is not None:
        p_pr.remove(border)


def _add_inline(paragraph, text: str, *, code_font: bool = False) -> None:
    pattern = re.compile(r"(\*\*.+?\*\*|`.+?`)")
    cursor = 0
    for match in pattern.finditer(text):
        if match.start() > cursor:
            run = paragraph.add_run(text[cursor : match.start()])
            _font(run, "Aptos", 10.5)
        token = match.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            _font(run, "Aptos", 10.5, True)
        else:
            run = paragraph.add_run(token[1:-1])
            _font(run, "Consolas", 9.4)
        cursor = match.end()
    if cursor < len(text):
        run = paragraph.add_run(text[cursor:])
        _font(run, "Consolas" if code_font else "Aptos", 9.4 if code_font else 10.5)


def _add_page_field(paragraph) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = "PAGE"
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instruction, separate, text, end])
    _font(run, "Aptos", 8.5)


def _configure_document(document: Document) -> None:
    section = document.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(0.72)
    section.bottom_margin = Inches(0.68)
    section.left_margin = Inches(0.78)
    section.right_margin = Inches(0.78)

    normal = document.styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor(0, 0, 0)
    normal.paragraph_format.space_after = Pt(5)
    normal.paragraph_format.line_spacing = 1.08
    for name, size, before, after in (
        ("Title", 24, 0, 14),
        ("Subtitle", 13, 0, 10),
        ("Heading 1", 16, 14, 7),
        ("Heading 2", 12.5, 11, 5),
        ("Heading 3", 11, 8, 4),
    ):
        style = document.styles[name]
        style.font.name = "Aptos Display" if name != "Normal" else "Aptos"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.font.bold = name != "Subtitle"
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
        _remove_paragraph_border(style)

    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = header.add_run("VPNGUARD X  |  SIH 26160")
    _font(run, "Aptos", 8.5, True)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run("Student experiment execution runbook   |   Page ")
    _font(run, "Aptos", 8.5)
    _add_page_field(footer)


def _cover(document: Document) -> None:
    paragraph = document.add_paragraph(style="Title")
    _remove_paragraph_border(paragraph)
    paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run = paragraph.add_run("VPNGUARD X Student Experiment Execution Runbook")
    _font(run, "Aptos Display", 24, True)
    subtitle = document.add_paragraph(style="Subtitle")
    run = subtitle.add_run("SIH 26160 Cyber Range Baselines and Five Seed Evaluation")
    _font(run, "Aptos Display", 13)
    document.add_paragraph()
    intro = document.add_paragraph()
    _add_inline(
        intro,
        "This manual gives the student team the executable path from an isolated IPsec cyber-range to traceable manuscript tables. It defines the required data, ownership, commands, acceptance gates, generalization tests, packet-loss analysis, and the preferred strongSwan-to-Libreswan validation.",
    )
    status = document.add_paragraph()
    _add_inline(status, "Empirical status  **TBD — requires experiment**")
    boundary = document.add_paragraph()
    _add_inline(boundary, "Safety boundary  Controlled institutional laboratory only. Do not scan, probe, capture, or interact with public or unauthorized systems.")
    metadata = document.add_paragraph()
    metadata.paragraph_format.space_before = Pt(16)
    _add_inline(metadata, "Repository procedure version  0.2.0\nPrepared for  VPNGUARD-X SIH 26160 student research team\nDate  14 September 2026")
    document.add_page_break()


def _add_table(document: Document, source_rows: list[str]) -> None:
    parsed = [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in source_rows]
    header = parsed[0]
    body = parsed[2:]
    table = document.add_table(rows=1, cols=len(header))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    _set_table_borders(table)
    _set_repeat_header(table.rows[0])
    _prevent_row_split(table.rows[0])
    for index, value in enumerate(header):
        cell = table.rows[0].cells[index]
        _cell_shading(cell, "1F4E78")
        _cell_margin(cell)
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        paragraph = cell.paragraphs[0]
        run = paragraph.add_run(value)
        _font(run, "Aptos", 9, True)
        run.font.color.rgb = RGBColor(255, 255, 255)
    for row_index, values in enumerate(body):
        row = table.add_row()
        _prevent_row_split(row)
        cells = row.cells
        for index, value in enumerate(values):
            cell = cells[index]
            _cell_margin(cell)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if row_index % 2:
                _cell_shading(cell, "F3F7FA")
            paragraph = cell.paragraphs[0]
            _add_inline(paragraph, value)
            for run in paragraph.runs:
                run.font.size = Pt(8.6)
    document.add_paragraph().paragraph_format.space_after = Pt(2)


def build() -> Path:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    document = Document()
    _configure_document(document)
    _cover(document)
    index = 0
    in_code = False
    code_lines: list[str] = []
    while index < len(lines):
        line = lines[index]
        if line.startswith("# "):
            index += 1
            continue
        if line.startswith("```"):
            if in_code:
                paragraph = document.add_paragraph()
                paragraph.paragraph_format.left_indent = Inches(0.2)
                paragraph.paragraph_format.right_indent = Inches(0.1)
                paragraph.paragraph_format.space_before = Pt(3)
                paragraph.paragraph_format.space_after = Pt(7)
                paragraph.paragraph_format.line_spacing = 1.0
                paragraph.paragraph_format.keep_together = True
                shading = OxmlElement("w:shd")
                shading.set(qn("w:fill"), "F2F2F2")
                paragraph._p.get_or_add_pPr().append(shading)
                run = paragraph.add_run("\n".join(code_lines))
                _font(run, "Consolas", 8.2)
                code_lines = []
                in_code = False
            else:
                in_code = True
            index += 1
            continue
        if in_code:
            code_lines.append(line)
            index += 1
            continue
        if line.startswith("|") and index + 1 < len(lines) and lines[index + 1].startswith("|---"):
            table_rows = [line, lines[index + 1]]
            index += 2
            while index < len(lines) and lines[index].startswith("|"):
                table_rows.append(lines[index])
                index += 1
            _add_table(document, table_rows)
            continue
        heading_match = re.match(r"^(#{2,4})\s+(.+)$", line)
        if heading_match:
            level = min(3, len(heading_match.group(1)) - 1)
            paragraph = document.add_paragraph(style=f"Heading {level}")
            _add_inline(paragraph, heading_match.group(2))
            index += 1
            continue
        if re.match(r"^\d+\.\s+", line):
            paragraph = document.add_paragraph(style="List Number")
            paragraph.paragraph_format.keep_together = True
            _add_inline(paragraph, re.sub(r"^\d+\.\s+", "", line))
            index += 1
            continue
        if line.startswith("- [ ] "):
            paragraph = document.add_paragraph(style="List Bullet")
            paragraph.paragraph_format.keep_together = True
            _add_inline(paragraph, "☐ " + line[6:])
            index += 1
            continue
        if line.startswith("- "):
            paragraph = document.add_paragraph(style="List Bullet")
            paragraph.paragraph_format.keep_together = True
            _add_inline(paragraph, line[2:])
            index += 1
            continue
        if not line.strip():
            index += 1
            continue
        paragraph = document.add_paragraph()
        _add_inline(paragraph, line.replace("  ", " "))
        index += 1

    core = document.core_properties
    core.title = "VPNGUARD X Student Experiment Execution Runbook"
    core.subject = "SIH 26160 cyber-range, dataset, baseline, and five-seed evaluation procedure"
    core.author = "VPNGUARD-X SIH 26160 Team"
    core.keywords = "IPsec, IKEv2, CGII, strongSwan, Libreswan, reproducibility"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document.save(OUTPUT)
    return OUTPUT


if __name__ == "__main__":
    print(build())
