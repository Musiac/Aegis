"""Markdown -> Word, shared by Aegis so a report never shows raw ** or | or --- (seen in a real report: bold labels, a pipe table and a rule printed as
literal characters). Supports: # headings, ---/***/___ rules, pipe tables (header row, cell formatting), - * bullets (nested by indent), 1. numbered items (printed as
text, see note), > quotes, ``` code blocks, and inline **bold**, __bold__, *italic*, `code`, [text](url). Everything is plain python-docx; nothing is executed or fetched."""
import re

from docx.enum.text import WD_BREAK  # noqa: F401  (kept for callers that want page breaks)
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

_INLINE = re.compile(r"(\*\*[^*\n]+?\*\*|__[^_\n]+?__|`[^`\n]+`|\[[^\]\n]+\]\([^)\s]+\)|(?<![\w*])\*[^*\s][^*\n]*?\*(?![\w*]))")
_RULE = re.compile(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
_HEAD = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_BULLET = re.compile(r"^(\s*)([-*•])\s+(.*)$")
_NUMBERED = re.compile(r"^(\s*)(\d+[.)])\s+(.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_FENCE = re.compile(r"^\s*```")
MAX_COLS = 8


def add_runs(paragraph, text: str, bold: bool = False, size=None):
    """Inline markdown inside one line -> runs."""
    for part in _INLINE.split(text or ""):
        if not part:
            continue
        run = None
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            run = paragraph.add_run(part[2:-2]); run.bold = True
        elif part.startswith("__") and part.endswith("__") and len(part) > 4:
            run = paragraph.add_run(part[2:-2]); run.bold = True
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            run = paragraph.add_run(part[1:-1]); run.font.name = "Consolas"; run.font.size = Pt(9.5)
            _shade_run(run, "EEEEEE")
        elif part.startswith("[") and "](" in part and part.endswith(")"):
            label, url = part[1:-1].split("](", 1)
            run = paragraph.add_run(f"{label} ({url})")
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            run = paragraph.add_run(part[1:-1]); run.italic = True
        else:
            run = paragraph.add_run(part)
        if bold:
            run.bold = True
        if size and not (part.startswith("`") and part.endswith("`")):
            run.font.size = size
    return paragraph


def _shade_run(run, fill: str):
    rpr = run._r.get_or_add_rPr()
    shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill)
    rpr.append(shd)


def _shade_cell(cell, fill: str):
    tcpr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill)
    tcpr.append(shd)


def _rule(doc):
    p = doc.add_paragraph()
    ppr = p._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    for k, v in (("w:val", "single"), ("w:sz", "6"), ("w:space", "1"), ("w:color", "999999")):
        bottom.set(qn(k), v)
    borders.append(bottom); ppr.append(borders)
    p.paragraph_format.space_after = Pt(6)


def _split_row(line: str) -> list:
    t = line.strip()
    if t.startswith("|"):
        t = t[1:]
    if t.endswith("|"):
        t = t[:-1]
    return [c.strip() for c in t.split("|")]


def _table(doc, rows: list, style: str = "Table Grid", max_cols: int = MAX_COLS):
    ncols = min(max(len(r) for r in rows), max_cols)
    table = doc.add_table(rows=len(rows), cols=ncols)
    try:
        table.style = style
    except Exception:                                                         # noqa: BLE001 -- style missing in a custom template
        pass
    for r, cells in enumerate(rows):
        for c in range(ncols):
            cell = table.cell(r, c)
            para = cell.paragraphs[0]
            add_runs(para, cells[c] if c < len(cells) else "", bold=(r == 0), size=Pt(10))
            if r == 0 and style == "Table Grid":
                _shade_cell(cell, "D9E2F3")
    doc.add_paragraph()


def add_markdown(doc, body: str, max_chars: int = 200_000, table_style: str = "Table Grid", max_cols: int = MAX_COLS):
    lines = (body or "")[:max_chars].replace("\r", "").split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        s = raw.strip()
        if not s:
            i += 1
            continue
        if _FENCE.match(raw):                                                  # code block: monospace, untouched
            i += 1
            buf = []
            while i < len(lines) and not _FENCE.match(lines[i]):
                buf.append(lines[i].rstrip()); i += 1
            i += 1
            for ln in buf or [""]:
                p = doc.add_paragraph()
                run = p.add_run(ln); run.font.name = "Consolas"; run.font.size = Pt(9)
                p.paragraph_format.space_after = Pt(0); p.paragraph_format.left_indent = Pt(12)
            continue
        if _RULE.match(raw):
            _rule(doc); i += 1; continue
        m = _HEAD.match(s)
        if m:
            doc.add_heading(m.group(2), level=min(len(m.group(1)), 3)); i += 1; continue
        if s.startswith("|"):                                                   # pipe table
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                if not _TABLE_SEP.match(lines[i]):
                    rows.append(_split_row(lines[i]))
                i += 1
            if rows:
                _table(doc, rows, table_style, max_cols)
            continue
        if s.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip()); i += 1
            p = doc.add_paragraph(); add_runs(p, " ".join(buf))
            for r in p.runs: r.italic = True
            p.paragraph_format.left_indent = Pt(18)
            continue
        m = _BULLET.match(raw)
        if m:
            depth = min(len(m.group(1).replace("\t", "    ")) // 2, 2)
            style = "List Bullet" if depth == 0 else f"List Bullet {depth + 1}"
            try:
                p = doc.add_paragraph(style=style)
            except KeyError:
                p = doc.add_paragraph(style="List Bullet")
            add_runs(p, m.group(3)); i += 1; continue
        m = _NUMBERED.match(raw)
        if m:
            # numbers are printed as text: Word's built-in list-number style shares one counter across the whole document (a second list continued at 11.)
            p = doc.add_paragraph(style="List Paragraph")
            p.add_run(m.group(2) + " "); add_runs(p, m.group(3)); i += 1; continue
        add_runs(doc.add_paragraph(), s); i += 1
