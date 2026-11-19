#!/usr/bin/env python3
"""
Convert a Markdown file to a clean, printable .docx.

Purpose-built for this repo's walkthrough document — not a general Markdown engine.
It handles the constructs that doc actually uses:
  - headings (#, ##, ###)
  - paragraphs, blockquotes (>)
  - bullet lists (-, *) and numbered lists (1.)
  - fenced code blocks (```)
  - pipe tables
  - inline: **bold**, *italic*, `code`, and [label](target) links

It deliberately:
  - strips any <style>...</style> HTML block (meaningless in Word),
  - flattens links to readable plain text: a `#Lnn` anchor becomes
    "label (file: line nn)"; other links become "label (target)"; a same-doc
    .md link keeps just the label.

Usage:
    python scripts/md_to_docx.py <input.md> [output.docx]
"""
import os
import re
import sys

from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
INLINE_RE = re.compile(r"(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)")
CODE_FONT = "Consolas"


def flatten_links(text: str) -> str:
    """Turn [label](target) into readable plain text for print."""
    def repl(m):
        label, target = m.group(1), m.group(2)
        mL = re.search(r"#L(\d+)$", target)
        if mL:
            path = target[: mL.start()].split("/")[-1]
            return f"{label} ({path}: line {mL.group(1)})"
        if target.endswith(".md"):
            return label  # same-doc companion link — just the label
        if target.startswith(("http://", "https://")):
            return f"{label} ({target})"
        return f"{label} ({target})"
    return LINK_RE.sub(repl, text)


def add_runs(paragraph, text: str):
    """Add inline-formatted runs (**bold**, *italic*, `code`) to a paragraph."""
    text = flatten_links(text)
    for part in INLINE_RE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            r = paragraph.add_run(part[2:-2]); r.bold = True
        elif part.startswith("*") and part.endswith("*"):
            r = paragraph.add_run(part[1:-1]); r.italic = True
        elif part.startswith("`") and part.endswith("`"):
            r = paragraph.add_run(part[1:-1]); r.font.name = CODE_FONT
            r.font.color.rgb = RGBColor(0x1F, 0x2D, 0x3D)
        else:
            paragraph.add_run(part)


def parse_table(lines, i, doc):
    """Consume a pipe-table starting at lines[i]; return the next index."""
    rows = []
    while i < len(lines) and lines[i].strip().startswith("|"):
        raw = lines[i].strip().strip("|")
        # skip the header separator row (---|---)
        if not re.match(r"^\s*:?-{2,}", raw.split("|")[0].strip() or "-"):
            cells = [c.strip() for c in raw.split("|")]
            rows.append(cells)
        elif set(raw.replace("|", "").replace(":", "").replace("-", "").strip()) == set():
            pass  # separator
        else:
            cells = [c.strip() for c in raw.split("|")]
            rows.append(cells)
        i += 1
    # filter out any separator rows that slipped through
    rows = [r for r in rows if not all(re.match(r"^:?-{2,}:?$", c or "-") for c in r)]
    if rows:
        ncols = max(len(r) for r in rows)
        table = doc.add_table(rows=0, cols=ncols)
        table.style = "Light Grid Accent 1"
        for r in rows:
            cells = table.add_row().cells
            for j in range(ncols):
                cells[j].text = ""
                p = cells[j].paragraphs[0]
                add_runs(p, r[j] if j < len(r) else "")
    return i


def convert(md_path: str, docx_path: str):
    with open(md_path, encoding="utf-8") as f:
        text = f.read()

    # Strip any <style>...</style> block.
    text = re.sub(r"<style>.*?</style>\s*", "", text, flags=re.DOTALL | re.IGNORECASE)
    lines = text.split("\n")

    doc = Document()
    doc.styles["Normal"].font.size = Pt(11)

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Fenced code block
        if stripped.startswith("```"):
            i += 1
            code_lines = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i]); i += 1
            i += 1  # closing fence
            p = doc.add_paragraph()
            r = p.add_run("\n".join(code_lines))
            r.font.name = CODE_FONT
            r.font.size = Pt(9.5)
            r.font.color.rgb = RGBColor(0x1F, 0x2D, 0x3D)
            continue

        # Table
        if stripped.startswith("|"):
            i = parse_table(lines, i, doc); continue

        # Horizontal rule
        if re.match(r"^\s*---+\s*$", line):
            doc.add_paragraph().add_run("").add_break(); i += 1; continue

        # Headings
        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            level = min(len(m.group(1)), 4)
            h = doc.add_heading(level=level)
            add_runs(h, m.group(2))
            i += 1; continue

        # Blockquote
        if stripped.startswith(">"):
            p = doc.add_paragraph(style="Intense Quote")
            add_runs(p, stripped.lstrip(">").strip())
            i += 1; continue

        # Numbered list
        m = re.match(r"^(\s*)\d+\.\s+(.*)$", line)
        if m:
            p = doc.add_paragraph(style="List Number")
            add_runs(p, m.group(2))
            i += 1; continue

        # Bullet list
        m = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        if m:
            p = doc.add_paragraph(style="List Bullet")
            add_runs(p, m.group(2))
            i += 1; continue

        # Blank
        if not stripped:
            i += 1; continue

        # Paragraph
        p = doc.add_paragraph()
        add_runs(p, stripped)
        i += 1

    doc.save(docx_path)
    print(f"Wrote {docx_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/md_to_docx.py <input.md> [output.docx]")
        sys.exit(2)
    md_path = sys.argv[1]
    docx_path = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(md_path)[0] + ".docx"
    convert(md_path, docx_path)


if __name__ == "__main__":
    main()
