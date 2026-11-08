"""MkDocs hook: expand `{{ readme:<section> }}` and `{{ file:<path> }}` from repo files.

README.md is the single source; the docs pages are stubs that pull sections out of
it by the `<!-- --8<-- [start:x] -->` markers. Relative repo links in the pulled
text (examples/, LICENSE, test/...) are pointed at GitHub so they resolve on the site.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLOB = "https://github.com/anirudhbiyani/cloud-auth/blob/main/"
PLACEHOLDER = re.compile(r"\{\{\s*(readme|file):([^}\s]+)\s*\}\}")
LINK = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)")


def section(name: str) -> str:
    text = (ROOT / "README.md").read_text()
    start = f"<!-- --8<-- [start:{name}] -->"
    end = f"<!-- --8<-- [end:{name}] -->"
    if start not in text:
        raise ValueError(f"README.md has no section {name!r}")
    body = text.split(start, 1)[1].split(end, 1)[0]
    # The README's markers for nested sections are noise once pulled out.
    return re.sub(r"<!-- --8<-- \[(start|end):[^\]]+\] -->\n?", "", body).strip("\n")


# README anchors that live on another docs page.
CROSS_PAGE = {"#aws-proof-selection": "aws-proof.md#aws-proof-selection"}


def repo_links(text: str, base: Path, page_dir: Path, in_docs) -> str:
    """Point relative links at GitHub unless the target is a docs page (case-sensitive: macOS would say CONTRIBUTING.md exists when only contributing.md does)."""
    def fix(m):
        target = m.group(1)
        if target in CROSS_PAGE:
            return f"]({CROSS_PAGE[target]})"
        if target.startswith("#") or in_docs((page_dir / target.split("#")[0]).as_posix()):
            return m.group(0)
        rel = (base / target).resolve().relative_to(ROOT)
        return f"]({BLOB}{rel})"
    return LINK.sub(fix, text)


def on_page_markdown(markdown, page, config, files):
    page_dir = Path(page.file.src_path).parent

    def in_docs(rel: str) -> bool:
        return files.get_file_from_path(rel.removeprefix("./")) is not None

    def expand(m):
        kind, arg = m.group(1), m.group(2)
        if kind == "readme":
            return repo_links(section(arg), ROOT, page_dir, in_docs)
        src = ROOT / arg
        return repo_links(src.read_text(), src.parent, page_dir, in_docs)

    return PLACEHOLDER.sub(expand, markdown)
