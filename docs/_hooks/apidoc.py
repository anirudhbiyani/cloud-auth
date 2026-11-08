"""MkDocs hook: regenerate docs/sdk/reference from the Go source before every build.

The pages are not committed; `go run ./internal/apidoc` writes them from go/doc, so
the API inventory is always the code's own. Needs a Go toolchain on PATH.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def on_pre_build(config):
    subprocess.run(["go", "run", "./internal/apidoc"], cwd=ROOT, check=True)
