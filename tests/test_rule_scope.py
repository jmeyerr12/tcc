#!/usr/bin/env python3
"""Check real excluded rules and the paired experimental artifacts."""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALGORITHM = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "build/alg"


def sids(text):
    return re.findall(r"\bsid\s*:\s*(\d+)\s*;", text)


def run(source, destination):
    return subprocess.run(
        [str(ALGORITHM), str(source), str(destination)],
        check=True, capture_output=True, text=True,
    ).stdout


with tempfile.TemporaryDirectory(prefix="tcc-rule-scope-") as directory:
    temporary = Path(directory)
    output = temporary / "adapted.rules"
    excluded = ROOT / "application-rules/excluded-application.rules"
    assert set(sids(excluded.read_text())) == {
        "2024212", "2057247", "2008605", "2009477",
    }
    summary = run(excluded, output)
    assert output.read_text() == "", "application rules must be excluded"
    assert "Intervalos extraidos: 0\n" in summary
    assert "Excluidas (nao tratadas): 4\n" in summary

    # Excluded application rules must not widen the remaining UDP interval.
    original = ROOT / "application-rules/original-application.rules"
    combined = temporary / "combined.rules"
    combined.write_text(original.read_text() + excluded.read_text())
    summary = run(combined, output)
    assert "Merged:\n16-23\n" in summary
    assert output.read_bytes() == original.with_name(
        "original-application-adapted.rules"
    ).read_bytes()

    for folder, stem in (
        ("application-rules", "original-application"),
        ("transport-rules", "original-tcp-udp"),
        ("ip-rules", "original-ip"),
    ):
        source = ROOT / folder / (stem + ".rules")
        adapted = ROOT / folder / (stem + "-adapted.rules")
        summary = run(source, output)
        assert sids(source.read_text()) == sids(adapted.read_text()), folder
        assert output.read_bytes() == adapted.read_bytes(), folder
        assert summary == (ROOT / folder / "summary.txt").read_text(), folder

print("OK: exclusoes reais, intervalos e pares original/adaptado")
