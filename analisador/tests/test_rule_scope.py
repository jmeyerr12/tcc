#!/usr/bin/env python3
"""Check real rules and the paired experimental artifacts."""

import re
import subprocess
import sys
import tempfile
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
ALGORITHM = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "build/alg"
sys.path.insert(0, str(ROOT / "analisador"))
from extract_original_rules import classify_rule
from generate_rule_groups import generate


def sids(text):
    return re.findall(r"\bsid\s*:\s*(\d+)\s*;", text)


def protocol_by_sid(text):
    result = {}
    for line in text.splitlines():
        sid = re.search(r"\bsid\s*:\s*(\d+)\s*;", line)
        protocol = re.match(r"\s*(?:alert|log|pass|drop|reject|sdrop)\s+(\S+)", line)
        if sid and protocol:
            result[sid.group(1)] = protocol.group(1).lower()
    return result


def run(source, destination):
    return subprocess.run(
        [str(ALGORITHM), str(source), str(destination)],
        check=True, capture_output=True, text=True,
    ).stdout


with tempfile.TemporaryDirectory(prefix="tcc-rule-scope-") as directory:
    temporary = Path(directory)
    output = temporary / "adapted.rules"

    run(ROOT / 'suricata.rules', output)
    accepted_sids = Counter(sids(output.read_text()))
    grouped_sids = Counter()
    for path in ROOT.glob('*-rules/*-adapted.rules'):
        grouped_sids.update(sids(path.read_text()))
    assert grouped_sids == accepted_sids, (
        'Groups must contain ALL accepted rules exactly once',
        'missing', sum((accepted_sids - grouped_sids).values()),
        'extra/duplicate', sum((grouped_sids - accepted_sids).values()),
    )

    generated = temporary / 'generated'
    generate(ROOT / 'suricata.rules', ALGORITHM, generated)

    for folder, stem in (
        ("application-rules", "original-application"),
        ("transport-rules", "original-tcp-udp"),
        ("ip-rules", "original-ip"),
    ):
        source = ROOT / folder / (stem + ".rules")
        adapted = ROOT / folder / (stem + "-adapted.rules")
        summary = run(source, output)
        expected_sids = sids(source.read_text())
        for line in source.read_text().splitlines():
            assert classify_rule(line) == folder.removesuffix('-rules'), folder
        assert expected_sids == sids(adapted.read_text()), folder
        assert output.read_bytes() == adapted.read_bytes(), folder
        assert summary == (ROOT / folder / "summary.txt").read_text(), folder
        for name in (source.name, adapted.name, 'summary.txt'):
            assert (generated / folder / name).read_bytes() == (ROOT / folder / name).read_bytes()

    original = ROOT / "application-rules/original-application.rules"
    adapted = ROOT / "application-rules/original-application-adapted.rules"
    original_protocols = protocol_by_sid(original.read_text())
    adapted_text = adapted.read_text()
    adapted_protocols = protocol_by_sid(adapted_text)
    for sid in ("2024212", "2057247", "2008605", "2009477"):
        assert original_protocols[sid] in {"smb", "ssh", "http"}
        assert adapted_protocols[sid] == "tcp"
        line = next(line for line in adapted_text.splitlines() if f"sid:{sid};" in line)
        assert re.search(r"\bflow\s*:[^;]*\bno_stream\b", line)
    assert "Merged:\n4-183\n" in (ROOT / "application-rules/summary.txt").read_text()

print("OK: cobertura integral, grupos disjuntos, regeneracao e pares original/adaptado")
