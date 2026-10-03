#!/usr/bin/env python3
"""Regenerate the three groups from ALL rules accepted by the adapter."""
import argparse
from pathlib import Path
import subprocess
import tempfile

from extract_original_rules import classify_rule, get_protocol, get_sid

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    'application': 'original-application',
    'transport': 'original-tcp-udp',
    'ip': 'original-ip',
}


def load_rules(path):
    rules = {}
    for line in path.read_text().splitlines():
        if not get_protocol(line):
            continue
        sid = get_sid(line)
        if sid is None or sid in rules:
            raise ValueError(f'{path}: missing or duplicate SID: {sid}')
        rules[sid] = line
    return rules


def adapt(algorithm, source, destination):
    return subprocess.run(
        [str(algorithm), str(source), str(destination)],
        check=True, capture_output=True, text=True,
    ).stdout


def generate(source, algorithm, destination):
    originals = load_rules(source)
    # Stage and validate everything before replacing the experimental files.
    with tempfile.TemporaryDirectory(prefix='tcc-rule-groups-') as directory:
        stage = Path(directory)
        full = stage / 'all-adapted.rules'
        full_summary = adapt(algorithm, source, full)
        accepted = load_rules(full)
        if not accepted.keys() <= originals.keys():
            raise ValueError('Adapter output contains unknown SIDs')
        groups = {group: {} for group in GROUPS}
        for sid, line in originals.items():
            if sid in accepted:
                groups[classify_rule(line)][sid] = line

        for group, stem in GROUPS.items():
            folder = stage / f'{group}-rules'
            folder.mkdir()
            original = folder / f'{stem}.rules'
            original.write_text(''.join(line + '\n' for line in groups[group].values()))
            adapted = folder / f'{stem}-adapted.rules'
            # Offsets must match this group's intervals, not the global cuts.
            summary = adapt(algorithm, original, adapted)
            if list(load_rules(adapted)) != list(groups[group]):
                raise ValueError(f'{group}: adapter changed the accepted SID list')
            (folder / 'summary.txt').write_text(summary)

        for group in GROUPS:
            target = destination / f'{group}-rules'
            target.mkdir(parents=True, exist_ok=True)
            for path in (stage / target.name).iterdir():
                (target / path.name).write_bytes(path.read_bytes())
            print(f'{group}: {len(groups[group])} regras')
        print(f'Total: {len(accepted)} regras aceitas, sem omissoes ou repeticoes')
        print(full_summary.split('Resumo das regras:\n', 1)[1], end='')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'suricata.rules')
    parser.add_argument('--algorithm', type=Path, default=ROOT / 'build/alg')
    parser.add_argument('--output-dir', type=Path, default=ROOT)
    args = parser.parse_args()
    generate(args.source.resolve(), args.algorithm.resolve(), args.output_dir.resolve())


if __name__ == '__main__':
    main()
