#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

RULE_RE = re.compile(r"^\s*(alert|log|pass|drop|reject|sdrop)\b", re.IGNORECASE)

CONTENT_RE = re.compile(r'\bcontent\s*:', re.IGNORECASE)
OFFSET_RE = re.compile(r'\boffset\s*:?\s*-?\d+', re.IGNORECASE)
DEPTH_RE = re.compile(r'\bdepth\s*:?\s*\d+', re.IGNORECASE)


def remove_comment(line: str) -> str:
    inside_quotes = False
    escaped = False

    for i, c in enumerate(line):
        if escaped:
            escaped = False
            continue

        if c == "\\":
            escaped = True
            continue

        if c == '"':
            inside_quotes = not inside_quotes
            continue

        if c == "#" and not inside_quotes:
            return line[:i]

    return line


def is_rule(line: str) -> bool:
    return bool(RULE_RE.match(line.strip()))


def write_rules(path: Path, title: str, rules):
    with path.open("w", encoding="utf-8") as f:
        f.write(f"# {title}\n")
        f.write(f"# Total: {len(rules)}\n\n")

        for rule in rules:
            f.write(rule.rstrip("\n") + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Separa regras Snort em: sem content, com content+offset e com content+depth."
    )

    parser.add_argument("input_rules", help="Arquivo .rules de entrada")
    parser.add_argument("--out-dir", required=True, help="Diretorio de saida")

    args = parser.parse_args()

    input_path = Path(args.input_rules)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    total = 0
    no_content = []
    content_offset = []
    content_depth = []

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            cleaned = remove_comment(line).strip()

            if not cleaned:
                continue

            if not is_rule(cleaned):
                continue

            total += 1

            has_content = bool(CONTENT_RE.search(cleaned))
            has_offset = bool(OFFSET_RE.search(cleaned))
            has_depth = bool(DEPTH_RE.search(cleaned))

            if not has_content:
                no_content.append(cleaned)

            if has_content and has_offset:
                content_offset.append(cleaned)

            if has_content and has_depth:
                content_depth.append(cleaned)

    write_rules(
        out_dir / "rules_no_content.rules",
        "Regras sem content",
        no_content
    )

    write_rules(
        out_dir / "rules_content_offset.rules",
        "Regras com content e offset",
        content_offset
    )

    write_rules(
        out_dir / "rules_content_depth.rules",
        "Regras com content e depth",
        content_depth
    )

    with (out_dir / "summary.txt").open("w", encoding="utf-8") as f:
        f.write("Resumo da separacao de regras\n")
        f.write("============================\n\n")
        f.write(f"Arquivo analisado: {input_path}\n")
        f.write(f"Total de regras: {total}\n")
        f.write(f"Regras sem content: {len(no_content)}\n")
        f.write(f"Regras com content e offset: {len(content_offset)}\n")
        f.write(f"Regras com content e depth: {len(content_depth)}\n")

    print("Resumo")
    print("======")
    print(f"Arquivo analisado: {input_path}")
    print(f"Total de regras: {total}")
    print(f"Regras sem content: {len(no_content)}")
    print(f"Regras com content e offset: {len(content_offset)}")
    print(f"Regras com content e depth: {len(content_depth)}")
    print(f"Saida: {out_dir}")


if __name__ == "__main__":
    main()
