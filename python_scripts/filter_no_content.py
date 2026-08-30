#!/usr/bin/env python3
import argparse
import csv
import re
from pathlib import Path


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


def split_options(options: str):
    result = []
    current = []
    inside_quotes = False
    escaped = False

    for c in options:
        if escaped:
            current.append(c)
            escaped = False
            continue

        if c == "\\":
            current.append(c)
            escaped = True
            continue

        if c == '"':
            inside_quotes = not inside_quotes
            current.append(c)
            continue

        if c == ";" and not inside_quotes:
            opt = "".join(current).strip()
            if opt:
                result.append(opt)
            current = []
        else:
            current.append(c)

    opt = "".join(current).strip()
    if opt:
        result.append(opt)

    return result


def extract_options(rule: str):
    open_paren = rule.find("(")
    close_paren = rule.rfind(")")

    if open_paren == -1 or close_paren == -1 or close_paren <= open_paren:
        return []

    return split_options(rule[open_paren + 1:close_paren])


def has_content(rule: str) -> bool:
    options = extract_options(rule)

    for opt in options:
        name = opt.split(":", 1)[0].strip().lower()

        if name == "content":
            return True

    return False


def extract_sid(rule: str) -> str:
    match = re.search(r"\bsid\s*:\s*(\d+)", rule)
    return match.group(1) if match else ""


def extract_msg(rule: str) -> str:
    match = re.search(r'\bmsg\s*:\s*"((?:\\.|[^"\\])*)"', rule)
    return match.group(1) if match else ""


def is_rule_line(line: str) -> bool:
    stripped = line.strip()
    return bool(re.match(r"^(alert|log|pass|drop|reject|sdrop)\b", stripped))


def main():
    parser = argparse.ArgumentParser(
        description="Filtra regras Snort que não possuem a opção content."
    )

    parser.add_argument("input_rules", help="Arquivo .rules de entrada")
    parser.add_argument("output_rules", help="Arquivo .rules com regras sem content")
    parser.add_argument(
        "--csv",
        default="rules_without_content.csv",
        help="Relatório CSV das regras sem content"
    )

    args = parser.parse_args()

    input_path = Path(args.input_rules)
    output_path = Path(args.output_rules)
    csv_path = Path(args.csv)

    total_rules = 0
    without_content = 0
    with_content = 0

    selected_rules = []
    report_rows = []

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, original_line in enumerate(f, start=1):
            cleaned = remove_comment(original_line).strip()

            if not cleaned:
                continue

            if not is_rule_line(cleaned):
                continue

            total_rules += 1

            if has_content(cleaned):
                with_content += 1
                continue

            without_content += 1
            selected_rules.append(original_line.rstrip("\n"))

            report_rows.append({
                "line": line_number,
                "sid": extract_sid(cleaned),
                "msg": extract_msg(cleaned),
                "rule": cleaned
            })

    with output_path.open("w", encoding="utf-8") as f:
        f.write("# Regras Snort sem a opcao content\n")
        f.write(f"# Arquivo original: {input_path}\n")
        f.write(f"# Total de regras analisadas: {total_rules}\n")
        f.write(f"# Regras sem content: {without_content}\n\n")

        for rule in selected_rules:
            f.write(rule + "\n")

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["line", "sid", "msg", "rule"])
        writer.writeheader()
        writer.writerows(report_rows)

    print("Resumo")
    print("======")
    print(f"Arquivo analisado: {input_path}")
    print(f"Total de regras: {total_rules}")
    print(f"Com content: {with_content}")
    print(f"Sem content: {without_content}")
    print(f"Arquivo gerado: {output_path}")
    print(f"Relatorio CSV: {csv_path}")


if __name__ == "__main__":
    main()