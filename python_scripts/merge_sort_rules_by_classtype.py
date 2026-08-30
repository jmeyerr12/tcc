#!/usr/bin/env python3
import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

RULE_ACTION_RE = re.compile(r"^\s*(alert|log|pass|drop|reject|sdrop)\b", re.IGNORECASE)
COMMENTED_RULE_RE = re.compile(r"^\s*#\s*(alert|log|pass|drop|reject|sdrop)\b", re.IGNORECASE)


def strip_inline_comment(line: str) -> str:
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


def paren_balance(text: str) -> int:
    inside_quotes = False
    escaped = False
    balance = 0

    for c in text:
        if escaped:
            escaped = False
            continue

        if c == "\\":
            escaped = True
            continue

        if c == '"':
            inside_quotes = not inside_quotes
            continue

        if inside_quotes:
            continue

        if c == "(":
            balance += 1
        elif c == ")":
            balance -= 1

    return balance


def normalize_rule_line(lines):
    # Junta regra multiline em uma linha só, preservando espaços simples.
    return " ".join(line.strip() for line in lines if line.strip())


def iter_rules_from_file(path: Path, include_disabled: bool = False):
    buffer = []
    balance = 0
    start_line = None
    was_disabled = False

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            stripped = line.strip()

            if not buffer:
                if not stripped:
                    continue

                disabled_match = COMMENTED_RULE_RE.match(line)
                active_match = RULE_ACTION_RE.match(line)

                if disabled_match and include_disabled:
                    # Remove só o primeiro # para tratar como regra.
                    line = re.sub(r"^\s*#\s*", "", line, count=1)
                    was_disabled = True
                elif active_match:
                    was_disabled = False
                else:
                    continue

                buffer = [strip_inline_comment(line)]
                balance = paren_balance(buffer[0])
                start_line = line_no

                if balance <= 0 and ")" in buffer[0]:
                    yield normalize_rule_line(buffer), start_line, was_disabled
                    buffer = []
                    balance = 0
                    start_line = None
                    was_disabled = False

            else:
                clean = strip_inline_comment(line)
                buffer.append(clean)
                balance += paren_balance(clean)

                if balance <= 0:
                    yield normalize_rule_line(buffer), start_line, was_disabled
                    buffer = []
                    balance = 0
                    start_line = None
                    was_disabled = False


def extract_options_text(rule: str) -> str:
    open_paren = rule.find("(")
    close_paren = rule.rfind(")")

    if open_paren == -1 or close_paren == -1 or close_paren <= open_paren:
        return ""

    return rule[open_paren + 1:close_paren]


def split_options(options_text: str):
    options = []
    current = []
    inside_quotes = False
    escaped = False

    for c in options_text:
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
                options.append(opt)
            current = []
        else:
            current.append(c)

    opt = "".join(current).strip()
    if opt:
        options.append(opt)

    return options


def option_name(option: str) -> str:
    return option.split(":", 1)[0].strip().lower()


def option_value(options, name: str) -> str:
    name = name.lower()
    for opt in options:
        if option_name(opt) == name:
            if ":" in opt:
                return opt.split(":", 1)[1].strip()
            return ""
    return ""


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_rule(rule: str):
    options = split_options(extract_options_text(rule))
    sid = option_value(options, "sid")
    rev = option_value(options, "rev")
    classtype = option_value(options, "classtype").lower().strip() or "sem_classtype"
    msg = unquote(option_value(options, "msg"))

    return {
        "sid": sid,
        "rev": rev,
        "classtype": classtype,
        "msg": msg,
    }


def sid_sort_key(sid: str):
    return int(sid) if sid.isdigit() else 999999999


def main():
    parser = argparse.ArgumentParser(
        description="Unifica varios arquivos .rules e ordena as regras por classtype."
    )
    parser.add_argument("input_dir", help="Pasta contendo arquivos .rules")
    parser.add_argument("output_rules", help="Arquivo .rules unificado e ordenado por classtype")
    parser.add_argument(
        "--csv",
        default=None,
        help="Relatorio CSV. Padrao: mesmo nome do output, com extensao .csv"
    )
    parser.add_argument(
        "--summary",
        default=None,
        help="Resumo TXT. Padrao: mesmo nome do output, com sufixo _summary.txt"
    )
    parser.add_argument(
        "--include-disabled",
        action="store_true",
        help="Inclui regras comentadas que começam com '# alert', '# drop' etc."
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="Mantem regras duplicadas. Por padrao, remove duplicatas por sid, mantendo a maior rev."
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_path = Path(args.output_rules)
    csv_path = Path(args.csv) if args.csv else output_path.with_suffix(".csv")
    summary_path = Path(args.summary) if args.summary else output_path.with_name(output_path.stem + "_summary.txt")

    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Erro: pasta nao encontrada: {input_dir}")

    rules_files = sorted(input_dir.rglob("*.rules"))

    all_rows = []
    for file_path in rules_files:
        for rule, line_no, disabled in iter_rules_from_file(file_path, include_disabled=args.include_disabled):
            info = parse_rule(rule)
            all_rows.append({
                "source_file": str(file_path),
                "source_line": line_no,
                "disabled_in_source": disabled,
                "sid": info["sid"],
                "rev": info["rev"],
                "classtype": info["classtype"],
                "msg": info["msg"],
                "rule": rule,
            })

    duplicate_count = 0
    if args.keep_duplicates:
        selected_rows = all_rows
    else:
        by_sid = {}
        no_sid_rows = []

        for row in all_rows:
            sid = row["sid"]
            if not sid:
                no_sid_rows.append(row)
                continue

            rev = int(row["rev"]) if row["rev"].isdigit() else 0
            old = by_sid.get(sid)

            if old is None:
                by_sid[sid] = row
            else:
                duplicate_count += 1
                old_rev = int(old["rev"]) if old["rev"].isdigit() else 0
                if rev > old_rev:
                    by_sid[sid] = row

        selected_rows = list(by_sid.values()) + no_sid_rows

    selected_rows = sorted(
        selected_rows,
        key=lambda r: (
            r["classtype"],
            sid_sort_key(r["sid"]),
            r["msg"].lower(),
            r["source_file"],
            r["source_line"],
        )
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    grouped = defaultdict(list)
    for row in selected_rows:
        grouped[row["classtype"]].append(row)

    with output_path.open("w", encoding="utf-8") as f:
        f.write("# Arquivo unificado automaticamente a partir de multiplos .rules\n")
        f.write(f"# Pasta original: {input_dir}\n")
        f.write(f"# Arquivos .rules encontrados: {len(rules_files)}\n")
        f.write(f"# Regras lidas: {len(all_rows)}\n")
        f.write(f"# Regras gravadas: {len(selected_rows)}\n")
        if not args.keep_duplicates:
            f.write(f"# Duplicatas removidas por sid: {duplicate_count}\n")
        f.write("# Ordenacao: classtype, sid, msg\n\n")

        for classtype in sorted(grouped.keys()):
            rows = grouped[classtype]
            f.write("\n")
            f.write(f"# ============================================================\n")
            f.write(f"# classtype: {classtype} | total: {len(rows)}\n")
            f.write(f"# ============================================================\n")
            for row in rows:
                f.write(row["rule"] + "\n")

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "classtype", "sid", "rev", "msg", "source_file", "source_line",
            "disabled_in_source", "rule"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in selected_rows:
            writer.writerow({k: row[k] for k in fieldnames})

    class_counts = Counter(row["classtype"] for row in selected_rows)
    with summary_path.open("w", encoding="utf-8") as f:
        f.write("Resumo da unificacao de regras Snort\n")
        f.write("===================================\n\n")
        f.write(f"Pasta analisada: {input_dir}\n")
        f.write(f"Arquivos .rules encontrados: {len(rules_files)}\n")
        f.write(f"Regras lidas: {len(all_rows)}\n")
        f.write(f"Regras gravadas: {len(selected_rows)}\n")
        if not args.keep_duplicates:
            f.write(f"Duplicatas removidas por sid: {duplicate_count}\n")
        f.write(f"Arquivo .rules gerado: {output_path}\n")
        f.write(f"Relatorio CSV: {csv_path}\n\n")
        f.write("Contagem por classtype:\n")
        for classtype, count in sorted(class_counts.items()):
            f.write(f"- {classtype}: {count}\n")

    print("Resumo")
    print("======")
    print(f"Pasta analisada: {input_dir}")
    print(f"Arquivos .rules encontrados: {len(rules_files)}")
    print(f"Regras lidas: {len(all_rows)}")
    print(f"Regras gravadas: {len(selected_rows)}")
    if not args.keep_duplicates:
        print(f"Duplicatas removidas por sid: {duplicate_count}")
    print(f"Arquivo gerado: {output_path}")
    print(f"CSV: {csv_path}")
    print(f"Resumo TXT: {summary_path}")


if __name__ == "__main__":
    main()
