#!/usr/bin/env python3
import argparse
import csv
import re
from collections import Counter
from pathlib import Path


BEHAVIOR_OPTIONS = {
    "detection_filter",
    "threshold",
    "rate_filter",
    "event_filter",
    "suppress",
}

HEADER_BEHAVIOR_OPTIONS = {
    "flags",
    "flow",
    "flowbits",
    "fragbits",
    "fragoffset",
    "ttl",
    "tos",
    "id",
    "ipopts",
    "sameip",
    "seq",
    "ack",
    "window",
    "itype",
    "icode",
    "icmp_id",
    "icmp_seq",
    "session",
}

SIZE_DEPENDENT_OPTIONS = {
    "dsize",
    "stream_size",
}

PAYLOAD_OPTIONS = {
    "content",
    "protected_content",
    "pcre",
    "byte_test",
    "byte_jump",
    "byte_extract",
    "byte_math",
    "byte_replace",
    "isdataat",
    "base64_decode",
    "base64_data",
    "pkt_data",
    "file_data",
    "js_data",
    "vba_data",
}

BUFFER_OPTIONS = {
    "http_uri",
    "http_raw_uri",
    "http_header",
    "http_raw_header",
    "http_client_body",
    "http_cookie",
    "http_method",
    "http_stat_code",
    "http_stat_msg",
    "http_encode",
    "http_param",
    "http_version",
    "http_user_agent",
    "http_host",
    "http_raw_host",
    "http_server_body",
    "http_header_test",
    "http_trailer",
    "http_true_ip",
    "http_num_headers",
    "http_num_cookies",
    "http_max_header_line",
    "http_max_trailer_line",
    "sip_method",
    "sip_header",
    "sip_body",
    "smtp_command",
    "ssl_state",
    "ssl_version",
    "tls_sni",
}

ABSOLUTE_POSITION_OPTIONS = {"offset", "depth"}
RELATIVE_POSITION_OPTIONS = {"distance", "within"}
POSITION_OPTIONS = ABSOLUTE_POSITION_OPTIONS | RELATIVE_POSITION_OPTIONS


def remove_comment(line):
    inside_quotes = False
    escaped = False

    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if char == '"':
            inside_quotes = not inside_quotes
            continue

        if char == "#" and not inside_quotes:
            return line[:index]

    return line


def split_options(options_text):
    parts = []
    current = []
    inside_quotes = False
    inside_pipe = False
    escaped = False

    for char in options_text:
        if escaped:
            current.append(char)
            escaped = False
            continue

        if char == "\\":
            current.append(char)
            escaped = True
            continue

        if char == '"' and not inside_pipe:
            inside_quotes = not inside_quotes
            current.append(char)
            continue

        if char == "|" and not inside_quotes:
            inside_pipe = not inside_pipe
            current.append(char)
            continue

        if char == ";" and not inside_quotes and not inside_pipe:
            item = "".join(current).strip()
            if item:
                parts.append(item)
            current = []
            continue

        current.append(char)

    item = "".join(current).strip()
    if item:
        parts.append(item)

    return parts


def option_name(option):
    match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\b", option)
    if not match:
        return ""
    return match.group(1).lower()


def parse_rule(line):
    stripped = remove_comment(line).strip()
    if not stripped:
        return None

    open_paren = stripped.find("(")
    close_paren = stripped.rfind(")")

    if open_paren == -1 or close_paren == -1 or close_paren <= open_paren:
        return None

    header = stripped[:open_paren].strip()
    options_text = stripped[open_paren + 1:close_paren]
    options = split_options(options_text)
    names = [option_name(option) for option in options]

    sid = ""
    msg = ""
    for option in options:
        name = option_name(option)
        if name == "sid":
            sid = option.split(":", 1)[-1].strip()
        elif name == "msg":
            msg = option.split(":", 1)[-1].strip().strip('"')

    return {
        "raw": stripped,
        "header": header,
        "options": options,
        "names": names,
        "sid": sid,
        "msg": msg,
    }


def content_blocks(options):
    blocks = []
    current = None

    for option in options:
        name = option_name(option)

        if name in {"content", "protected_content"}:
            if current is not None:
                blocks.append(current)
            current = {"content": option, "modifiers": []}
            continue

        if current is not None:
            current["modifiers"].append(option)

    if current is not None:
        blocks.append(current)

    return blocks


def has_option(names, options):
    return any(name in options for name in names)


def block_text(block):
    block_text = block["content"] + "; " + "; ".join(block["modifiers"])
    return block_text


def block_has_option(block, options):
    option_pattern = "|".join(sorted(options))
    return re.search(
        rf"\b({option_pattern})\s*:?\s*-?\d+\b",
        block_text(block),
        re.IGNORECASE,
    ) is not None


def block_has_absolute_position(block):
    return block_has_option(block, ABSOLUTE_POSITION_OPTIONS)


def block_has_relative_position(block):
    return block_has_option(block, RELATIVE_POSITION_OPTIONS)


def payload_position_status(blocks):
    if not blocks:
        return "none", ""

    has_relative = any(block_has_relative_position(block) for block in blocks)
    all_absolute = all(block_has_absolute_position(block) for block in blocks)

    if all_absolute and not has_relative:
        return "absolute_supported", "todos os contents possuem offset/depth absoluto"

    anchored = False
    for block in blocks:
        if block_has_absolute_position(block):
            anchored = True
            continue

        if block_has_relative_position(block) and anchored:
            continue

        return "unbounded", "content sem ancora absoluta; padrao pode aparecer em qualquer byte"

    if has_relative:
        return (
            "relative_review",
            "cadeia com distance/within ancorada, mas o adaptador atual ainda nao recalcula posicoes relativas",
        )

    return "unbounded", "content sem offset/depth/distance/within; padrao pode aparecer em qualquer byte"


def header_looks_specific(header):
    fields = header.split()
    if len(fields) < 7:
        return False

    proto = fields[1].lower()
    src_port = fields[3].lower()
    direction = fields[4]
    dst_port = fields[6].lower()

    if proto not in {"ip", "tcp", "udp", "icmp", "icmp6"}:
        return False

    return src_port != "any" or dst_port != "any" or direction in {"<>", "<-"}


def classify(rule):
    names = rule["names"]
    options = rule["options"]
    blocks = content_blocks(options)

    reasons = []
    tags = []
    discard_reasons = []
    review_reasons = []

    frequency_based = has_option(names, BEHAVIOR_OPTIONS)
    explicit_header_behavior = has_option(names, HEADER_BEHAVIOR_OPTIONS)

    has_content = bool(blocks)
    position_status, position_reason = payload_position_status(blocks)
    all_content_absolute_positioned = position_status == "absolute_supported"

    pcre = "pcre" in names
    payload_without_content = has_option(names, PAYLOAD_OPTIONS - {"content", "protected_content", "pcre"})
    buffer_rule = has_option(names, BUFFER_OPTIONS)
    size_dependent = has_option(names, SIZE_DEPENDENT_OPTIONS)
    payload_dependency = has_content or pcre or payload_without_content or buffer_rule

    header_only_behavior = (
        (explicit_header_behavior or header_looks_specific(rule["header"]))
        and not payload_dependency
        and not size_dependent
    )
    header_with_supported_payload = explicit_header_behavior and all_content_absolute_positioned and not pcre

    if frequency_based and not payload_dependency and not size_dependent:
        tags.append("behavior_frequency")
        reasons.append("usa limite/frequencia de eventos sem depender do payload")

    if header_only_behavior:
        tags.append("behavior_header")
        reasons.append("usa apenas cabecalho, fluxo, flags ou metadados do pacote")

    if header_with_supported_payload:
        tags.append("behavior_header")
        reasons.append("combina cabecalho/fluxo com payload posicionado por offset/depth")

    if all_content_absolute_positioned:
        tags.append("payload_positioned")
        reasons.append(position_reason)

    if position_status == "unbounded":
        discard_reasons.append(position_reason)

    if position_status == "relative_review":
        review_reasons.append(position_reason)

    if pcre:
        discard_reasons.append("pcre sem ancora de intervalo reconhecida pelo script")

    if payload_without_content:
        review_reasons.append("usa operador de payload ainda nao suportado automaticamente pelo adaptador")

    if buffer_rule:
        review_reasons.append("usa buffer normalizado/camada de aplicacao; offset pode nao corresponder ao pacote bruto")

    if size_dependent:
        review_reasons.append("usa dsize/stream_size; a lavagem altera tamanho e pode exigir ajuste proprio")

    if frequency_based and payload_dependency and not all_content_absolute_positioned:
        discard_reasons.append("controle de frequencia aparece junto de payload sem posicao segura")

    if explicit_header_behavior and payload_dependency and not all_content_absolute_positioned:
        discard_reasons.append("cabecalho/fluxo aparece junto de payload sem posicao segura")

    if discard_reasons:
        return "discarded", "unsupported_payload_scan", "; ".join(discard_reasons + review_reasons)

    if review_reasons:
        category = "manual_review"
        if position_status == "relative_review":
            category = "relative_payload_position"
        elif size_dependent:
            category = "size_dependent_rule"
        elif buffer_rule:
            category = "normalized_buffer_rule"
        elif payload_without_content:
            category = "unsupported_payload_operator"
        return "review", category, "; ".join(review_reasons)

    if tags:
        return "included", ",".join(tags), "; ".join(reasons)

    return "review", "needs_manual_review", "regra nao se enquadrou nas categorias automaticas"


def write_rows(path, rows):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=["line", "sid", "msg", "status", "category", "reason", "rule"],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_rules(path, rows):
    with path.open("w", encoding="utf-8") as output:
        output.write("# Regras selecionadas automaticamente para o conjunto MicroSec.\n")
        output.write("# Inclui regras com intervalo de payload e regras comportamentais/cabecalho.\n")
        for row in rows:
            output.write(row["rule"] + "\n")


def write_summary(path, rows):
    status_counts = Counter(row["status"] for row in rows)
    category_counts = Counter(row["category"] for row in rows)
    behavior_count = sum(
        1 for row in rows
        if row["status"] == "included"
        and ("behavior_frequency" in row["category"] or "behavior_header" in row["category"])
    )
    payload_positioned_count = sum(
        1 for row in rows
        if row["status"] == "included" and "payload_positioned" in row["category"]
    )

    with path.open("w", encoding="utf-8") as output:
        output.write("Resumo da classificacao de regras Snort\n")
        output.write("======================================\n\n")
        output.write(f"Total de regras analisadas: {len(rows)}\n")
        output.write(f"Incluidas: {status_counts['included']}\n")
        output.write(f"Comportamentais/cabecalho: {behavior_count}\n")
        output.write(f"Payload posicionado: {payload_positioned_count}\n")
        output.write(f"Descartadas: {status_counts['discarded']}\n")
        output.write(f"Revisao manual: {status_counts['review']}\n\n")

        output.write("Categorias:\n")
        for category, count in category_counts.most_common():
            output.write(f"- {category}: {count}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Classifica regras Snort para uso no conjunto MicroSec."
    )
    parser.add_argument("rules_file", help="Arquivo .rules de entrada")
    parser.add_argument(
        "--out-dir",
        default="microsec_rule_report",
        help="Diretorio onde os relatorios serao gerados",
    )
    args = parser.parse_args()

    input_path = Path(args.rules_file)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []

    with input_path.open("r", encoding="utf-8", errors="replace") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            rule = parse_rule(line)
            if rule is None:
                continue

            status, category, reason = classify(rule)
            rows.append(
                {
                    "line": line_number,
                    "sid": rule["sid"],
                    "msg": rule["msg"],
                    "status": status,
                    "category": category,
                    "reason": reason,
                    "rule": rule["raw"],
                }
            )

    included = [row for row in rows if row["status"] == "included"]
    discarded = [row for row in rows if row["status"] == "discarded"]
    behavior = [
        row for row in included
        if "behavior_frequency" in row["category"] or "behavior_header" in row["category"]
    ]
    payload_positioned = [
        row for row in included
        if "payload_positioned" in row["category"]
    ]
    review = [row for row in rows if row["status"] == "review"]

    write_rows(out_dir / "all_rules_classification.csv", rows)
    write_rows(out_dir / "discarded_rules.csv", discarded)
    write_rows(out_dir / "behavior_rules.csv", behavior)
    write_rows(out_dir / "payload_positioned_rules.csv", payload_positioned)
    write_rows(out_dir / "manual_review_rules.csv", review)
    write_rules(out_dir / "microsec_candidate.rules", included)
    write_rules(out_dir / "behavior_rules.rules", behavior)
    write_rules(out_dir / "payload_positioned.rules", payload_positioned)
    write_summary(out_dir / "summary.txt", rows)

    print(f"Total de regras analisadas: {len(rows)}")
    print(f"Incluidas no conjunto MicroSec: {len(included)}")
    print(f"Regras comportamentais/cabecalho: {len(behavior)}")
    print(f"Regras com payload posicionado: {len(payload_positioned)}")
    print(f"Descartadas: {len(discarded)}")
    print(f"Revisao manual: {len(review)}")
    print(f"Relatorios gerados em: {out_dir}")


if __name__ == "__main__":
    main()
