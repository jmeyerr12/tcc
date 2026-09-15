#!/usr/bin/env python3

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

INTERVALS_MAP = "/sys/fs/bpf/jmm23_maps/intervals_map"
COUNT_MAP = "/sys/fs/bpf/jmm23_maps/interval_cnt"
PROGRAM = "/sys/fs/bpf/jmm23_xdp"

MAX_INTERVALS = 16
MAX_PAYLOAD_BYTES = 2048


def parse_interval(text):
    try:
        start_text, end_text = text.split("-", 1)
        start = int(start_text)
        end = int(end_text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid interval '{text}', expected START-END"
        )

    if start < 0 or end < 0:
        raise argparse.ArgumentTypeError("interval values cannot be negative")

    if end < start:
        raise argparse.ArgumentTypeError(
            f"invalid interval '{text}': end is smaller than start"
        )

    if end >= MAX_PAYLOAD_BYTES:
        raise argparse.ArgumentTypeError(
            f"interval '{text}' exceeds MAX_PAYLOAD_BYTES={MAX_PAYLOAD_BYTES}"
        )

    return start, end


def u32_hex(value):
    return [f"{byte:02x}" for byte in struct.pack("<I", value)]


def run(command):
    print("+", " ".join(command))
    subprocess.run(command, check=True)


def update_map(path, key, value_bytes):
    command = [
        "bpftool",
        "map",
        "update",
        "pinned",
        path,
        "key",
        "hex",
        *u32_hex(key),
        "value",
        "hex",
        *value_bytes,
    ]
    run(command)


def validate_intervals(intervals):
    if len(intervals) > MAX_INTERVALS:
        raise ValueError(
            f"too many intervals: {len(intervals)} "
            f"(maximum is {MAX_INTERVALS})"
        )

    for i in range(1, len(intervals)):
        previous = intervals[i - 1]
        current = intervals[i]

        if current[0] <= previous[1]:
            raise ValueError(
                "intervals must be sorted and already merged: "
                f"{previous[0]}-{previous[1]} and "
                f"{current[0]}-{current[1]}"
            )


def configure_intervals(intervals):
    count_bytes = u32_hex(len(intervals))
    update_map(COUNT_MAP, 0, count_bytes)

    for index, (start, end) in enumerate(intervals):
        value = u32_hex(start) + u32_hex(end)
        update_map(INTERVALS_MAP, index, value)


def dump_maps():
    run(["bpftool", "map", "dump", "pinned", COUNT_MAP])
    run(["bpftool", "map", "dump", "pinned", INTERVALS_MAP])


def run_packet(input_file, output_file):
    run([
        "bpftool",
        "prog",
        "run",
        "pinned",
        PROGRAM,
        "data_in",
        str(input_file),
        "data_out",
        str(output_file),
    ])

    size = os.path.getsize(output_file)
    print(f"output packet size: {size} bytes")


def main():
    parser = argparse.ArgumentParser(
        description="configure payload intervals for the XDP packet washer"
    )

    parser.add_argument(
        "intervals",
        nargs="+",
        type=parse_interval,
        metavar="START-END",
        help="intervals to preserve, for example 0-313 500-1363",
    )

    parser.add_argument(
        "--input",
        type=Path,
        help="optional packet file to run after configuring the maps",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output_packet.bin"),
        help="output packet file used with --input",
    )

    parser.add_argument(
        "--dump",
        action="store_true",
        help="dump the maps after configuring them",
    )

    args = parser.parse_args()

    try:
        validate_intervals(args.intervals)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    for path in (INTERVALS_MAP, COUNT_MAP):
        if not os.path.exists(path):
            print(
                f"error: pinned map not found: {path}\n"
                "load the XDP program first",
                file=sys.stderr,
            )
            return 1

    print("configured intervals:")
    for start, end in args.intervals:
        print(f"  {start}-{end}")

    configure_intervals(args.intervals)

    if args.dump:
        dump_maps()

    if args.input:
        if not args.input.exists():
            print(
                f"error: input file not found: {args.input}",
                file=sys.stderr,
            )
            return 1

        if not os.path.exists(PROGRAM):
            print(
                f"error: pinned program not found: {PROGRAM}",
                file=sys.stderr,
            )
            return 1

        run_packet(args.input, args.output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
