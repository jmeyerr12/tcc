#!/usr/bin/env python3
"""Small positive/negative fixtures against complete original/adapted rulesets.

Default: execute the compiled XDP with BPF_PROG_TEST_RUN (requires root).
--offline: reference PCAP transformation only; does NOT validate the XDP.
"""
import argparse
from collections import Counter
from datetime import datetime
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_intervals import summary_intervals


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(payload=b'', port=12345, udp_port=None, reverse=False,
          seq=101, ack=501, flags=0x18,
          addresses=('198.51.100.1', '10.0.0.2')):
    src, dst = map(socket.inet_aton, addresses)
    sport, dport = port, udp_port or 80
    if reverse:
        src, dst = dst, src
        if udp_port is None:
            sport, dport = dport, sport
    proto = 17 if udp_port is not None else 6
    if proto == 17:
        header = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
        csum_offset = 6
    else:
        header = struct.pack('!HHIIBBHHH', sport, dport, seq, ack,
                             0x50, flags, 65535, 0, 0)
        csum_offset = 16
    segment = bytearray(header + payload)
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(segment))
    struct.pack_into('!H', segment, csum_offset, checksum(pseudo + segment) or 65535)
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment),
                               1, 0, 64, proto, 0, src, dst))
    struct.pack_into('!H', ip, 10, checksum(ip))
    return bytes.fromhex('0200000000020200000000010800') + ip + segment


def fixtures(group):
    packets, expected = [], Counter()
    if group == 'ip':
        # Real accepted IP reputation rule; vary sources to avoid its threshold.
        for index in range(3):
            for negative in (False, True):
                packets.append(frame(
                    b'x' * 1400, port=20001 + index * 2 + int(negative), udp_port=12345,
                    addresses=(f'10.0.0.{index + 1}',
                               '192.0.2.1' if negative else '162.243.103.246'),
                ))
        return packets, Counter({2404300: 3})
    cases = {
        'transport': [(2008414, 2, b'Rand0mSTRING\0netascii', 69),
                      (2003155, 21, bytes.fromhex('fe800000000000008000') + b'TEREDO', 3544)],
        'application': [(2008605, 100, b'Session Stomper', None),
                        (2009477, 60, b'AND not exists (select * from master..sysdatabases)', None)],
    }
    port = 20000
    for sid, offset, pattern, udp_port in cases[group]:
        for _ in range(3):
            for negative in (False, True):
                port += 1
                needle = (b'X' + pattern[1:]) if negative else pattern
                if udp_port is not None:
                    payload = b'\0' * offset + needle
                    payload = payload.ljust(1400, b'\0')
                    packets.append(frame(payload, port, udp_port, reverse=sid == 2003155))
                else:
                    prefix = b'GET / HTTP/1.1\r\nHost: example.org\r\nX-Test: '
                    payload = prefix + b'x' * (offset - len(prefix)) + needle
                    payload += b'\r\nX-Padding: ' + b'x' * 300 + b'\r\n\r\n'
                    packets.extend([
                        frame(port=port, seq=100, ack=0, flags=2),
                        frame(port=port, reverse=True, seq=500, ack=101, flags=0x12),
                        frame(port=port, flags=0x10),
                        frame(payload, port=port),
                    ])
                if not negative:
                    expected[sid] += 1
    return packets, expected


def write_pcap(path, packets):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            out.write(struct.pack('<IIII', 1700000000, index * 1000,
                                  len(packet), len(packet)) + packet)


def reference_cut(packet, intervals):
    # Independent offline reference; the default mode uses the actual BPF object.
    udp = packet[23] == 17
    offset = 42 if udp else 34 + (packet[46] >> 4) * 4
    payload = packet[offset:]
    kept = b''.join(payload[start:end + 1] for start, end in intervals)
    if kept == payload:
        return packet
    result = bytearray(packet[:offset] + kept)
    struct.pack_into('!H', result, 16, len(result) - 14)
    if udp:
        struct.pack_into('!H', result, 38, len(result) - 34)
    return result


def execute(args, log=None):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, capture_output=True, text=True)
    if log:
        log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'Command failed: {args}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def alerts(pcap, rules, directory):
    directory.mkdir()
    args = ['suricata', '-c', '/dev/null', '--runmode', 'single', '-k', 'none',
            '-r', pcap, '-S', rules, '-l', directory]
    settings = {
        'vars.address-groups.HOME_NET': '10.0.0.0/8',
        'vars.address-groups.EXTERNAL_NET': 'any',
        'vars.address-groups.HTTP_SERVERS': '10.0.0.0/8',
        'vars.address-groups.SQL_SERVERS': '10.0.0.0/8',
        'vars.port-groups.HTTP_PORTS': '80',
        'classification-file': '/dev/null', 'reference-config-file': '/dev/null',
        'threshold-file': '/dev/null', 'outputs.0': 'fast',
        'outputs.0.fast.enabled': 'yes', 'outputs.0.fast.filename': 'fast.log',
    }
    for key, value in settings.items():
        args += ['--set', f'{key}={value}']
    execute(args, directory / 'console.log')
    lines = (directory / 'fast.log').read_text().splitlines()
    counts = Counter(int(re.search(r'\[\d+:(\d+):\d+\]', line)[1]) for line in lines)
    # HTTP may emit alerts when a flow is flushed at EOF, while no_stream
    # emits them on the packet. Compare identity/endpoints, not emission time.
    return Counter(line.split(' ', 1)[1].lstrip() for line in lines), counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    if not args.offline and os.geteuid() != 0:
        parser.error('XDP exige root: sudo python3 tests/compare_alerts.py')
    mode = 'offline-reference' if args.offline else 'xdp'
    out = ROOT / 'experiments/results' / (datetime.now().strftime('alerts_%Y%m%d_%H%M%S_%f_') + mode)
    out.mkdir(parents=True)
    execute(['make', 'all'], out / 'build.log')
    if not args.offline:
        execute(['g++', '-std=c++11', '-Wall', '-Wextra', '-pedantic',
                 'tests/wash_pcap.cpp', '-lbpf', '-lelf', '-lz', '-o', out / 'wash_pcap'])
    report = [f'Modo: {mode}', 'Grupo\tPacotes\tSID\tOriginal\tCortado\tResultado']
    success = True
    for group, stem in [('application', 'original-application'),
                        ('transport', 'original-tcp-udp'), ('ip', 'original-ip')]:
        directory = out / group
        directory.mkdir()
        source = ROOT / f'{group}-rules' / f'{stem}.rules'
        # Copies record the exact inputs; repository originals remain untouched.
        original = directory / 'original.rules'
        original.write_bytes(source.read_bytes())
        adapted = directory / 'adapted.rules'
        summary = execute([ROOT / 'build/alg', original, adapted])
        (directory / 'summary.txt').write_text(summary)
        packets, expected = fixtures(group)
        write_pcap(directory / 'original.pcap', packets)
        if args.offline:
            intervals = summary_intervals(directory / 'summary.txt')
            shortened = [reference_cut(packet, intervals) for packet in packets]
            assert sum(map(len, shortened)) < sum(map(len, packets)), 'No bytes cut'
            write_pcap(directory / 'cut.pcap', shortened)
        else:
            execute([out / 'wash_pcap', ROOT / 'build/af_xdp_kern.o',
                     directory / 'summary.txt', directory / 'original.pcap',
                     directory / 'cut.pcap'], directory / 'xdp.log')
        before, before_sids = alerts(directory / 'original.pcap', original, directory / 'original-log')
        after, after_sids = alerts(directory / 'cut.pcap', adapted, directory / 'cut-log')
        # Check the alert multiset (SID, message, endpoints), plus
        # explicit positive counts. Equality of two empty logs is not a pass.
        ok = before == after and all(before_sids[sid] == n for sid, n in expected.items())
        # All positive flows use odd source ports; even ports are negatives.
        ok = ok and all(int(re.search(r'\{(?:TCP|UDP)\} [^ ]+:(\d+) ->', line)[1]) % 2
                        for line in before if int(re.search(r'\[\d+:(\d+):\d+\]', line)[1]) in expected)
        success &= ok
        for sid in sorted(set(before_sids) | set(after_sids) | set(expected)):
            report.append(f'{group}\t{len(packets)}\t{sid}\t{before_sids[sid]}\t{after_sids[sid]}\t' + ('PASS' if ok else 'FAIL'))
    (out / 'comparison.tsv').write_text('\n'.join(report) + '\n')
    print('\n'.join(report))
    print(f'Artefatos: {out}')
    if args.offline:
        print('Referencia offline: execucao do XDP no kernel ainda nao validada.')
    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
