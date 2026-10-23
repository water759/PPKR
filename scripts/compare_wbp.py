#!/usr/bin/env python3
"""Print a compact, same-run WBP / OPRF-PPKR / device-assisted comparison."""
import argparse
import csv
import json
from pathlib import Path
from compare_lev3 import summarize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir', type=Path)
    args = parser.parse_args()
    root = args.run_dir
    env = json.loads((root / 'environment.json').read_text())
    data = json.loads((root / 'protocols.json').read_text())
    if env.get('status') != 'passed' or 'wbp' not in data.get('context', {}):
        raise ValueError('need a successful WBP-aware run')
    if data['context'].get('ppkr_build_revision') != env['build']['build_revision']:
        raise ValueError('benchmark and manifest build revisions differ')
    with (root / 'protocol_sizes.csv').open() as stream:
        sizes = {r['protocol']: r for r in csv.DictReader(stream)}
    result = []
    lengths, repetitions = set(), set()
    for label, prefix, row_prefix in [('WBP', 'Wbp', 'wbp_'),
                                     ('pi^{OPRF-PPKR}', 'Lev3', 'lev3_'),
                                     ('Our scheme', '', '')]:
        init = summarize(data['benchmarks'], prefix + 'InitializationCpu')
        rec = summarize(data['benchmarks'], prefix + 'KeyRecoveryCpu')
        repetitions.update([init[3], rec[3]])
        a, b = sizes[row_prefix + 'initialization'], sizes[row_prefix + 'key_recovery']
        for row in (a, b):
            lengths.add((row['id_bytes'], row['password_bytes']))
            if int(row['ordinary_hop_bytes']) != (2 * int(row['relayed_payload_bytes_once'])
                                                  + int(row['server_control_bytes']) + int(row['direct_bytes'])):
                raise ValueError('inconsistent hop-byte accounting')
        result.append((label, init[0], rec[0], a, b))
    if len(lengths) != 1 or len(repetitions) != 1:
        raise ValueError('comparison workload lengths or repetition counts differ')
    print(f"Mode: {env['mode']}; revision: {env['revision']}; repetitions: {next(iter(repetitions))}")
    if env['mode'] != 'measurement':
        print('SMOKE CHECK ONLY: not final paper measurements.')
    print('Common scope: sequential software CPU work; concrete channel attestation excluded.')
    print('\n| Protocol | Init time | Recovery time | Init communication | Recovery communication | HSM storage/user | Device storage/user | Server account mapping/user |')
    print('|---|---:|---:|---:|---:|---:|---:|---:|')
    for label, init, rec, a, b in result:
        print(f"| {label} | {init:.2f} us | {rec:.2f} us | {a['ordinary_hop_bytes']} B | {b['ordinary_hop_bytes']} B | {b['hsm_record_bytes']} B | {b['device_record_bytes']} B | {b['server_account_mapping_bytes']} B |")
    print('\nOurs includes encrypted client delivery and a separate 32 B QR public key.')
    print('Bytes describe the specified encoding/records, not measured packets or physical storage.')
    print('WBP uses an abstract secure record store; global static keys and retired aid history are excluded.')
    print('Main initialization/recovery exclude separate client-device short-code authentication.')


if __name__ == '__main__':
    main()
