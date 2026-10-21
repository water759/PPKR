#!/usr/bin/env python3
"""Print Level-3 vs device-assisted compute/encoding comparisons from one run."""
import argparse
import csv
import json
from pathlib import Path
import statistics

PAIRS = [('Initialization', 'initialization'), ('KeyRecovery', 'key_recovery')]
SCALE = {'ns': .001, 'us': 1, 'ms': 1000, 's': 1e6}


def summarize(rows, name):
    selected = [r for r in rows if r.get('run_name', r.get('name')) == name
                and r.get('run_type', 'iteration') == 'iteration']
    if not selected or any(r.get('error_occurred') for r in selected):
        raise ValueError(f'{name}: missing raw repetitions or benchmark error')
    values = [r['cpu_time'] * SCALE[r['time_unit']] for r in selected]
    if len(values) < 2 or any(v <= 0 for v in values):
        raise ValueError(f'{name}: at least two positive raw CPU timings required')
    mean = statistics.mean(values)
    sd = statistics.stdev(values)
    return mean, sd, sd / mean * 100, len(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir', type=Path)
    args = parser.parse_args()
    root = args.run_dir
    manifest = json.loads((root / 'environment.json').read_text())
    if manifest.get('status') != 'passed':
        raise ValueError('run is not marked passed')
    data = json.loads((root / 'protocols.json').read_text())
    if 'baseline' not in data.get('context', {}):
        raise ValueError('missing baseline provenance; use the updated benchmark')
    with (root / 'protocol_sizes.csv').open() as stream:
        sizes = {r['protocol']: r for r in csv.DictReader(stream)}
    print(f"Mode: {manifest['mode']}; revision: {manifest['revision']}")
    print('Software CPU cost; human/network/attested-channel costs excluded.')
    if manifest['mode'] != 'measurement':
        print('SMOKE CHECK ONLY: not final paper measurements.')
    print('\n| Phase | Level-3 mean ± SD (us) | Ours mean ± SD (us) | Delta (us) | Change | CV baseline / ours | Repetitions |')
    print('|---|---:|---:|---:|---:|---:|---:|')
    for stem, stage in PAIRS:
        b, bs, bc, bn = summarize(data['benchmarks'], 'Lev3' + stem + 'Cpu')
        o, os, oc, on = summarize(data['benchmarks'], stem + 'Cpu')
        if bn != on:
            raise ValueError('repetition counts differ across the paired workloads')
        print(f'| {stage} | {b:.3f} ± {bs:.3f} | {o:.3f} ± {os:.3f} | {o-b:+.3f} | {(o/b-1)*100:+.2f}% | {bc:.2f}% / {oc:.2f}% | {bn} |')
    print('\n| Phase / metric | Level-3 | Ours | Delta | Change |')
    print('|---|---:|---:|---:|---:|')
    for _, stage in PAIRS:
        b, o = sizes['lev3_' + stage], sizes[stage]
        if (b['id_bytes'], b['password_bytes']) != (o['id_bytes'], o['password_bytes']):
            raise ValueError('workload input lengths differ')
        for row in (b, o):
            row['hsm_plus_device_bytes'] = int(row['hsm_record_bytes']) + int(row['device_record_bytes'])
        for metric in ['ordinary_hop_bytes', 'qr_public_key_bytes', 'hsm_record_bytes',
                       'device_record_bytes', 'hsm_plus_device_bytes']:
            bv, ov = int(b[metric]), int(o[metric])
            change = f'{(ov/bv-1)*100:+.2f}%' if bv else 'N/A (zero baseline)'
            print(f'| {stage} / {metric} | {bv} | {ov} | {ov-bv:+d} | {change} |')
    print('\nByte values follow the documented encoding profile, not measured wire bytes.')
    print('Ours recovery includes QR-key encrypted delivery; baseline outputs K directly to C.')
    print('Backup and restoration have no baseline counterpart and are reported separately.')


if __name__ == '__main__':
    main()
