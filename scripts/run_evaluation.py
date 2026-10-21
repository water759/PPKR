#!/usr/bin/env python3
"""Run local evaluation and preserve provenance; never changes CPU governors."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def capture(args):
    try:
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    except OSError as exc:
        return {'error': str(exc)}
    if result.returncode:
        return {"error": result.stderr.strip(), "returncode": result.returncode}
    return result.stdout.strip()

def read(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None

def machine():
    cpus = {}
    for cpu in sorted(Path('/sys/devices/system/cpu').glob('cpu[0-9]*')):
        if not cpu.name[3:].isdigit():
            continue
        cpus[cpu.name] = {key: read(cpu / path) for key, path in {
            'core_id': 'topology/core_id', 'package_id': 'topology/physical_package_id',
            'thread_siblings': 'topology/thread_siblings_list', 'core_type': 'topology/core_type',
            'governor': 'cpufreq/scaling_governor', 'driver': 'cpufreq/scaling_driver',
            'max_frequency_khz': 'cpufreq/cpuinfo_max_freq',
        }.items()}
    return {'timestamp': datetime.datetime.now().astimezone().isoformat(),
            'platform': platform.platform(), 'machine': platform.machine(),
            'affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
            'lscpu': capture(['lscpu', '-J']), 'cpus': cpus,
            'load_average': list(os.getloadavg()) if hasattr(os, 'getloadavg') else None,
            'power_supply': {p.name: {key: read(p / key) for key in ['type', 'online', 'status', 'capacity']}
                             for p in Path('/sys/class/power_supply').glob('*')},
            'openssl': capture(['openssl', 'version'])}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build-eval')
    parser.add_argument('--mode', choices=['smoke', 'measurement'], default='smoke')
    parser.add_argument('--suite', choices=['protocols', 'oprf', 'breakdown', 'all'], default='protocols')
    parser.add_argument('--repetitions', type=int)
    parser.add_argument('--min-time', help='Google Benchmark duration, e.g. 0.5s')
    parser.add_argument('--filter', help='Google Benchmark regular expression')
    parser.add_argument('--random-interleaving', action='store_true',
                        help='Randomly interleave benchmark repetitions to reduce ordering bias')
    parser.add_argument('--cpu', type=int, help='Optional Linux logical CPU affinity; choose from actual topology')
    parser.add_argument('--output-dir', help='New directory; existing results are never overwritten')
    args = parser.parse_args()
    repetitions = args.repetitions if args.repetitions is not None else (3 if args.mode == 'smoke' else 10)
    duration = args.min_time or ('0.05s' if args.mode == 'smoke' else '0.5s')
    if repetitions < 1 or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?s', duration) or float(duration[:-1]) <= 0:
        parser.error('positive repetitions and a positive duration such as 0.5s are required')
    build = (ROOT / args.build_dir).resolve()
    suites = ['protocols', 'oprf'] if args.suite == 'all' else [args.suite]
    executables = {'protocols': build / 'protocol_bench', 'oprf': build / 'oprf_bench',
                   'breakdown': build / 'recovery_breakdown_bench'}
    required = [build / 'protocol_sizes'] + [executables[s] for s in suites]
    for exe in required:
        if not exe.is_file() or not os.access(exe, os.X_OK):
            parser.error(f'{exe} is missing or not executable; build with PPKR_BUILD_BENCHMARKS=ON first')
    if args.cpu is not None:
        if not hasattr(os, 'sched_setaffinity') or args.cpu not in os.sched_getaffinity(0):
            parser.error('requested CPU is unavailable in the current process affinity')
        os.sched_setaffinity(0, {args.cpu})
    metadata = json.loads(subprocess.check_output([str(build / 'protocol_sizes'), '--metadata'], text=True))
    revision = capture(['git', 'rev-parse', 'HEAD'])
    status = capture(['git', 'status', '--porcelain'])
    if args.mode == 'measurement' and (metadata['build_type'] != 'Release' or
            metadata['build_source_dirty'] or status or metadata['build_revision'] != revision):
        parser.error('measurement requires a clean checkout and a matching fresh Release build; reconfigure and rebuild after updating')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    output = (ROOT / (args.output_dir or f'results/{args.mode}-{stamp}')).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'mode': args.mode, 'suite': args.suite, 'revision': revision, 'git_status': status,
                'build': metadata, 'build_dir': str(build), 'command': sys.argv,
                'cmake_flags': {line.split(':', 1)[0]: line.split('=', 1)[1]
                                for line in (read(build / 'CMakeCache.txt') or '').splitlines()
                                if '=' in line and line.split(':', 1)[0] in {
                                    'CMAKE_CXX_COMPILER', 'CMAKE_CXX_FLAGS',
                                    'CMAKE_CXX_FLAGS_RELEASE', 'CMAKE_BUILD_TYPE', 'CMAKE_GENERATOR'}},
                'binary_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in required},
                'before': machine(), 'benchmark_commands': [], 'status': 'running'}
    manifest_file = output / 'environment.json'
    def save():
        manifest_file.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    save()
    try:
        print(f'Mode: {args.mode}; output: {output}', flush=True)
        with (output / 'protocol_sizes.csv').open('w') as stream:
            subprocess.run([str(build / 'protocol_sizes')], check=True, stdout=stream, cwd=ROOT)
        for suite in suites:
            result_file = output / f'{suite}.json'
            command = [str(executables[suite]), f'--benchmark_repetitions={repetitions}',
                       f'--benchmark_min_time={duration}', f'--benchmark_out={result_file}',
                       '--benchmark_out_format=json']
            if args.random_interleaving:
                command.append('--benchmark_enable_random_interleaving=true')
            if args.filter:
                command.append(f'--benchmark_filter={args.filter}')
            manifest['benchmark_commands'].append(command)
            save()
            print(f'Running {suite}; console output saved to {suite}.log ...', flush=True)
            with (output / f'{suite}.log').open('w') as log:
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT)
            data = json.loads(result_file.read_text())
            if not data.get('benchmarks') or any(row.get('error_occurred') for row in data['benchmarks']):
                raise RuntimeError(f'{suite}: no matching benchmarks or a benchmark reported failure; inspect the log')
        manifest['status'] = 'passed'
        print(f'PASS: artifacts saved in {output}', flush=True)
        if args.mode == 'smoke':
            print('Smoke run only: these are not final paper measurements.')
    except BaseException as exc:
        manifest['status'] = 'failed'
        manifest['error'] = str(exc)
        raise
    finally:
        manifest['after'] = machine()
        save()

if __name__ == '__main__':
    main()
