"""Последовательно запускает эксперименты и сохраняет каждый результат в CSV."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parent


def run(file, size, mode, threads, extra=()):
    command = [str(ROOT / 'analyze'), str(file), '--limit-mib', str(size), '--mode', mode,
               '--threads', str(threads), *extra, '--json']
    begin = time.perf_counter()
    p = subprocess.run(command, capture_output=True, text=True, check=True)
    wall = time.perf_counter() - begin
    result = json.loads(p.stdout)
    stats = {k: v for k, v in result.items() if k not in ('mode', 'threads', 'seconds')}
    digest = hashlib.sha256(json.dumps(stats, sort_keys=True).encode()).hexdigest()
    return result, digest, wall


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--sizes', nargs='+', type=int, default=[100, 500, 1024, 5120, 10240])
    parser.add_argument('--threads', nargs='+', type=int, default=[1, 2, 4, 8])
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--out', type=Path, default=ROOT / 'results')
    # Дополнительные операции анализа, которые передаются в ./analyze.
    parser.add_argument('--checksum', action='store_true', help='проверять контрольные суммы')
    parser.add_argument('--signatures', action='store_true', help='искать сигнатуры в нагрузке')
    args = parser.parse_args()
    extra = [flag for flag, on in (('--checksum', args.checksum), ('--signatures', args.signatures)) if on]
    if args.repeats < 1 or any(x < 1 for x in args.sizes) or any(x < 1 or x > 256 for x in args.threads):
        parser.error('Sizes/repeats must be positive; threads: 1..256')
    if not args.file.is_file():
        parser.error('Input file does not exist')
    # Генератор завершает файл на границе пакета, поэтому допускаем разницу до 65551 байт.
    if max(args.sizes) * 1024**2 > args.file.stat().st_size + 65551:
        parser.error('Input file is smaller than requested size')
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out / 'measurements.csv').exists():
        parser.error('measurements.csv already exists; choose a new --out directory')
    metadata = {
        'platform': platform.platform(), 'machine': platform.machine(),
        'logical_cpus': os.cpu_count(), 'input': str(args.file.resolve()),
        'input_bytes': args.file.stat().st_size, 'sizes_mib': args.sizes,
        'threads': args.threads, 'repeats': args.repeats, 'analysis_flags': extra,
        'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'compiler': subprocess.check_output(['clang++', '--version'], text=True).splitlines()[0],
        'sources_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in ('analyze.cpp', 'generate.cpp', 'common.h', 'Makefile')},
        'cache_policy': 'One sequential warm-up per size; OS cache is not cleared. Mixed cache conditions.',
    }
    # sysctl не обязателен: в некоторых средах сведения о машине недоступны.
    for key in ('hw.model', 'hw.memsize', 'hw.physicalcpu', 'hw.perflevel0.physicalcpu', 'hw.perflevel1.physicalcpu'):
        try:
            p = subprocess.run(['sysctl', '-n', key], capture_output=True, text=True)
            if p.returncode == 0:
                metadata[key] = p.stdout.strip()
        except OSError:
            pass
    (args.out / 'environment.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    configurations = [('seq', 1)] + [('par', t) for t in args.threads]
    rng = random.Random(42)
    rows = []
    columns = ['size_mib', 'mode', 'threads', 'repeat', 'seconds', 'wall_seconds',
               'file_bytes', 'packets', 'mib_per_second', 'packets_per_second', 'stats_sha256']
    with (args.out / 'measurements.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        f.flush()
        for size in args.sizes:
            print(f'Warm-up: {size} MiB', flush=True)
            reference, expected, _ = run(args.file, size, 'seq', 1, extra)
            (args.out / f'stats_{size}mib.json').write_text(json.dumps(reference, indent=2), encoding='utf-8')
            for repeat in range(1, args.repeats + 1):
                order = list(configurations)
                rng.shuffle(order)  # Порядок меняем, чтобы один режим не был постоянно первым.
                for mode, threads in order:
                    result, digest, wall = run(args.file, size, mode, threads, extra)
                    if digest != expected:
                        raise RuntimeError(f'Statistics mismatch: {size} MiB, {mode}, {threads} threads')
                    seconds = result['seconds']
                    row = dict(size_mib=size, mode=mode, threads=threads, repeat=repeat,
                               seconds=seconds, wall_seconds=round(wall, 6), file_bytes=result['file_bytes'],
                               packets=result['total'], mib_per_second=result['file_bytes'] / 1024**2 / seconds,
                               packets_per_second=result['total'] / seconds, stats_sha256=digest)
                    rows.append(row)
                    writer.writerow(row)
                    f.flush()
                    print(f'{size:5} MiB | {mode} {threads} | run {repeat} | {seconds:.3f} s | OK', flush=True)
    summary = []
    for size in args.sizes:
        base = statistics.median(r['seconds'] for r in rows if r['size_mib'] == size and r['mode'] == 'seq')
        for mode, threads in configurations:
            selected = [r for r in rows if (r['size_mib'], r['mode'], r['threads']) == (size, mode, threads)]
            values = [r['seconds'] for r in selected]
            median = statistics.median(values)
            summary.append(dict(size_mib=size, mode=mode, threads=threads, median_seconds=median,
                                min_seconds=min(values), max_seconds=max(values), speedup=base / median,
                                efficiency=base / median / threads,
                                mib_per_second=selected[0]['file_bytes'] / 1024**2 / median))
    with (args.out / 'summary.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]))
        writer.writeheader(); writer.writerows(summary)
    metadata['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    (args.out / 'environment.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print(f'Finished. Statistics agree in all {len(rows)} measured runs.', flush=True)


if __name__ == '__main__':
    main()
