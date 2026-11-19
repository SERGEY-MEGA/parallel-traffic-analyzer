"""Короткая демонстрация для защиты: тесты, пример анализа и таблица seq против par.

Запуск: make demo   (или python3 demo.py [МиБ], по умолчанию 1024 МиБ)
"""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
PCAP = ROOT / 'data' / 'traffic_10gib.pcap'
SIZE = sys.argv[1] if len(sys.argv) > 1 else '1024'


def title(text):
    print(f'\n\033[1m=== {text} ===\033[0m', flush=True)


def analyze(*args):
    p = subprocess.run([str(ROOT / 'analyze'), str(PCAP), '--limit-mib', SIZE, *args, '--json'],
                       capture_output=True, text=True, check=True)
    result = json.loads(p.stdout)
    seconds = result.pop('seconds')
    result.pop('mode'); result.pop('threads')
    return seconds, result


def table(name, flags):
    title(f'{name}: {SIZE} МиБ, лучший из 2 запусков')
    print(f"{'режим':<10}{'время, с':>10}{'ускорение':>11}   статистика")
    base, reference = None, None
    for mode, threads in [('seq', 1), ('par', 1), ('par', 2), ('par', 4), ('par', 8)]:
        runs = [analyze('--mode', mode, '--threads', str(threads), *flags) for _ in range(2)]
        seconds = min(r[0] for r in runs)
        stats = runs[0][1]
        if base is None:
            base, reference = seconds, stats
        same = 'совпадает с seq' if stats == reference else 'ОТЛИЧАЕТСЯ!'
        label = 'seq' if mode == 'seq' else f'par {threads}'
        print(f'{label:<10}{seconds:>10.3f}{base / seconds:>10.2f}x   {same}', flush=True)


def main():
    if not PCAP.exists():
        sys.exit(f'Нет файла {PCAP}. Создайте: ./generate data/traffic_10gib.pcap 10240 42')
    title('Автоматические тесты (10 групп)')
    p = subprocess.run([sys.executable, str(ROOT / 'tests.py')], capture_output=True, text=True)
    print(p.stderr.strip().splitlines()[-3], '->', p.stderr.strip().splitlines()[-1])
    if p.returncode:
        sys.exit(p.stderr)

    title('Пример: 100 МиБ, 4 потока, фильтр TCP порт 443, проверка сумм')
    out = subprocess.run([str(ROOT / 'analyze'), str(PCAP), '--limit-mib', '100', '--mode', 'par',
                          '--threads', '4', '--protocol', 'tcp', '--port', '443', '--checksum'],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    print('\n'.join(out[:16]))

    table('Лёгкий анализ (только заголовки)', [])
    table('Тяжёлый анализ (заголовки + поиск сигнатур)', ['--signatures'])
    print('\nВывод: лёгкий анализ упирается в последовательное чтение файла (закон Амдала),'
          '\nтяжёлый масштабируется примерно до числа производительных ядер (у M2 их 4).')


if __name__ == '__main__':
    main()
