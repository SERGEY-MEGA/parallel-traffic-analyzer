"""Строит обычные графики Matplotlib по таблице summary.csv."""
import argparse
import csv
from pathlib import Path
import os

# Кэш шрифтов держим во временной папке, чтобы не менять домашний каталог.
os.environ.setdefault('MPLCONFIGDIR', '/tmp/traffic-matplotlib')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', type=Path, nargs='?', default=Path(__file__).resolve().parent / 'results')
    args = parser.parse_args()
    with (args.results / 'summary.csv').open() as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for key in ('size_mib', 'threads'):
            r[key] = int(r[key])
        for key in ('median_seconds', 'min_seconds', 'max_seconds', 'speedup'):
            r[key] = float(r[key])
    plt.rcParams.update({'font.size': 10, 'axes.spines.top': False, 'axes.spines.right': False})
    sizes = sorted({r['size_mib'] for r in rows})
    workers = sorted({r['threads'] for r in rows if r['mode'] == 'par'})

    fig, ax = plt.subplots(figsize=(9, 5), layout='constrained')
    for mode, count in [('seq', 1)] + [('par', t) for t in workers]:
        series = sorted([r for r in rows if (r['mode'], r['threads']) == (mode, count)],
                        key=lambda r: r['size_mib'])
        label = 'Последовательно' if mode == 'seq' else f'{count} раб. поток(а)'
        ax.plot([r['size_mib'] for r in series], [r['median_seconds'] for r in series],
                'o-', label=label)
    # Логарифмические оси: иначе объёмы 100 МиБ – 1 ГиБ сжимаются в угол графика.
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xticks(sizes, [str(x) for x in sizes]); ax.minorticks_off()
    ax.axvspan(4096, max(sizes) * 1.3, color='#f2e6d9', alpha=0.6, label='не помещается в ОЗУ → чтение с диска')
    ax.set(xlabel='Размер входа, МиБ (логарифмическая шкала)', ylabel='Медианное время, с (лог. шкала)',
           title='Время чтения и анализа PCAP')
    ax.grid(alpha=0.25); ax.legend()
    fig.savefig(args.results / 'time.png', dpi=180)
    fig.savefig(args.results / 'time.svg')
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 5), layout='constrained')
    for size in sizes:
        series = sorted([r for r in rows if r['mode'] == 'par' and r['size_mib'] == size],
                        key=lambda r: r['threads'])
        ax.plot([r['threads'] for r in series], [r['speedup'] for r in series], 'o-', label=f'{size} МиБ')
    ax.axhline(1, color='black', linestyle='--', linewidth=1, label='Ускорение = 1')
    ax.set(xlabel='Количество рабочих потоков (+ один читатель)', ylabel='Ускорение Tseq / Tpar',
           title='Ускорение относительно последовательного режима', xticks=workers)
    ax.grid(alpha=0.25); ax.legend(ncol=2)
    fig.savefig(args.results / 'speedup.png', dpi=180)
    fig.savefig(args.results / 'speedup.svg')
    plt.close(fig)

    # На крупнейшем входе показываем также разброс трёх повторов.
    large = [r for r in rows if r['size_mib'] == max(sizes)]
    fig, ax = plt.subplots(figsize=(9, 5), layout='constrained')
    labels = ['seq' if r['mode'] == 'seq' else f"par {r['threads']}" for r in large]
    medians = [r['median_seconds'] for r in large]
    errors = [[r['median_seconds'] - r['min_seconds'] for r in large],
              [r['max_seconds'] - r['median_seconds'] for r in large]]
    ax.bar(labels, medians, yerr=errors, capsize=5, color=['#444444'] + ['#3578b8'] * (len(large) - 1))
    ax.set(ylabel='Время, с', title=f'{max(sizes)} МиБ: медиана и диапазон min–max')
    ax.grid(axis='y', alpha=0.25)
    fig.savefig(args.results / 'largest.png', dpi=180)
    fig.savefig(args.results / 'largest.svg')
    plt.close(fig)
    print(f'Графики сохранены: {args.results}')


if __name__ == '__main__':
    main()
