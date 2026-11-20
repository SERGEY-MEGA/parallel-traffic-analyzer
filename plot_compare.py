"""Сравнивает ускорение трёх видов анализа и подбирает долю последовательной части по Амдалу.

Использование: python plot_compare.py [папка results]
Читает results/данные/v2_basic, v2_checksum, v2_signatures. Главные графики (why.png,
compare_100mib.png, compare_1024mib.png, compare_10240mib.png, by_size.png, all.png,
all_lines.png, growth.png, protocols.png) кладёт в results/, остальные и compare.csv — в results/дополнительно/.
"""
import csv
import os
import sys
from pathlib import Path

os.environ.setdefault('MPLCONFIGDIR', '/tmp/traffic-matplotlib')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

SERIES = [('v2_basic', 'Только заголовки'),
          ('v2_checksum', 'Заголовки + контрольные суммы'),
          ('v2_signatures', 'Заголовки + поиск сигнатур')]
SIZE_NAMES = {100: '100 МиБ', 500: '500 МиБ', 1024: '1 ГиБ', 2048: '2 ГиБ', 5120: '5 ГиБ', 10240: '10 ГиБ'}


def load(folder):
    with (folder / 'summary.csv').open() as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r['size_mib'] = int(r['size_mib']); r['threads'] = int(r['threads'])
        r['median_seconds'] = float(r['median_seconds']); r['speedup'] = float(r['speedup'])
    return rows


def amdahl(f, p):
    return 1 / (f + (1 - f) / p)


def fit_f(points):
    """Перебором ищем f, при котором закон Амдала ближе всего к замерам (P >= 2)."""
    best = min((sum((amdahl(f / 1000, p) - s) ** 2 for p, s in points), f / 1000)
               for f in range(0, 1001))
    return best[1]


def why(root, data):
    """Столбики: время seq и par 4 для трёх видов анализа. Линия — время чтения файла одним потоком:
    быстрее неё параллельная версия стать не может (последовательная часть по Амдалу)."""
    panels = [(1024, 'данные в памяти'), (10240, 'данные с диска (не помещаются в ОЗУ)')]
    panels = [(s, w) for s, w in panels if all(any(r['size_mib'] == s for r in rows) for rows in data.values())]
    if not panels or len(data) < 3:
        return
    fig, axes = plt.subplots(1, len(panels), figsize=(12, 5.4), layout='constrained')
    axes = [axes] if len(panels) == 1 else axes
    for ax, (size, where) in zip(axes, panels):
        get = lambda name, mode, t: next(r['median_seconds'] for r in data[name]
                                         if (r['size_mib'], r['mode'], r['threads']) == (size, mode, t))
        # Время чтения: лучший параллельный результат лёгкого анализа (анализ там почти бесплатный).
        floor = min(get('v2_basic', 'par', t) for t in (1, 2, 4, 8))
        names = ['Только\nзаголовки', 'Заголовки +\nконтр. суммы', 'Заголовки +\nпоиск сигнатур']
        x = range(3)
        seq = [get(n, 'seq', 1) for n, _ in SERIES]
        par = [get(n, 'par', 4) for n, _ in SERIES]
        ax.bar([i - 0.2 for i in x], seq, 0.38, color='#888888', label='последовательно (1 поток)')
        ax.bar([i + 0.2 for i in x], par, 0.38, color='#d0592b', label='параллельно (4 рабочих потока)')
        for i in x:
            ax.annotate(f'{seq[i]:.2f} с', (i - 0.2, seq[i]), xytext=(0, 3), textcoords='offset points',
                        ha='center', fontsize=8.5)
            ax.annotate(f'{par[i]:.2f} с\n{seq[i] / par[i]:.1f}×', (i + 0.2, par[i]), xytext=(0, 3),
                        textcoords='offset points', ha='center', fontsize=8.5, color='#d0592b', weight='bold')
        ax.axhline(floor, color='#3578b8', linestyle='--', linewidth=1.5,
                   label=f'чтение файла одним потоком ≈ {floor:.2f} с\n(быстрее не стать — закон Амдала)')
        ax.set_xticks(list(x), names)
        ax.set(ylabel='Время, с', title=f'{size} МиБ — {where}', ylim=(0, max(seq) * 1.25))
        ax.grid(axis='y', alpha=0.25); ax.legend(loc='upper left', fontsize=8.5)
    fig.suptitle('Почему ускорение разное: параллельная версия не может быть быстрее чтения файла', fontsize=12)
    fig.savefig(root / 'why.png', dpi=160)
    plt.close(fig)


def by_size(root, data, threads=4):
    """Одна картинка на все объёмы: ускорение на 4 рабочих потоках для трёх видов анализа."""
    if len(data) < 3:
        return
    sizes = sorted({r['size_mib'] for r in data['v2_basic']})
    fig, ax = plt.subplots(figsize=(10, 5.6), layout='constrained')
    ax.axvspan(3000, max(sizes) * 1.5, color='#f2e6d9', alpha=0.7)
    ax.text(6800, 4.75, 'файл не помещается в ОЗУ →\nчтение с диска,\nвсе упираются в диск',
            ha='center', va='top', fontsize=9, color='#8a5a2b')
    ax.text(100, 4.75, 'мало работы →\nнакладные расходы', ha='left', va='top', fontsize=9, color='#555555')
    for (name, label), color in zip(SERIES, ['#888888', '#3578b8', '#d0592b']):
        rows = sorted((r for r in data[name] if r['mode'] == 'par' and r['threads'] == threads),
                      key=lambda r: r['size_mib'])
        xs = [r['size_mib'] for r in rows]; ys = [r['speedup'] for r in rows]
        ax.plot(xs, ys, 'o-', color=color, linewidth=2.2, label=label)
        for x, y in zip(xs, ys):
            ax.annotate(f'{y:.2f}×', (x, y), textcoords='offset points',
                        xytext=(0, -16) if name == 'v2_basic' else (0, 8),
                        ha='center', fontsize=8.5, color=color, weight='bold')
    ax.axhline(1, color='black', linewidth=0.6)
    ax.axhline(threads, color='black', linestyle='--', linewidth=0.8, label=f'идеал: {threads}×')
    ax.set_xscale('log')
    ax.set_xticks(sizes, [SIZE_NAMES.get(x, f'{x} МиБ') for x in sizes])
    ax.minorticks_off()
    ax.set(xlim=(80, max(sizes) * 1.4), ylim=(0, threads + 1), xlabel='Объём входных данных (лог. шкала)',
           ylabel='Ускорение Tseq / Tpar',
           title=f'Ускорение на {threads} рабочих потоках для всех объёмов: лучший случай — 1 ГиБ')
    ax.grid(alpha=0.25); ax.legend(loc='center left', fontsize=9)
    fig.savefig(root / 'by_size.png', dpi=160)
    plt.close(fig)


def overview(root, data):
    """Тепловые карты: для каждого вида анализа таблица «объём × число потоков», в клетке — ускорение.
    Видно сразу всё: где параллельность даёт прирост (тёмные клетки), а где нет (светлые)."""
    if len(data) < 3:
        return
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list('speed', ['#f4f4f4', '#f6c9a8', '#e0743a', '#a63a0f'])
    sizes = sorted({r['size_mib'] for r in data['v2_basic']})
    size_names = SIZE_NAMES
    configs = [('seq', 1), ('par', 1), ('par', 2), ('par', 4), ('par', 8)]
    labels = ['1 поток\n(seq)', '1 раб.\n+ чтение', '2 раб.', '4 раб.', '8 раб.']
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.4), layout='constrained')
    for ax, (name, title) in zip(axes, SERIES):
        grid, secs = [], []
        for size in sizes:
            row = {(r['mode'], r['threads']): r for r in data[name] if r['size_mib'] == size}
            grid.append([row[c]['speedup'] for c in configs])
            secs.append([row[c]['median_seconds'] for c in configs])
        im = ax.imshow(grid, cmap=cmap, vmin=0.8, vmax=5.8, aspect='auto')
        for i in range(len(sizes)):
            for j in range(len(configs)):
                v = grid[i][j]
                ax.text(j, i - 0.12, f'{v:.2f}×', ha='center', va='center', fontsize=10, weight='bold',
                        color='white' if v > 3.3 else 'black')
                ax.text(j, i + 0.22, f'{secs[i][j]:.2f} с' if secs[i][j] < 10 else f'{secs[i][j]:.1f} с',
                        ha='center', va='center', fontsize=7.5, color='white' if v > 3.3 else '#444444')
        ax.set_xticks(range(len(configs)), labels, fontsize=8.5)
        ax.set_yticks(range(len(sizes)), [size_names.get(x, f'{x} МиБ') for x in sizes])
        ax.set_title(title, fontsize=11)
        ax.tick_params(length=0)
        for spine in ax.spines.values():
            spine.set_visible(False)
        # граница «в памяти / с диска»
        disk = [i for i, x in enumerate(sizes) if x > 4096]
        if disk:
            ax.axhline(disk[0] - 0.5, color='#8a5a2b', linewidth=2)
            ax.text(-0.45, disk[0] - 0.44, '▼ ниже — файл не в ОЗУ, чтение с диска', ha='left', va='top',
                    fontsize=7.5, color='#8a5a2b', weight='bold')
    fig.colorbar(im, ax=axes, shrink=0.8, label='Ускорение относительно seq (во сколько раз быстрее)')
    fig.suptitle('Все замеры сразу: ускорение (крупно) и медианное время (мелко) '
                 'для каждого объёма и числа потоков', fontsize=12)
    fig.savefig(root / 'all.png', dpi=160)
    plt.close(fig)


def threads_lines(root, data):
    """Линейные графики: для каждого вида анализа ускорение от числа потоков, отдельная линия на каждый объём."""
    if len(data) < 3:
        return
    sizes = sorted({r['size_mib'] for r in data['v2_basic']})
    size_names = {**SIZE_NAMES, 5120: '5 ГиБ (диск)', 10240: '10 ГиБ (диск)'}
    colors = {100: '#9ecae1', 500: '#6baed6', 1024: '#2171b5', 2048: '#08306b', 5120: '#fd8d3c', 10240: '#a63603'}
    styles = {100: 'o-', 500: 'o-', 1024: 'o-', 2048: 'o-', 5120: 's--', 10240: 's--'}
    ps = [1, 2, 4, 8]
    fig, axes = plt.subplots(1, 3, figsize=(15, 5.2), layout='constrained', sharey=True)
    for ax, (name, title) in zip(axes, SERIES):
        for size in sizes:
            rows = sorted((r for r in data[name] if r['size_mib'] == size and r['mode'] == 'par'),
                          key=lambda r: r['threads'])
            ys = [r['speedup'] for r in rows]
            ax.plot([r['threads'] for r in rows], ys, styles.get(size, 'o-'), color=colors.get(size),
                    linewidth=2, label=size_names.get(size, f'{size} МиБ'))
            if size in (1024, 10240):  # подписываем память и диск, чтобы подписи не наезжали
                ax.annotate(f'{ys[-1]:.1f}×', (8, ys[-1]), textcoords='offset points',
                            xytext=(6, 6 if size == 1024 else -6),
                            va='center', fontsize=9, color=colors.get(size), weight='bold')
        ax.plot(ps, ps, ':', color='black', linewidth=1, label='идеал S = P')
        ax.axhline(1, color='black', linewidth=0.5)
        ax.set(title=title, xlabel='Рабочих потоков P', xticks=ps, xlim=(0.7, 9), ylim=(0, 8.5))
        ax.grid(alpha=0.25)
    axes[0].set_ylabel('Ускорение Tseq / Tpar')
    axes[0].legend(loc='upper left', fontsize=9, title='Объём данных', title_fontsize=9)
    fig.suptitle('Прирост от параллельной обработки: ускорение от числа потоков для каждого объёма '
                 '(сплошные — данные в памяти, пунктир — с диска)', fontsize=12)
    fig.savefig(root / 'all_lines.png', dpi=160)
    plt.close(fig)


def protocols(root):
    """График по протоколам из results/данные/protocols.csv: время seq/par 4 и ускорение с фильтром --protocol."""
    path = root / 'данные' / 'protocols.csv'
    if not path.exists():
        return
    with path.open() as f:
        rows = list(csv.DictReader(f))
    names = {'all': 'Все пакеты', 'tcp': 'TCP', 'udp': 'UDP', 'icmp': 'ICMP'}
    order = ['all', 'tcp', 'udp', 'icmp']
    get = lambda a, p: next(r for r in rows if r['analysis'] == a and r['protocol_filter'] == p)
    fig, (left, right) = plt.subplots(1, 2, figsize=(14, 5.6), layout='constrained',
                                      gridspec_kw={'width_ratios': [1.25, 1]})
    # Слева: время поиска сигнатур, seq и par 4, линия — чтение файла.
    x = range(len(order))
    seq = [float(get('signatures', p)['seq_seconds']) for p in order]
    par = [float(get('signatures', p)['par4_seconds']) for p in order]
    floor = min(float(get('headers', p)['par4_seconds']) for p in order)
    left.bar([i - 0.2 for i in x], seq, 0.38, color='#888888', label='последовательно (1 поток)')
    left.bar([i + 0.2 for i in x], par, 0.38, color='#d0592b', label='параллельно (4 рабочих потока)')
    for i, proto in enumerate(order):
        r = get('signatures', proto)
        left.annotate(f'{seq[i]:.2f} с', (i - 0.2, seq[i]), xytext=(0, 3), textcoords='offset points',
                      ha='center', fontsize=8.5)
        left.annotate(f'{par[i]:.2f} с\n{seq[i] / par[i]:.1f}×', (i + 0.2, par[i]), xytext=(0, 3),
                      textcoords='offset points', ha='center', fontsize=9, color='#d0592b', weight='bold')
    left.axhline(floor, color='#3578b8', linestyle='--', linewidth=1.5,
                 label=f'чтение всего файла одним потоком ≈ {floor:.2f} с')
    left.set_xticks(list(x), [f"{names[p]}\n{int(get('signatures', p)['selected_mb'])} МБ, "
                              f"{int(get('signatures', p)['selected_packets']) / 1e6:.2f} млн пак."
                              for p in order], fontsize=9)
    left.set(ylabel='Время, с', ylim=(0, max(seq) * 1.3),
             title='Поиск сигнатур с фильтром по протоколу (1 ГиБ)')
    left.grid(axis='y', alpha=0.25); left.legend(loc='upper right', fontsize=8.5)
    # Справа: ускорение и цена мегабайта.
    for k, (analysis, label, color) in enumerate([('headers', 'только заголовки', '#888888'),
                                                  ('signatures', '+ поиск сигнатур', '#d0592b')]):
        sp = [float(get(analysis, p)['speedup']) for p in order]
        right.bar([i - 0.2 + 0.4 * k for i in x], sp, 0.38, color=color, label=label)
        for i, v in enumerate(sp):
            right.annotate(f'{v:.2f}×', (i - 0.2 + 0.4 * k, v), xytext=(0, 3), textcoords='offset points',
                           ha='center', fontsize=8.5, color=color, weight='bold')
    right.axhline(1, color='black', linewidth=0.6)
    cost = []
    for p in order:
        s_, h = get('signatures', p), get('headers', p)
        cost.append((float(s_['seq_seconds']) - float(h['seq_seconds'])) / float(s_['selected_mb']) * 1000)
    right.set_xticks(list(x), [f'{names[p]}\nпоиск: {c:.2f} мс/МБ' for p, c in zip(order, cost)], fontsize=9)
    right.set(ylabel='Ускорение seq / par 4', ylim=(0, 5), title='Ускорение на 4 потоках')
    right.grid(axis='y', alpha=0.25); right.legend(loc='upper right', fontsize=8.5)
    fig.suptitle(f'По протоколам: цена мегабайта одинаковая (≈ {sum(cost) / len(cost):.1f} мс/МБ), ускорение зависит от того, '
                 'сколько работы осталось после фильтра', fontsize=12)
    fig.savefig(root / 'protocols.png', dpi=160)
    plt.close(fig)


def growth(root, data):
    """Главный график роста: поиск сигнатур, объёмы в памяти, ускорение от числа потоков (линия на объём)."""
    if 'v2_signatures' not in data:
        return
    rows = data['v2_signatures']
    sizes = sorted({r['size_mib'] for r in rows if r['size_mib'] <= 4096})
    colors = {100: '#f4a582', 500: '#e0703d', 1024: '#c4461b', 2048: '#7f2704'}
    ps = [1, 2, 4, 8]
    fig, ax = plt.subplots(figsize=(10, 6), layout='constrained')
    ax.plot([0, 8.5], [0, 8.5], ':', color='black', linewidth=1, label='идеал S = P')
    ax.axhline(1, color='black', linewidth=0.6)
    for size in sizes:
        pts = sorted(((r['threads'], r['speedup']) for r in rows
                      if r['size_mib'] == size and r['mode'] == 'par'), key=lambda x: x[0])
        xs, ys = [x for x, _ in pts], [y for _, y in pts]
        ax.plot(xs, ys, 'o-', color=colors.get(size, '#c4461b'), linewidth=3, markersize=9,
                label=SIZE_NAMES.get(size, f'{size} МиБ'))
        # подписи соседних линий разводим по вертикали, чтобы не наезжали
        shift = {100: -9, 500: -11, 1024: 2, 2048: 17}.get(size, 0)
        ax.annotate(f'{SIZE_NAMES.get(size, size)}: {ys[-1]:.2f}×', (xs[-1], ys[-1]), textcoords='offset points',
                    xytext=(10, shift),
                    va='center', fontsize=13, weight='bold', color=colors.get(size, '#c4461b'))
    ax.set(xticks=ps, xlim=(0.6, 10.8), ylim=(0, 8.5), xlabel='Рабочих потоков P',
           ylabel='Ускорение Tseq / Tpar',
           title='Поиск сигнатур, данные в памяти: прирост растёт с числом потоков')
    ax.grid(alpha=0.25)
    ax.tick_params(labelsize=13)
    ax.xaxis.label.set_size(14); ax.yaxis.label.set_size(14); ax.title.set_size(15)
    ax.legend(loc='upper left', fontsize=13, title='Объём данных', title_fontsize=13)
    fig.savefig(root / 'growth.png', dpi=160)
    plt.close(fig)


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / 'results'
    data = {name: load(root / 'данные' / name) for name, _ in SERIES
            if (root / 'данные' / name / 'summary.csv').exists()}
    extra = root / 'дополнительно'
    extra.mkdir(exist_ok=True)
    sizes = sorted({r['size_mib'] for rows in data.values() for r in rows})
    lines = ['size_mib,analysis,threads,seconds,speedup,amdahl_f']
    plt.rcParams.update({'font.size': 10, 'axes.spines.top': False, 'axes.spines.right': False})
    for size in sizes:
        where = 'данные с диска' if size > 4096 else 'данные в памяти'
        fig, ax = plt.subplots(figsize=(10, 5.6), layout='constrained')
        for (name, label), color in zip(SERIES, ['#888888', '#3578b8', '#d0592b']):
            if name not in data:
                continue
            rows = sorted((r for r in data[name] if r['size_mib'] == size and r['mode'] == 'par'),
                          key=lambda r: r['threads'])
            points = [(r['threads'], r['speedup']) for r in rows if r['threads'] >= 2]
            f = fit_f(points)
            seq = next(r for r in data[name] if r['size_mib'] == size and r['mode'] == 'seq')
            lines.append(f"{size},{name},seq,{seq['median_seconds']:.4f},1.000,{f:.3f}")
            for r in rows:
                lines.append(f"{size},{name},{r['threads']},{r['median_seconds']:.4f},{r['speedup']:.3f},{f:.3f}")
            ax.plot([r['threads'] for r in rows], [r['speedup'] for r in rows], 'o-', color=color,
                    linewidth=2.2, label=f'{label}: замер')
            for r in rows:  # подписываем значение у каждой точки
                offset = {'v2_basic': (0, -15), 'v2_checksum': (0, 8), 'v2_signatures': (-24, 2)}[name]
                ax.annotate(f"{r['speedup']:.2f}×", (r['threads'], r['speedup']), textcoords='offset points',
                            xytext=offset, ha='center', fontsize=8.5, color=color, weight='bold')
            ps = [1 + i / 10 for i in range(71)]
            ax.plot(ps, [amdahl(f, p) for p in ps], ':', color=color, linewidth=1.3,
                    label=f'  теория Амдала, f ≈ {f:.2f} (потолок {1 / f:.1f}×)' if f > 0 else '  теория Амдала')
        ps = [1, 2, 4, 8]
        ax.plot(ps, ps, '--', color='black', linewidth=0.8, label='Идеальное ускорение S = P')
        ax.axhline(1, color='black', linewidth=0.5)
        ax.set(xlabel='Рабочих потоков P (+ поток чтения)', ylabel='Ускорение Tseq / Tpar',
               title=f'Ускорение на {size} МиБ ({where}): '
                     f'сплошная — замер, точки — закон Амдала',
               xticks=ps, ylim=(0, 8.5))
        ax.grid(alpha=0.25); ax.legend(loc='upper left', fontsize=8.5)
        fig.savefig((root if size in (100, 1024, 10240) else extra) / f'compare_{size}mib.png', dpi=160)
        plt.close(fig)
    why(root, data)
    by_size(root, data)
    overview(root, data)
    threads_lines(root, data)
    growth(root, data)
    protocols(root)
    (extra / 'compare.csv').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
