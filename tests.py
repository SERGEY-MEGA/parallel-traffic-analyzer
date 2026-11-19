"""Проверки на маленьких файлах. Никаких сторонних библиотек не требуется."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent


def execute(path, *options, ok=True):
    p = subprocess.run([str(ROOT / 'analyze'), str(path), *options, '--json'],
                       capture_output=True, text=True, timeout=30)
    if ok:
        if p.returncode:
            raise AssertionError(p.stderr)
        return json.loads(p.stdout)
    assert p.returncode != 0, p.stdout


def statistics(result):
    return {k: v for k, v in result.items() if k not in ('mode', 'threads', 'seconds')}


def frame(proto=6, src='10.0.0.1', dst='10.0.0.2', sport=1234, dport=80,
          vlan=False, fragment=0):
    if proto == 6:
        transport = struct.pack('!HHIIBBHHH', sport, dport, 0, 0, 0x50, 0x10, 4096, 0, 0)
    elif proto == 17:
        transport = struct.pack('!HHHH', sport, dport, 8, 0)
    else:
        transport = bytes([8, 0, 0, 0, 0, 1, 0, 1])
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 1, fragment,
                     64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ethernet = b'\x02' * 12 + (b'\x81\x00\x00\x01\x08\x00' if vlan else b'\x08\x00')
    return ethernet + ip + transport


def pcap(path, packets, endian='<', nano=False, link=1):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    content = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 65535, link)
    for item in packets:
        payload, wire = item if isinstance(item, tuple) else (item, len(item))
        content += struct.pack(endian + 'IIII', 1, 0, len(payload), wire) + payload
    path.write_bytes(content)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'test.pcap'

    def tearDown(self):
        self.temp.cleanup()

    def compare(self, *args):
        seq = execute(self.path, *args)
        for threads in (1, 2, 4, 8):
            par = execute(self.path, '--mode', 'par', '--threads', str(threads), *args)
            self.assertEqual(statistics(seq), statistics(par))
        return seq

    def test_known_statistics_and_filters(self):
        packets = [frame(), frame(17, dport=53, vlan=True), frame(1),
                   frame(6, src='10.0.0.3', dport=443), b'bad',
                   b'\0' * 12 + b'\x86\xdd' + b'\0' * 40]
        pcap(self.path, packets)
        s = self.compare()
        self.assertEqual((s['total'], s['selected'], s['invalid'], s['unsupported']), (6, 4, 1, 1))
        self.assertEqual(s['selected_bytes'], sum(map(len, packets[:4])))
        self.assertEqual(s['protocols']['TCP'], [2, len(packets[0]) + len(packets[3])])
        self.assertEqual(s['ips']['10.0.0.2'][2], 4)
        self.assertEqual(self.compare('--protocol', 'udp')['selected'], 1)
        self.assertEqual(self.compare('--port', '443')['selected'], 1)
        self.assertEqual(self.compare('--ip', '10.0.0.3')['selected'], 1)
        self.assertEqual(self.compare('--ip', '10.0.0.2')['selected'], 4)
        self.assertEqual(self.compare('--protocol', 'tcp', '--port', '53')['selected'], 0)

    def test_byte_orders_and_nanoseconds(self):
        for endian in ('<', '>'):
            for nano in (False, True):
                pcap(self.path, [frame()], endian=endian, nano=nano)
                self.assertEqual(self.compare()['selected'], 1)

    def test_empty_and_truncated_capture(self):
        pcap(self.path, [])
        self.assertEqual(self.compare()['total'], 0)
        full = frame()
        pcap(self.path, [(full[:38], len(full))])  # TCP-порты уже доступны, остальное не захвачено.
        self.assertEqual(self.compare('--port', '80')['selected'], 1)
        pcap(self.path, [(full[:34], len(full))])
        self.assertEqual(self.compare()['selected'], 1)
        self.assertEqual(self.compare('--port', '80')['selected'], 0)

    def test_fragments(self):
        # У второго фрагмента нет заголовка TCP, поэтому порт неизвестен.
        pcap(self.path, [frame(fragment=0x2000), frame(fragment=1)])
        self.assertEqual(self.compare()['selected'], 2)
        self.assertEqual(self.compare('--port', '80')['selected'], 1)

    def test_bad_files(self):
        for data in (b'', b'pcapng' * 5):
            self.path.write_bytes(data)
            execute(self.path, ok=False)
        pcap(self.path, [frame()])
        self.path.write_bytes(self.path.read_bytes()[:-1])
        execute(self.path, ok=False)
        execute(self.path, '--mode', 'par', '--threads', '4', ok=False)
        pcap(self.path, [], link=0)
        execute(self.path, ok=False)
        pcap(self.path, [])
        self.path.write_bytes(self.path.read_bytes() + b'123')
        execute(self.path, ok=False)
        pcap(self.path, [])
        self.path.write_bytes(self.path.read_bytes() + struct.pack('<IIII', 1, 0, 999999, 999999))
        execute(self.path, ok=False)

    def test_invalid_headers(self):
        wrong_ip = bytearray(frame()); wrong_ip[14] = 0x44
        wrong_tcp = bytearray(frame()); wrong_tcp[46] = 0x10
        wrong_udp = bytearray(frame(17)); wrong_udp[38:40] = b'\x00\x01'
        pcap(self.path, [wrong_ip, wrong_tcp, wrong_udp])
        self.assertEqual(self.compare()['invalid'], 3)

    def test_invalid_options(self):
        pcap(self.path, [])
        for opts in (['--threads', '0'], ['--threads', '257'], ['--ip', '1.2.3.999'],
                     ['--ip', '1.2.3.'], ['--port', '65536'], ['--limit-mib', '-1'],
                     ['--mode', 'x'], ['--mode', 'seq', '--threads', '2']):
            execute(self.path, *opts, ok=False)

    def test_generator_and_multiple_blocks(self):
        p = subprocess.run([str(ROOT / 'generate'), str(self.path), '8', '42'],
                           capture_output=True, text=True, check=True)
        expected = dict(line.split(': ') for line in p.stdout.splitlines())
        s = self.compare()
        self.assertEqual(s['total'], int(expected['Packets']))
        self.assertEqual(s['file_bytes'], int(expected['Bytes']))
        self.assertEqual(s['invalid'], 0)
        for name in ('TCP', 'UDP', 'ICMP'):
            self.assertEqual(s['protocols'][name][0], int(expected[name]))
        small = self.compare('--limit-mib', '1')
        # Независимо считаем записи, попадающие в первый МиБ.
        data = self.path.read_bytes()
        pos, count = 24, 0
        counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        while pos < len(data):
            size = struct.unpack_from('<I', data, pos + 8)[0]
            end = pos + 16 + size
            packet = data[pos + 16:end]
            ip = packet[14:]
            self.assertEqual(checksum(ip[:20]), 0)
            transport = ip[20:]
            proto = ip[9]
            if proto in (6, 17):
                pseudo = ip[12:20] + bytes([0, proto]) + struct.pack('!H', len(transport))
                self.assertEqual(checksum(pseudo + transport), 0)
            else:
                self.assertEqual(checksum(transport), 0)
            if end <= 1024 * 1024:
                count += 1
                counts[{6: 'TCP', 17: 'UDP', 1: 'ICMP'}[proto]] += 1
            pos = end
        self.assertEqual(small['total'], count)
        self.assertLessEqual(small['file_bytes'], 1024 * 1024)
        for name, count in counts.items():
            self.assertEqual(small['protocols'][name][0], count)
        # Одинаковый seed даёт побайтно одинаковый файл.
        second = self.path.with_name('second.pcap')
        subprocess.run([str(ROOT / 'generate'), str(second), '8', '42'], check=True, capture_output=True)
        self.assertEqual(data, second.read_bytes())

    def test_checksum_verification(self):
        # Файл генератора: все суммы верны. Затем портим по одному байту в двух пакетах.
        subprocess.run([str(ROOT / 'generate'), str(self.path), '2', '7'], check=True, capture_output=True)
        s = self.compare('--checksum')
        self.assertEqual((s['checked'], s['bad_checksum']), (s['selected'], 0))
        data = bytearray(self.path.read_bytes())
        first = 24 + 16                      # первый пакет
        second = first + struct.unpack_from('<I', data, 24 + 8)[0] + 16
        data[first + 14 + 8] ^= 1            # TTL в заголовке IPv4
        data[second + 60] ^= 0xff            # байт транспортного уровня
        self.path.write_bytes(bytes(data))
        self.assertEqual(self.compare('--checksum')['bad_checksum'], 2)
        # Без флага поля проверки в выводе нет, статистика прежняя.
        self.assertNotIn('bad_checksum', execute(self.path))

    def test_signatures(self):
        def with_payload(proto, payload, **kw):
            return frame(proto, **kw) + payload
        packets = [with_payload(6, b'GET /etc/passwd HTTP/1.1\r\n'),
                   with_payload(17, b'xxcmd.exe', dport=53),
                   with_payload(1, b'\x90' * 8),
                   with_payload(6, b'GET ', dport=443),      # неполная сигнатура
                   with_payload(6, b'<scrip')]               # обрезана в конце пакета
        fixed = []
        for pkt in packets:                                  # исправляем длину IPv4 и UDP
            pkt = bytearray(pkt)
            struct.pack_into('!H', pkt, 16, len(pkt) - 14)
            if pkt[23] == 17:
                struct.pack_into('!H', pkt, 38, len(pkt) - 34)
            fixed.append(bytes(pkt))
        pcap(self.path, fixed)
        s = self.compare('--signatures')
        names = ['GET /', 'POST /', 'HTTP/1.', '/etc/passwd', 'cmd.exe', '<script',
                 'SELECT ', 'UNION SELECT', 'NOP', 'ELF']
        hits = dict(zip(names, s['signatures']))
        self.assertEqual(hits, {'GET /': 1, 'POST /': 0, 'HTTP/1.': 1, '/etc/passwd': 1,
                                'cmd.exe': 1, '<script': 0, 'SELECT ': 0, 'UNION SELECT': 0,
                                'NOP': 1, 'ELF': 0})
        # Фильтр применяется до поиска: только TCP.
        self.assertEqual(self.compare('--signatures', '--protocol', 'tcp')['signatures'][4], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
