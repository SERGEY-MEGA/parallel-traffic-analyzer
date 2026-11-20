// =============================================================================
// analyze.cpp — анализатор сетевого трафика из PCAP-файла.
//
// Что делает программа:
//   1. Читает PCAP-файл (файл с записанными сетевыми пакетами).
//   2. Для каждого пакета разбирает заголовки: Ethernet → IPv4 → TCP/UDP/ICMP.
//   3. Фильтрует пакеты (по протоколу, IP-адресу, порту).
//   4. Считает статистику: сколько пакетов и байт по протоколам и по IP-адресам.
//   5. По желанию: проверяет контрольные суммы (--checksum)
//      и ищет сигнатуры атак в содержимом пакетов (--signatures).
//
// Два режима работы:
//   seq — один поток: прочитал блок → разобрал → следующий блок.
//   par — один поток читает файл и кладёт блоки в очередь,
//         P рабочих потоков берут блоки из очереди и разбирают параллельно,
//         у каждого потока своя статистика, в конце всё складывается.
//
// Порядок чтения кода: main → run → Reader::next → Queue → packet.
// =============================================================================

#include "common.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

// -----------------------------------------------------------------------------
// Настройки запуска из командной строки.
// -----------------------------------------------------------------------------
struct Options {
    std::string file, mode = "seq";   // имя файла; режим: seq или par
    unsigned threads = 1;             // число рабочих потоков (для par)
    uint64_t limit = 0;               // сколько байт файла анализировать (0 = весь файл)
    int protocol = -1, port = -1;     // фильтры: номер протокола и порт (-1 = нет фильтра)
    bool has_ip = false, json = false, verify = false, signatures = false;
    uint32_t ip = 0;                  // фильтр по IP-адресу (если has_ip)
};

// Разбор аргументов командной строки, например:
//   ./analyze file.pcap --mode par --threads 4 --protocol tcp --port 443
Options arguments(int argc, char** argv) {
    if (argc < 2) throw std::runtime_error(
        "Usage: ./analyze FILE [--mode seq|par] [--threads N] [--limit-mib N] "
        "[--protocol tcp|udp|icmp] [--ip ADDRESS] [--port N] [--checksum] [--signatures] [--json]");
    Options o; o.file = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string key = argv[i];
        // Флаги без значения.
        if (key == "--json") { o.json = true; continue; }
        if (key == "--checksum") { o.verify = true; continue; }
        if (key == "--signatures") { o.signatures = true; continue; }
        // Остальные параметры идут парой «ключ значение».
        if (i + 1 == argc) throw std::runtime_error("Missing value for " + key);
        std::string value = argv[++i];
        if (key == "--mode") o.mode = value;
        else if (key == "--threads") {
            auto n = number(value);
            if (n < 1 || n > 256) throw std::runtime_error("Threads: 1..256");
            o.threads = unsigned(n);
        } else if (key == "--limit-mib") {
            auto n = number(value);
            if (n > 1024 * 1024) throw std::runtime_error("Limit too large");
            o.limit = n * MiB;
        } else if (key == "--protocol") {
            // Номера протоколов внутри IPv4: TCP = 6, UDP = 17, ICMP = 1.
            if (value == "tcp") o.protocol = 6;
            else if (value == "udp") o.protocol = 17;
            else if (value == "icmp") o.protocol = 1;
            else throw std::runtime_error("Protocol: tcp, udp or icmp");
        } else if (key == "--ip") { o.ip = parse_ip(value); o.has_ip = true; }
        else if (key == "--port") {
            auto n = number(value);
            if (n > 65535) throw std::runtime_error("Port: 0..65535");
            o.port = int(n);
        } else throw std::runtime_error("Unknown option: " + key);
    }
    if (o.mode != "seq" && o.mode != "par") throw std::runtime_error("Mode: seq or par");
    if (o.mode == "seq" && o.threads != 1) throw std::runtime_error("seq uses one thread");
    return o;
}

// -----------------------------------------------------------------------------
// File — обёртка над дескриптором файла (RAII): файл закрывается
// автоматически, когда объект уничтожается, даже при ошибке.
// -----------------------------------------------------------------------------
struct File {
    int fd = -1;
    File() = default;
    File(const File&) = delete;             // копировать нельзя: файл закрылся бы дважды
    File& operator=(const File&) = delete;
    ~File() { if (fd >= 0) close(fd); }
};

// -----------------------------------------------------------------------------
// Reader — «читатель» PCAP-файла.
//
// Устройство PCAP: 24 байта общего заголовка, затем записи подряд:
//   [16 байт заголовка записи: время, длина][байты пакета][16 байт][пакет]...
//
// Читатель берёт файл кусками по 4 МиБ (один системный вызов read())
// и находит в куске границы пакетов, проходя только по 16-байтовым заголовкам.
// Если последний пакет в куске не поместился целиком, его начало переносится
// в следующий блок. Так блок всегда состоит из целых пакетов.
//
// Почему читатель один: в PCAP нет меток начала пакета — где начинается
// следующий пакет, можно узнать только из длины предыдущего.
// -----------------------------------------------------------------------------
class Reader {
    File file;
    Bytes pending;           // хвост предыдущего куска: начало неполного пакета
    uint64_t file_pos = 24;  // сколько байт файла уже прочитано
    uint32_t snaplen = 0;    // максимальная длина пакета из заголовка файла
    uint64_t limit;          // ограничение объёма (--limit-mib), 0 = без ограничения
    bool finished = false;   // файл (или лимит) закончился

    // Читает ровно n байт (или меньше, если файл закончился).
    // read() может вернуть меньше, чем просили, поэтому читаем в цикле.
    size_t read_full(uint8_t* dst, size_t n) {
        size_t got = 0;
        while (got < n) {
            ssize_t r = ::read(file.fd, dst + got, n - got);
            if (r < 0 && errno == EINTR) continue;   // прервано сигналом — повторяем
            if (r < 0) throw std::runtime_error("Cannot read PCAP file");
            if (r == 0) break;                       // конец файла
            got += size_t(r);
        }
        return got;
    }
public:
    bool little = true;      // порядок байтов чисел в файле (little-endian или big-endian)
    uint64_t bytes = 24;     // сколько байт целых пакетов передано на анализ

    // Открываем файл и проверяем общий заголовок PCAP (24 байта).
    Reader(const Options& o) : limit(o.limit) {
        file.fd = ::open(o.file.c_str(), O_RDONLY);
        if (file.fd < 0) throw std::runtime_error("Cannot open PCAP file");
        uint8_t h[24];
        if (read_full(h, 24) != 24) throw std::runtime_error("Incomplete PCAP header");
        // «Магическое число» в начале файла говорит, что это PCAP и какой порядок байтов.
        uint32_t magic = be32(h);
        if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) little = true;
        else if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) little = false;
        else throw std::runtime_error("Expected classic PCAP (pcapng is not supported)");
        auto field16 = [&](const uint8_t* p) {
            return little ? uint16_t(p[0] | (uint16_t(p[1]) << 8)) : be16(p);
        };
        if (field16(h + 4) != 2 || field16(h + 6) != 4)          // версия формата 2.4
            throw std::runtime_error("Expected PCAP version 2.4");
        snaplen = word32(h + 16, little);
        if (!snaplen || snaplen > 16 * MiB) throw std::runtime_error("Unsupported snaplen");
        if ((word32(h + 20, little) & 65535) != 1)                // 1 = Ethernet
            throw std::runtime_error("Only Ethernet PCAP is supported");
    }

    // Выдаёт следующий блок из целых пакетов. Возвращает false, когда данных больше нет.
    bool next(Bytes& block) {
        // clear() не освобождает память буфера — используем её повторно.
        block.clear();
        if (finished) return false;
        // Начинаем блок с хвоста, оставшегося от прошлого куска.
        block.insert(block.end(), pending.begin(), pending.end());
        pending.clear();
        while (true) {
            // 1. Дочитываем кусок до 4 МиБ (не выходя за --limit-mib).
            size_t want = 4 * MiB;
            if (limit) want = size_t(std::min<uint64_t>(want, limit > file_pos ? limit - file_pos : 0));
            size_t old = block.size();
            block.resize(old + want);
            size_t got = want ? read_full(block.data() + old, want) : 0;
            block.resize(old + got);
            file_pos += got;
            bool at_limit = limit && file_pos >= limit;
            bool at_eof = got < want;
            // 2. Идём по заголовкам записей (16 байт): узнаём длину пакета и прыгаем дальше.
            //    Сами байты пакетов здесь не разбираем — это работа рабочих потоков.
            size_t pos = 0;
            bool stop = false;
            while (block.size() - pos >= 16) {
                uint32_t n = word32(block.data() + pos + 8, little);         // длина в файле
                uint32_t original = word32(block.data() + pos + 12, little); // длина в сети
                if (n > snaplen || n > original) throw std::runtime_error("Invalid packet record length");
                if (limit && bytes + 16 + n > limit) { stop = true; break; } // пакет за лимитом
                if (block.size() - pos < 16 + size_t(n)) break;              // пакет не влез целиком
                pos += 16 + n; bytes += 16 + n;
            }
            // Ни одного целого пакета (очень большой пакет) — читаем ещё кусок.
            if (!stop && pos == 0 && !at_eof && !at_limit) continue;
            // 3. Всё после последнего целого пакета — «хвост».
            size_t rest = block.size() - pos;
            if (stop || at_limit) finished = true;
            else if (at_eof) {
                // Файл кончился, а хвост остался — значит, файл обрезан.
                if (rest) throw std::runtime_error(rest < 16 ? "Incomplete packet record header"
                                                             : "Incomplete packet data");
                finished = true;
            } else pending.assign(block.begin() + long(pos), block.end()); // хвост — в следующий блок
            block.resize(pos);   // в блоке оставляем только целые пакеты
            return !block.empty();
        }
    }
};

// -----------------------------------------------------------------------------
// Поиск сигнатур (--signatures): ищем в содержимом пакета опасные строки,
// как простые системы обнаружения вторжений (IDS).
// -----------------------------------------------------------------------------
const std::vector<std::string> SIGNATURES = {
    "GET /", "POST /", "HTTP/1.",      // HTTP-запросы
    "/etc/passwd", "cmd.exe",          // попытки добраться до системных файлов/команд
    "<script",                         // внедрение JavaScript (XSS)
    "SELECT ", "UNION SELECT",         // SQL-инъекции
    std::string(8, '\x90'),            // NOP-цепочка (признак эксплойта)
    "\x7f" "ELF"};                     // заголовок исполняемого файла Linux

// Таблица ускорения: для каждого байта — битовая маска сигнатур, которые с него
// начинаются. Бит k = 1 означает «сигнатура номер k начинается с этого байта».
std::array<uint32_t, 256> signature_index() {
    std::array<uint32_t, 256> index{};
    for (size_t k = 0; k < SIGNATURES.size(); ++k) index[uint8_t(SIGNATURES[k][0])] |= 1u << k;
    return index;
}
const std::array<uint32_t, 256> FIRST_BYTE = signature_index();

// Ищет сигнатуры в n байтах. Возвращает маску найденных (каждая — максимум один раз).
// Для каждого байта по таблице берём сигнатуры, начинающиеся с него,
// и сравниваем их целиком (memcmp). Это тяжёлая работа: смотрим каждый байт.
uint32_t find_signatures(const uint8_t* p, size_t n) {
    uint32_t found = 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t candidates = FIRST_BYTE[p[i]] & ~found;    // уже найденные пропускаем
        while (candidates) {
            unsigned k = unsigned(__builtin_ctz(candidates)); // номер младшего единичного бита
            candidates &= candidates - 1;                     // убираем этот бит
            const std::string& sig = SIGNATURES[k];
            if (i + sig.size() <= n && std::memcmp(p + i, sig.data(), sig.size()) == 0) found |= 1u << k;
        }
    }
    return found;
}

// -----------------------------------------------------------------------------
// Статистика. У каждого рабочего потока своя копия Stats — поэтому
// при подсчёте пакетов не нужны блокировки. В конце копии складываются (merge).
// -----------------------------------------------------------------------------
struct Counter { uint64_t packets = 0, bytes = 0; };   // пакеты и байты
struct IPStat { Counter sent, received; };            // по IP: отправлено и получено
struct Stats {
    uint64_t total = 0;        // всего пакетов
    uint64_t invalid = 0;      // битые (неполные или неверные заголовки)
    uint64_t unsupported = 0;  // не IPv4 (например, ARP, IPv6)
    uint64_t filtered = 0;     // не прошли фильтр
    uint64_t checked = 0, bad_checksum = 0;     // только при --checksum
    std::array<uint64_t, 32> signature_hits{};  // только при --signatures: сколько пакетов с каждой сигнатурой
    Counter selected;                           // прошли фильтр и попали в статистику
    std::array<Counter, 256> protocols{};       // по номеру протокола: [6] = TCP, [17] = UDP, [1] = ICMP
    std::unordered_map<uint32_t, IPStat> ips;   // по каждому IP-адресу
};

// -----------------------------------------------------------------------------
// packet — разбор ОДНОГО пакета. Это главная функция анализа.
// Её вызывают и seq, и par, поэтому результаты обоих режимов одинаковые.
//   p    — байты пакета, n — сколько байт записано в файл,
//   wire — исходная длина пакета в сети, o — настройки, s — куда считать.
//
// Устройство пакета:
//   [Ethernet 14 байт][VLAN 4 байта, если есть][IPv4 ≥ 20 байт][TCP/UDP/ICMP][данные]
// -----------------------------------------------------------------------------
void packet(const uint8_t* p, size_t n, uint32_t wire, const Options& o, Stats& s) {
    ++s.total;
    // ---- Ethernet: 6 байт MAC получателя, 6 байт MAC отправителя, 2 байта типа ----
    if (n < 14) { ++s.invalid; return; }
    size_t offset = 14;
    uint16_t ether = be16(p + 12);          // тип: 0x0800 = IPv4
    // VLAN-метка (0x8100 или 0x88a8) добавляет 4 байта; меток может быть несколько.
    while (ether == 0x8100 || ether == 0x88a8) {
        if (n < offset + 4) { ++s.invalid; return; }
        ether = be16(p + offset + 2); offset += 4;
    }
    if (ether != 0x0800) { ++s.unsupported; return; }   // не IPv4 — не разбираем

    // ---- IPv4 ----
    if (n < offset + 20) { ++s.invalid; return; }
    const uint8_t* ip = p + offset;
    size_t ihl = size_t(ip[0] & 15) * 4;   // длина заголовка IP (обычно 20 байт)
    uint16_t length = be16(ip + 2);        // полная длина IP-пакета
    // Проверяем: версия 4, длины разумные, пакет не обрезан посреди заголовка.
    if ((ip[0] >> 4) != 4 || ihl < 20 || length < ihl || n < offset + ihl
        || wire < offset + length) { ++s.invalid; return; }
    // В файл могла записаться только часть пакета — работаем только с доступными байтами.
    size_t available = std::min(n - offset, size_t(length));
    unsigned proto = ip[9];                            // протокол: 6 = TCP, 17 = UDP, 1 = ICMP
    uint32_t src = be32(ip + 12), dst = be32(ip + 16); // IP отправителя и получателя
    // Фрагментация: большой пакет может быть разбит на части.
    // Заголовок TCP/UDP есть только в первом фрагменте.
    bool first_fragment = (be16(ip + 6) & 0x1fff) == 0;
    bool more_fragments = (be16(ip + 6) & 0x2000) != 0;

    // ---- TCP / UDP: порты и проверка длины заголовка ----
    int sport = -1, dport = -1;                        // -1 = порт неизвестен
    if (first_fragment && (proto == 6 || proto == 17)) {
        size_t min_header = proto == 6 ? 20 : 8;       // TCP ≥ 20 байт, UDP = 8 байт
        if (!more_fragments && length < ihl + min_header) { ++s.invalid; return; }
        if (available >= ihl + 4) {                    // первые 4 байта: порт отправителя и получателя
            sport = be16(ip + ihl); dport = be16(ip + ihl + 2);
        }
        if (proto == 6 && available >= ihl + 13) {     // TCP: длина заголовка в 12-м байте
            size_t tcp_header = size_t(ip[ihl + 12] >> 4) * 4;
            if (tcp_header < 20 || (!more_fragments && length < ihl + tcp_header)) { ++s.invalid; return; }
        }
        if (proto == 17 && available >= ihl + 8) {     // UDP: длина в байтах 4–5
            unsigned udp_length = be16(ip + ihl + 4);
            if (udp_length < 8 || (!more_fragments && udp_length > length - ihl)) {
                ++s.invalid; return;
            }
        }
    } else if (first_fragment && proto == 1 && length < ihl + 8) {   // ICMP: заголовок 8 байт, портов нет
        ++s.invalid; return;
    }

    // ---- Фильтр: все заданные условия должны выполняться («И») ----
    if ((o.protocol >= 0 && unsigned(o.protocol) != proto)
        || (o.has_ip && o.ip != src && o.ip != dst)          // IP — отправитель или получатель
        || (o.port >= 0 && o.port != sport && o.port != dport)) {
        ++s.filtered; return;
    }

    // ---- --checksum: проверка контрольных сумм ----
    // Контрольная сумма — «подпись» пакета: если байты повредились, она не сойдётся.
    // Проверка проходит по всем байтам пакета, поэтому это более тяжёлая работа.
    if (o.verify) {
        bool ok = checksum(ip, ihl) == 0;  // сумма заголовка IPv4 (у верного пакета = 0)
        // Транспортный уровень проверяем только у целого, полностью записанного пакета.
        if (first_fragment && !more_fragments && available == length) {
            const uint8_t* t = ip + ihl;
            size_t tlen = length - ihl;
            if (proto == 6 || (proto == 17 && be16(t + 6) != 0)) {   // у UDP сумма 0 = «не считали»
                // TCP и UDP добавляют к сумме «псевдозаголовок»: IP-адреса, протокол, длину.
                uint32_t pseudo = (src >> 16) + (src & 65535) + (dst >> 16) + (dst & 65535)
                                + proto + uint32_t(tlen);
                ok = ok && checksum(t, tlen, pseudo) == 0;
            } else if (proto == 1) ok = ok && checksum(t, tlen) == 0;
        }
        ++s.checked;
        if (!ok) ++s.bad_checksum;
    }

    // ---- --signatures: поиск сигнатур в содержимом (после заголовков) ----
    if (o.signatures) {
        size_t start = ihl;   // где начинаются данные пакета
        if (first_fragment) {
            if (proto == 6 && available >= ihl + 13) start = ihl + size_t(ip[ihl + 12] >> 4) * 4;
            else if (proto == 17 || proto == 1) start = ihl + 8;
        }
        if (start < available) {
            uint32_t found = find_signatures(ip + start, available - start);
            while (found) {    // для каждого найденного бита увеличиваем свой счётчик
                ++s.signature_hits[unsigned(__builtin_ctz(found))];
                found &= found - 1;
            }
        }
    }

    // ---- Статистика: протокол и оба IP-адреса ----
    ++s.selected.packets; s.selected.bytes += wire;
    ++s.protocols[proto].packets; s.protocols[proto].bytes += wire;
    ++s.ips[src].sent.packets; s.ips[src].sent.bytes += wire;          // отправитель
    ++s.ips[dst].received.packets; s.ips[dst].received.bytes += wire;  // получатель
}

// Разбирает все пакеты одного блока по очереди.
// Блок: [16 байт заголовка записи][пакет][16 байт][пакет]...
void analyze_block(const Bytes& block, bool little, const Options& o, Stats& stats) {
    size_t pos = 0;
    const uint8_t* data = block.data();
    while (pos < block.size()) {
        uint32_t n = word32(data + pos + 8, little);      // сколько байт пакета в файле
        uint32_t wire = word32(data + pos + 12, little);  // исходная длина пакета в сети
        packet(data + pos + 16, n, wire, o, stats);
        pos += 16 + n;                                    // переходим к следующей записи
    }
}

// -----------------------------------------------------------------------------
// Queue — общая очередь блоков между читателем и рабочими потоками
// (схема «производитель — потребители»).
//
//   mutex  — только один поток одновременно меняет очередь;
//   ready  — «появился блок»: будит рабочих, которые ждут работу;
//   space  — «появилось место»: будит читателя, если очередь была полна.
//
// Очередь ограничена (capacity): если рабочие не успевают, читатель ждёт
// и не загружает весь файл в память.
// wait(lock, условие) — поток спит, пока условие ложно; условие проверяется
// заново после пробуждения (защита от «ложных пробуждений»).
// -----------------------------------------------------------------------------
class Queue {
    std::deque<Bytes> blocks;
    std::mutex mutex;
    std::condition_variable ready, space;
    size_t capacity;
    bool closed = false;     // true — блоков больше не будет
public:
    explicit Queue(size_t size) : capacity(size) {}

    // Читатель кладёт блок. Если очередь полна — ждёт, пока освободится место.
    void push(Bytes block) {
        std::unique_lock lock(mutex);
        space.wait(lock, [&] { return closed || blocks.size() < capacity; });
        if (closed) return;
        blocks.push_back(std::move(block)); ready.notify_one();   // будим одного рабочего
    }

    // Рабочий берёт блок. Если пусто — ждёт. false = очередь закрыта и пуста, работа окончена.
    bool pop(Bytes& block) {
        std::unique_lock lock(mutex);
        ready.wait(lock, [&] { return closed || !blocks.empty(); });
        if (blocks.empty()) return false;
        block = std::move(blocks.front()); blocks.pop_front(); space.notify_one();   // будим читателя
        return true;
    }

    // Закрыть очередь: будим всех, чтобы никто не остался ждать вечно.
    void close() {
        std::lock_guard lock(mutex);
        closed = true; ready.notify_all(); space.notify_all();
    }
};

// Сложение статистики двух потоков: a += b.
void add(Counter& a, const Counter& b) { a.packets += b.packets; a.bytes += b.bytes; }
void merge(Stats& a, const Stats& b) {
    a.total += b.total; a.invalid += b.invalid;
    a.unsupported += b.unsupported; a.filtered += b.filtered;
    a.checked += b.checked; a.bad_checksum += b.bad_checksum;
    for (size_t i = 0; i < a.signature_hits.size(); ++i) a.signature_hits[i] += b.signature_hits[i];
    add(a.selected, b.selected);
    for (size_t i = 0; i < 256; ++i) add(a.protocols[i], b.protocols[i]);
    for (const auto& [ip, stat] : b.ips) {
        add(a.ips[ip].sent, stat.sent); add(a.ips[ip].received, stat.received);
    }
}

// -----------------------------------------------------------------------------
// run — главная функция обработки: последовательный или параллельный режим.
// -----------------------------------------------------------------------------
Stats run(Reader& reader, const Options& o) {
    Stats result;

    // ===== Последовательный режим (seq): один поток делает всё по очереди =====
    if (o.mode == "seq") {
        Bytes block;
        while (reader.next(block)) analyze_block(block, reader.little, o, result);
        return result;
    }

    // ===== Параллельный режим (par) =====
    // Главный поток — читатель, P рабочих потоков — анализ.
    Queue queue(std::min<size_t>(o.threads * 2, 16));   // очередь до 2P блоков, но не больше 16

    // Пул свободных буферов: обработанный блок рабочий возвращает сюда,
    // читатель берёт его снова — не нужно каждый раз выделять 4 МиБ памяти.
    std::vector<Bytes> spare;
    std::mutex spare_mutex;

    std::vector<Stats> local(o.threads);   // своя статистика у каждого потока — без блокировок
    std::vector<std::thread> workers;

    // Если в каком-то потоке ошибка: запоминаем её и закрываем очередь,
    // чтобы остальные потоки не ждали вечно (нет зависания / deadlock).
    std::exception_ptr failure;
    std::mutex failure_mutex;
    auto save_failure = [&] {
        std::lock_guard lock(failure_mutex);
        if (!failure) failure = std::current_exception();
        queue.close();
    };

    try {
        // 1. Запускаем P рабочих потоков.
        for (unsigned i = 0; i < o.threads; ++i) {
            workers.emplace_back([&, i] {
                try {
                    Bytes block;
                    while (queue.pop(block)) {                              // взять блок
                        analyze_block(block, reader.little, o, local[i]);   // разобрать в СВОЮ статистику
                        std::lock_guard lock(spare_mutex);
                        spare.push_back(std::move(block));                  // вернуть буфер в пул
                    }
                } catch (...) { save_failure(); }
            });
        }
        // 2. Главный поток читает файл и кладёт блоки в очередь.
        while (true) {
            Bytes block;
            {
                std::lock_guard lock(spare_mutex);    // берём свободный буфер из пула, если есть
                if (!spare.empty()) { block = std::move(spare.back()); spare.pop_back(); }
            }
            if (!reader.next(block)) break;            // файл кончился
            queue.push(std::move(block));
        }
    } catch (...) { save_failure(); }

    // 3. Блоков больше не будет: закрываем очередь и ждём завершения всех потоков.
    queue.close();
    for (auto& worker : workers) worker.join();
    if (failure) std::rethrow_exception(failure);     // ошибку из потока передаём в main

    // 4. Складываем статистику всех потоков в один результат.
    for (const auto& stats : local) merge(result, stats);
    return result;
}

// Название протокола по номеру.
std::string protocol_name(unsigned p) {
    if (p == 6) return "TCP";
    if (p == 17) return "UDP";
    if (p == 1) return "ICMP";
    return "IP-" + std::to_string(p);
}

// -----------------------------------------------------------------------------
// Вывод результата: обычный текст или JSON (--json, удобно для скриптов).
// -----------------------------------------------------------------------------
void output(const Stats& s, const Options& o, uint64_t bytes, double seconds) {
    std::cout << std::fixed << std::setprecision(6);
    if (o.json) {
        std::cout << "{\"mode\":\"" << o.mode << "\",\"threads\":" << o.threads
                  << ",\"seconds\":" << seconds << ",\"file_bytes\":" << bytes
                  << ",\"total\":" << s.total << ",\"invalid\":" << s.invalid
                  << ",\"unsupported\":" << s.unsupported << ",\"filtered\":" << s.filtered
                  << ",\"selected\":" << s.selected.packets << ",\"selected_bytes\":" << s.selected.bytes;
        if (o.verify) std::cout << ",\"checked\":" << s.checked << ",\"bad_checksum\":" << s.bad_checksum;
        if (o.signatures) {
            std::cout << ",\"signatures\":[";
            for (size_t k = 0; k < SIGNATURES.size(); ++k) std::cout << (k ? "," : "") << s.signature_hits[k];
            std::cout << ']';
        }
        std::cout << ",\"protocols\":{";
        bool first = true;
        for (unsigned i = 0; i < 256; ++i) if (s.protocols[i].packets) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << '"' << protocol_name(i) << "\":[" << s.protocols[i].packets
                      << ',' << s.protocols[i].bytes << ']';
        }
        std::cout << "},\"ips\":{";
        // Сортируем IP по возрастанию, чтобы вывод seq и par можно было сравнить. В замер времени не входит.
        std::map<uint32_t, IPStat> sorted(s.ips.begin(), s.ips.end());
        first = true;
        for (const auto& [ip, st] : sorted) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << '"' << ip_string(ip) << "\":[" << st.sent.packets << ',' << st.sent.bytes
                      << ',' << st.received.packets << ',' << st.received.bytes << ']';
        }
        std::cout << "}}\n";
    } else {
        std::cout << "Mode: " << o.mode << ", workers: " << (o.mode == "par" ? o.threads : 0)
                  << "\nTime: " << seconds << " s\nThroughput: " << double(bytes) / MiB / seconds
                  << " MiB/s\nPCAP bytes processed: " << bytes
                  << "\nPackets: " << s.total << "\nSelected: " << s.selected.packets
                  << "\nSelected wire bytes: " << s.selected.bytes << "\nFiltered: " << s.filtered
                  << "\nInvalid: " << s.invalid << "\nUnsupported: " << s.unsupported << '\n';
        if (o.verify) std::cout << "Checksum checked: " << s.checked
                                << ", bad: " << s.bad_checksum << '\n';
        if (o.signatures) {
            std::cout << "Signature matches (packets):\n";
            for (size_t k = 0; k < SIGNATURES.size(); ++k) {
                std::string name = k == 8 ? "NOP x8 (0x90)" : k == 9 ? "\\x7fELF" : SIGNATURES[k];
                std::cout << "  " << name << ": " << s.signature_hits[k] << '\n';
            }
        }
        for (unsigned i = 0; i < 256; ++i) if (s.protocols[i].packets)
            std::cout << protocol_name(i) << ": " << s.protocols[i].packets
                      << " packets, " << s.protocols[i].bytes << " bytes\n";
        // Топ-10 IP-адресов по объёму трафика (отправлено + получено).
        std::vector<std::pair<uint32_t, IPStat>> top(s.ips.begin(), s.ips.end());
        std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) {
            uint64_t x = a.second.sent.bytes + a.second.received.bytes;
            uint64_t y = b.second.sent.bytes + b.second.received.bytes;
            return x != y ? x > y : a.first < b.first;
        });
        std::cout << "Unique IPs: " << s.ips.size() << "\nTop IPs (sent + received bytes):\n";
        for (size_t i = 0; i < std::min<size_t>(10, top.size()); ++i)
            std::cout << ip_string(top[i].first) << ": " << top[i].second.sent.packets
                      << " sent, " << top[i].second.received.packets << " received, "
                      << top[i].second.sent.bytes + top[i].second.received.bytes << " bytes\n";
    }
}

// -----------------------------------------------------------------------------
// main: аргументы → замер времени (открытие, чтение, анализ, сложение) → вывод.
// Печать результата в замер времени не входит.
// -----------------------------------------------------------------------------
int main(int argc, char** argv) {
    try {
        Options o = arguments(argc, argv);
        auto begin = std::chrono::steady_clock::now();
        Reader reader(o);
        Stats stats = run(reader, o);
        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
        output(stats, o, reader.bytes, seconds);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n'; return 1;
    }
}
