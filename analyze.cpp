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

struct Options {
    std::string file, mode = "seq";
    unsigned threads = 1;
    uint64_t limit = 0;
    int protocol = -1, port = -1;
    bool has_ip = false, json = false, verify = false, signatures = false;
    uint32_t ip = 0;
};

Options arguments(int argc, char** argv) {
    if (argc < 2) throw std::runtime_error(
        "Usage: ./analyze FILE [--mode seq|par] [--threads N] [--limit-mib N] "
        "[--protocol tcp|udp|icmp] [--ip ADDRESS] [--port N] [--checksum] [--signatures] [--json]");
    Options o; o.file = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string key = argv[i];
        if (key == "--json") { o.json = true; continue; }
        if (key == "--checksum") { o.verify = true; continue; }
        if (key == "--signatures") { o.signatures = true; continue; }
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

// Закрывает файл, даже если конструктор Reader выбросил исключение.
struct File {
    int fd = -1;
    File() = default;
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    ~File() { if (fd >= 0) close(fd); }
};

// Читатель берёт файл крупными кусками (4 МиБ) одним системным вызовом read()
// и только находит в куске границы записей. Неполная запись в конце куска
// переносится в начало следующего блока, поэтому граница блока не разрезает пакет.
class Reader {
    File file;
    Bytes pending;           // хвост предыдущего куска: начало неполной записи
    uint64_t file_pos = 24;  // сколько байт файла уже прочитано
    uint32_t snaplen = 0;
    uint64_t limit;
    bool finished = false;
    size_t read_full(uint8_t* dst, size_t n) {
        size_t got = 0;
        while (got < n) {
            ssize_t r = ::read(file.fd, dst + got, n - got);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) throw std::runtime_error("Cannot read PCAP file");
            if (r == 0) break;
            got += size_t(r);
        }
        return got;
    }
public:
    bool little = true;
    uint64_t bytes = 24;     // байты целых записей, переданных на анализ
    Reader(const Options& o) : limit(o.limit) {
        file.fd = ::open(o.file.c_str(), O_RDONLY);
        if (file.fd < 0) throw std::runtime_error("Cannot open PCAP file");
        uint8_t h[24];
        if (read_full(h, 24) != 24) throw std::runtime_error("Incomplete PCAP header");
        uint32_t magic = be32(h);
        if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) little = true;
        else if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) little = false;
        else throw std::runtime_error("Expected classic PCAP (pcapng is not supported)");
        auto field16 = [&](const uint8_t* p) {
            return little ? uint16_t(p[0] | (uint16_t(p[1]) << 8)) : be16(p);
        };
        if (field16(h + 4) != 2 || field16(h + 6) != 4)
            throw std::runtime_error("Expected PCAP version 2.4");
        snaplen = word32(h + 16, little);
        if (!snaplen || snaplen > 16 * MiB) throw std::runtime_error("Unsupported snaplen");
        if ((word32(h + 20, little) & 65535) != 1)
            throw std::runtime_error("Only Ethernet PCAP is supported");
    }
    bool next(Bytes& block) {
        // clear() сохраняет выделенную память буфера: повторно используем её.
        block.clear();
        if (finished) return false;
        block.insert(block.end(), pending.begin(), pending.end());
        pending.clear();
        while (true) {
            // Дочитываем кусок, не выходя за заданный объём --limit-mib.
            size_t want = 4 * MiB;
            if (limit) want = size_t(std::min<uint64_t>(want, limit > file_pos ? limit - file_pos : 0));
            size_t old = block.size();
            block.resize(old + want);
            size_t got = want ? read_full(block.data() + old, want) : 0;
            block.resize(old + got);
            file_pos += got;
            bool at_limit = limit && file_pos >= limit;
            bool at_eof = got < want;
            // Проходим по заголовкам записей (16 байт), сами пакеты не трогаем.
            size_t pos = 0;
            bool stop = false;
            while (block.size() - pos >= 16) {
                uint32_t n = word32(block.data() + pos + 8, little);
                uint32_t original = word32(block.data() + pos + 12, little);
                if (n > snaplen || n > original) throw std::runtime_error("Invalid packet record length");
                if (limit && bytes + 16 + n > limit) { stop = true; break; }
                if (block.size() - pos < 16 + size_t(n)) break;
                pos += 16 + n; bytes += 16 + n;
            }
            if (!stop && pos == 0 && !at_eof && !at_limit) continue;  // запись больше куска
            size_t rest = block.size() - pos;
            if (stop || at_limit) finished = true;
            else if (at_eof) {
                if (rest) throw std::runtime_error(rest < 16 ? "Incomplete packet record header"
                                                             : "Incomplete packet data");
                finished = true;
            } else pending.assign(block.begin() + long(pos), block.end());
            block.resize(pos);
            return !block.empty();
        }
    }
};

// Сигнатуры подозрительного содержимого, как в простых системах обнаружения вторжений.
const std::vector<std::string> SIGNATURES = {
    "GET /", "POST /", "HTTP/1.", "/etc/passwd", "cmd.exe", "<script",
    "SELECT ", "UNION SELECT", std::string(8, '\x90'), "\x7f" "ELF"};

// Для каждого первого байта — битовая маска сигнатур, которые с него начинаются.
std::array<uint32_t, 256> signature_index() {
    std::array<uint32_t, 256> index{};
    for (size_t k = 0; k < SIGNATURES.size(); ++k) index[uint8_t(SIGNATURES[k][0])] |= 1u << k;
    return index;
}
const std::array<uint32_t, 256> FIRST_BYTE = signature_index();

// Возвращает маску сигнатур, найденных в полезной нагрузке (каждая учитывается один раз).
uint32_t find_signatures(const uint8_t* p, size_t n) {
    uint32_t found = 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t candidates = FIRST_BYTE[p[i]] & ~found;
        while (candidates) {
            unsigned k = unsigned(__builtin_ctz(candidates));
            candidates &= candidates - 1;
            const std::string& sig = SIGNATURES[k];
            if (i + sig.size() <= n && std::memcmp(p + i, sig.data(), sig.size()) == 0) found |= 1u << k;
        }
    }
    return found;
}

struct Counter { uint64_t packets = 0, bytes = 0; };
struct IPStat { Counter sent, received; };
struct Stats {
    uint64_t total = 0, invalid = 0, unsupported = 0, filtered = 0;
    uint64_t checked = 0, bad_checksum = 0;  // только при --checksum
    std::array<uint64_t, 32> signature_hits{};  // только при --signatures
    Counter selected;
    std::array<Counter, 256> protocols{};
    std::unordered_map<uint32_t, IPStat> ips;
};

void packet(const uint8_t* p, size_t n, uint32_t wire, const Options& o, Stats& s) {
    ++s.total;
    if (n < 14) { ++s.invalid; return; }
    size_t offset = 14;
    uint16_t ether = be16(p + 12);
    // VLAN добавляет 4 байта между Ethernet и IP; возможны вложенные теги.
    while (ether == 0x8100 || ether == 0x88a8) {
        if (n < offset + 4) { ++s.invalid; return; }
        ether = be16(p + offset + 2); offset += 4;
    }
    if (ether != 0x0800) { ++s.unsupported; return; }
    if (n < offset + 20) { ++s.invalid; return; }
    const uint8_t* ip = p + offset;
    size_t ihl = size_t(ip[0] & 15) * 4;
    uint16_t length = be16(ip + 2);
    if ((ip[0] >> 4) != 4 || ihl < 20 || length < ihl || n < offset + ihl
        || wire < offset + length) { ++s.invalid; return; }
    // Захваченный пакет может быть короче исходного: читаем только доступные байты.
    size_t available = std::min(n - offset, size_t(length));
    unsigned proto = ip[9];
    uint32_t src = be32(ip + 12), dst = be32(ip + 16);
    bool first_fragment = (be16(ip + 6) & 0x1fff) == 0;
    bool more_fragments = (be16(ip + 6) & 0x2000) != 0;
    int sport = -1, dport = -1;
    if (first_fragment && (proto == 6 || proto == 17)) {
        size_t min_header = proto == 6 ? 20 : 8;
        if (!more_fragments && length < ihl + min_header) { ++s.invalid; return; }
        if (available >= ihl + 4) {
            sport = be16(ip + ihl); dport = be16(ip + ihl + 2);
        }
        if (proto == 6 && available >= ihl + 13) {
            size_t tcp_header = size_t(ip[ihl + 12] >> 4) * 4;
            if (tcp_header < 20 || (!more_fragments && length < ihl + tcp_header)) { ++s.invalid; return; }
        }
        if (proto == 17 && available >= ihl + 8) {
            unsigned udp_length = be16(ip + ihl + 4);
            if (udp_length < 8 || (!more_fragments && udp_length > length - ihl)) {
                ++s.invalid; return;
            }
        }
    } else if (first_fragment && proto == 1 && length < ihl + 8) {
        ++s.invalid; return;
    }
    if ((o.protocol >= 0 && unsigned(o.protocol) != proto)
        || (o.has_ip && o.ip != src && o.ip != dst)
        || (o.port >= 0 && o.port != sport && o.port != dport)) {
        ++s.filtered; return;
    }
    // Проверка контрольных сумм — более тяжёлая операция: проходит по всем байтам пакета.
    if (o.verify) {
        bool ok = checksum(ip, ihl) == 0;  // заголовок IPv4
        // Транспортный уровень проверяем только у целого, полностью захваченного пакета.
        if (first_fragment && !more_fragments && available == length) {
            const uint8_t* t = ip + ihl;
            size_t tlen = length - ihl;
            if (proto == 6 || (proto == 17 && be16(t + 6) != 0)) {
                // TCP и UDP включают в сумму псевдозаголовок: адреса, протокол, длину.
                uint32_t pseudo = (src >> 16) + (src & 65535) + (dst >> 16) + (dst & 65535)
                                + proto + uint32_t(tlen);
                ok = ok && checksum(t, tlen, pseudo) == 0;
            } else if (proto == 1) ok = ok && checksum(t, tlen) == 0;
        }
        ++s.checked;
        if (!ok) ++s.bad_checksum;
    }
    // Поиск сигнатур: просматриваем каждый байт полезной нагрузки.
    if (o.signatures) {
        size_t start = ihl;
        if (first_fragment) {
            if (proto == 6 && available >= ihl + 13) start = ihl + size_t(ip[ihl + 12] >> 4) * 4;
            else if (proto == 17 || proto == 1) start = ihl + 8;
        }
        if (start < available) {
            uint32_t found = find_signatures(ip + start, available - start);
            while (found) {
                ++s.signature_hits[unsigned(__builtin_ctz(found))];
                found &= found - 1;
            }
        }
    }
    ++s.selected.packets; s.selected.bytes += wire;
    ++s.protocols[proto].packets; s.protocols[proto].bytes += wire;
    ++s.ips[src].sent.packets; s.ips[src].sent.bytes += wire;
    ++s.ips[dst].received.packets; s.ips[dst].received.bytes += wire;
}

void analyze_block(const Bytes& block, bool little, const Options& o, Stats& stats) {
    size_t pos = 0;
    const uint8_t* data = block.data();
    while (pos < block.size()) {
        uint32_t n = word32(data + pos + 8, little);
        uint32_t wire = word32(data + pos + 12, little);
        packet(data + pos + 16, n, wire, o, stats);
        pos += 16 + n;
    }
}

// Общая очередь хранит блоки. Мьютекс нужен только при добавлении и извлечении.
class Queue {
    std::deque<Bytes> blocks;
    std::mutex mutex;
    std::condition_variable ready, space;
    size_t capacity;
    bool closed = false;
public:
    explicit Queue(size_t size) : capacity(size) {}
    void push(Bytes block) {
        std::unique_lock lock(mutex);
        space.wait(lock, [&] { return closed || blocks.size() < capacity; });
        if (closed) return;
        blocks.push_back(std::move(block)); ready.notify_one();
    }
    bool pop(Bytes& block) {
        std::unique_lock lock(mutex);
        ready.wait(lock, [&] { return closed || !blocks.empty(); });
        if (blocks.empty()) return false;
        block = std::move(blocks.front()); blocks.pop_front(); space.notify_one();
        return true;
    }
    void close() {
        std::lock_guard lock(mutex);
        closed = true; ready.notify_all(); space.notify_all();
    }
};

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

Stats run(Reader& reader, const Options& o) {
    Stats result;
    if (o.mode == "seq") {
        Bytes block;
        while (reader.next(block)) analyze_block(block, reader.little, o, result);
        return result;
    }
    Queue queue(std::min<size_t>(o.threads * 2, 16));
    // Пул свободных буферов: обработанный блок возвращается читателю,
    // чтобы не выделять и не обнулять новые 4 МиБ памяти на каждый блок.
    std::vector<Bytes> spare;
    std::mutex spare_mutex;
    std::vector<Stats> local(o.threads);
    std::vector<std::thread> workers;
    std::exception_ptr failure;
    std::mutex failure_mutex;
    auto save_failure = [&] {
        std::lock_guard lock(failure_mutex);
        if (!failure) failure = std::current_exception();
        queue.close();
    };
    try {
        for (unsigned i = 0; i < o.threads; ++i) {
            workers.emplace_back([&, i] {
                try {
                    Bytes block;
                    while (queue.pop(block)) {
                        analyze_block(block, reader.little, o, local[i]);
                        std::lock_guard lock(spare_mutex);
                        spare.push_back(std::move(block));
                    }
                } catch (...) { save_failure(); }
            });
        }
        while (true) {
            Bytes block;
            {
                std::lock_guard lock(spare_mutex);
                if (!spare.empty()) { block = std::move(spare.back()); spare.pop_back(); }
            }
            if (!reader.next(block)) break;
            queue.push(std::move(block));
        }
    } catch (...) { save_failure(); }
    queue.close();
    for (auto& worker : workers) worker.join();
    if (failure) std::rethrow_exception(failure);
    for (const auto& stats : local) merge(result, stats);
    return result;
}

std::string protocol_name(unsigned p) {
    if (p == 6) return "TCP";
    if (p == 17) return "UDP";
    if (p == 1) return "ICMP";
    return "IP-" + std::to_string(p);
}

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
        // Сортировка нужна только для удобного сравнения и вывода, в замер не входит.
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
