// =============================================================================
// generate.cpp — генератор тестового PCAP-файла заданного размера.
//
// Запуск: ./generate data/traffic.pcap 1024 42   (файл, размер в МиБ, seed)
// Один и тот же seed всегда даёт один и тот же файл — эксперимент воспроизводим.
//
// Что внутри файла:
//   60% TCP, 30% UDP, 10% ICMP; размеры кадров 64/128/512/1024/1514 байт;
//   4096 IP-адресов, начиная с 10.0.0.1; все контрольные суммы правильные.
// =============================================================================
#include "common.h"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>

int main(int argc, char** argv) {
    try {
        // ---- Аргументы и проверки ----
        if (argc < 3 || argc > 4) {
            std::cerr << "Usage: ./generate OUTPUT SIZE_MIB [SEED]\n"; return 1;
        }
        uint64_t size = number(argv[2]);
        if (size == 0 || size > 1024 * 1024) throw std::runtime_error("SIZE_MIB: 1..1048576");
        uint64_t target = size * MiB;                               // нужный размер в байтах
        uint64_t seed = argc == 4 ? number(argv[3]) : 42;
        if (std::filesystem::exists(argv[1])) throw std::runtime_error("Output already exists");  // не затираем
        auto parent = std::filesystem::path(argv[1]).parent_path();
        auto free = std::filesystem::space(parent.empty() ? "." : parent).available;
        if (free < target + 512 * MiB) throw std::runtime_error("Not enough free disk space");

        // ---- Открываем файл с большим буфером записи (4 МиБ) — пишем быстрее ----
        std::ofstream out;
        std::vector<char> buffer(4 * MiB);
        out.rdbuf()->pubsetbuf(buffer.data(), std::streamsize(buffer.size()));
        out.open(argv[1], std::ios::binary);
        if (!out) throw std::runtime_error("Cannot create output file");
        out.exceptions(std::ios::badbit | std::ios::failbit);       // ошибка записи → исключение

        // ---- Общий заголовок PCAP (24 байта): magic, версия 2.4, snaplen, тип канала ----
        uint8_t header[24] = {};
        little32(header, 0xa1b2c3d4); header[4] = 2; header[6] = 4;
        little32(header + 16, 65535); little32(header + 20, 1); // 1 = Ethernet.
        out.write(reinterpret_cast<char*>(header), 24);

        std::mt19937_64 random(seed);                                // генератор случайных чисел
        const std::array<unsigned, 5> sizes = {64, 128, 512, 1024, 1514};
        uint64_t bytes = 24, packets = 0;
        std::array<uint64_t, 3> counts = {};                         // сколько TCP, UDP, ICMP

        // ---- Создаём пакеты, пока не наберём нужный размер ----
        while (true) {
            unsigned length = sizes[random() % sizes.size()];        // случайный размер кадра
            if (bytes + 16 + length > target) break;                 // больше не влезает — стоп
            Bytes p(length, 0);

            // Ethernet: фиксированные MAC-адреса, тип 0x0800 = IPv4.
            for (int i = 0; i < 12; ++i) p[i] = uint8_t(i + 2);
            put16(p.data() + 12, 0x0800);

            // IPv4-заголовок (20 байт).
            uint8_t* ip = p.data() + 14;
            ip[0] = 0x45; put16(ip + 2, uint16_t(length - 14));      // версия 4, длина 20; полная длина
            put16(ip + 4, uint16_t(packets)); put16(ip + 6, 0x4000); ip[8] = 64;  // id, «не фрагментировать», TTL
            // Выбор протокола: 0..59 → TCP, 60..89 → UDP, 90..99 → ICMP.
            unsigned choice = unsigned(random() % 100);
            unsigned kind = choice < 60 ? 0 : (choice < 90 ? 1 : 2);
            ip[9] = kind == 0 ? 6 : (kind == 1 ? 17 : 1);
            // Случайные адреса отправителя и получателя из 4096 узлов.
            put32(ip + 12, 0x0a000001 + uint32_t(random() % 4096));
            put32(ip + 16, 0x0a000001 + uint32_t(random() % 4096));
            put16(ip + 10, checksum(ip, 20));                        // контрольная сумма IP

            // Транспортный уровень: TCP (заголовок 20 байт), UDP или ICMP (8 байт).
            uint8_t* transport = ip + 20;
            unsigned transport_size = length - 34;                   // 34 = Ethernet 14 + IP 20
            unsigned header_size = kind == 0 ? 20 : 8;
            // Данные пакета: один случайный 8-байтовый образец, повторённый много раз.
            uint64_t pattern = random();
            for (unsigned i = header_size; i < transport_size; ++i)
                transport[i] = uint8_t(pattern >> ((i % 8) * 8));
            if (kind < 2) {
                // TCP и UDP: случайный порт отправителя, порт получателя из популярных.
                const uint16_t ports[] = {80, 443, 53, 22, 8080};
                put16(transport, uint16_t(1024 + random() % 60000));
                put16(transport + 2, ports[random() % 5]);
                if (kind == 0) {
                    // TCP: номер последовательности, длина заголовка 20 байт, флаги PSH+ACK, окно.
                    put32(transport + 4, uint32_t(packets));
                    transport[12] = 0x50; transport[13] = 0x18;
                    put16(transport + 14, 65535);
                } else put16(transport + 4, uint16_t(transport_size));   // UDP: длина
                // TCP/UDP учитывают IP-адреса в контрольной сумме (псевдозаголовок).
                uint32_t sum = be16(ip + 12) + be16(ip + 14) + be16(ip + 16)
                             + be16(ip + 18) + ip[9] + transport_size;
                uint16_t check = checksum(transport, transport_size, sum);
                // Сумма 0 у UDP означает «не считали», поэтому вместо 0 пишем 65535.
                put16(transport + (kind == 0 ? 16 : 6), check == 0 ? 65535 : check);
            } else {
                transport[0] = 8; // ICMP Echo Request.
                put16(transport + 4, 1); put16(transport + 6, uint16_t(packets));   // id и номер запроса
                put16(transport + 2, checksum(transport, transport_size));
            }

            // Заголовок записи PCAP (16 байт): время (сек, мкс), длина в файле, длина в сети.
            uint8_t record[16] = {};
            little32(record, 1700000000 + uint32_t(packets / 1000000));
            little32(record + 4, uint32_t(packets % 1000000));
            little32(record + 8, length); little32(record + 12, length);
            out.write(reinterpret_cast<char*>(record), 16);
            out.write(reinterpret_cast<char*>(p.data()), length);
            bytes += 16 + length; ++packets; ++counts[kind];
        }
        out.close();
        // Итог: сколько байт и пакетов каждого протокола записано.
        std::cout << "Bytes: " << bytes << "\nPackets: " << packets
                  << "\nTCP: " << counts[0] << "\nUDP: " << counts[1]
                  << "\nICMP: " << counts[2] << "\nSeed: " << seed << '\n';
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n'; return 1;
    }
}
