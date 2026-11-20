// =============================================================================
// common.h — общие маленькие функции для analyze.cpp и generate.cpp:
// чтение/запись чисел из байтов, IP-адрес ↔ строка, контрольная сумма.
// =============================================================================
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;          // массив байтов (блок файла, пакет)
constexpr uint64_t MiB = 1024ULL * 1024;     // 1 мебибайт = 1 048 576 байт

// Порядок байтов: в PCAP его задаёт заголовок файла (обычно младший байт первым),
// а в сетевых заголовках (IP, TCP, UDP) всегда старший байт первым (big-endian).

// Прочитать 2-байтовое число, старший байт первым (сетевой порядок).
inline uint16_t be16(const uint8_t* p) {
    return uint16_t((uint16_t(p[0]) << 8) | p[1]);
}
// Прочитать 4-байтовое число, старший байт первым (сетевой порядок).
inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) << 8) | p[3];
}
// Прочитать 4-байтовое число из заголовка PCAP в порядке, заданном файлом.
inline uint32_t word32(const uint8_t* p, bool little) {
    if (!little) return be32(p);
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
// Записать 2- и 4-байтовое число в сетевом порядке (нужно генератору).
inline void put16(uint8_t* p, uint16_t x) {
    p[0] = uint8_t(x >> 8); p[1] = uint8_t(x);
}
inline void put32(uint8_t* p, uint32_t x) {
    p[0] = uint8_t(x >> 24); p[1] = uint8_t(x >> 16);
    p[2] = uint8_t(x >> 8); p[3] = uint8_t(x);
}
// Записать 4-байтовое число младшим байтом первым (для заголовков PCAP).
inline void little32(uint8_t* p, uint32_t x) {
    for (int i = 0; i < 4; ++i) p[i] = uint8_t(x >> (8 * i));
}
// IP-адрес хранится как одно 32-битное число. Число → строка "10.0.0.1".
inline std::string ip_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255)
        + "." + std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
// Строка "10.0.0.1" → число. Проверяет: ровно 4 части, только цифры, каждая 0..255.
inline uint32_t parse_ip(const std::string& s) {
    uint32_t result = 0;
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        size_t end = s.find('.', pos);
        if ((i < 3 && end == std::string::npos) || (i == 3 && end != std::string::npos))
            throw std::runtime_error("Invalid IPv4 address");
        std::string part = s.substr(pos, end == std::string::npos ? end : end - pos);
        if (part.empty() || part.size() > 3 || part.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("Invalid IPv4 address");
        unsigned n = unsigned(std::stoul(part));
        if (n > 255) throw std::runtime_error("Invalid IPv4 address");
        result = (result << 8) | n;   // сдвигаем на байт и добавляем очередную часть
        if (i < 3) pos = end + 1;
    }
    return result;
}
// Строка → неотрицательное целое (с проверкой, что там только цифры).
inline uint64_t number(const std::string& s) {
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("Expected a non-negative integer: " + s);
    return std::stoull(s);
}
// Контрольная сумма Интернета (IP, TCP, UDP, ICMP):
// складываем все 16-битные слова, переносы за 16 бит добавляем обратно, инвертируем.
// Если в данных уже стоит правильная сумма, результат проверки = 0.
// sum — начальное значение (для TCP/UDP туда передают псевдозаголовок).
inline uint16_t checksum(const uint8_t* p, size_t n, uint32_t sum = 0) {
    while (n >= 2) { sum += be16(p); p += 2; n -= 2; }
    if (n) sum += uint16_t(p[0]) << 8;                     // нечётный последний байт
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);   // переносы обратно в сумму
    return uint16_t(~sum);
}
