#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
constexpr uint64_t MiB = 1024ULL * 1024;

// В PCAP порядок байтов задаёт заголовок файла, в IP всегда старший байт первым.
inline uint16_t be16(const uint8_t* p) {
    return uint16_t((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) << 8) | p[3];
}
inline uint32_t word32(const uint8_t* p, bool little) {
    if (!little) return be32(p);
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline void put16(uint8_t* p, uint16_t x) {
    p[0] = uint8_t(x >> 8); p[1] = uint8_t(x);
}
inline void put32(uint8_t* p, uint32_t x) {
    p[0] = uint8_t(x >> 24); p[1] = uint8_t(x >> 16);
    p[2] = uint8_t(x >> 8); p[3] = uint8_t(x);
}
inline void little32(uint8_t* p, uint32_t x) {
    for (int i = 0; i < 4; ++i) p[i] = uint8_t(x >> (8 * i));
}
inline std::string ip_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255)
        + "." + std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
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
        result = (result << 8) | n;
        if (i < 3) pos = end + 1;
    }
    return result;
}
inline uint64_t number(const std::string& s) {
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("Expected a non-negative integer: " + s);
    return std::stoull(s);
}
// Контрольная сумма: складываем 16-битные слова, перенос добавляем обратно.
inline uint16_t checksum(const uint8_t* p, size_t n, uint32_t sum = 0) {
    while (n >= 2) { sum += be16(p); p += 2; n -= 2; }
    if (n) sum += uint16_t(p[0]) << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return uint16_t(~sum);
}
