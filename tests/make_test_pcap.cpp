#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

using Bytes = std::vector<uint8_t>;

static void be16(Bytes& p, size_t n, uint16_t value) {
    p[n] = value >> 8;
    p[n + 1] = value;
}

static uint32_t sum(const Bytes& p, size_t start, size_t end) {
    uint32_t value = 0;
    for (size_t i = start; i < end; i += 2)
        value += (uint32_t(p[i]) << 8) + (i + 1 < end ? p[i + 1] : 0);
    return value;
}

static uint16_t fold(uint32_t value) {
    while (value >> 16) value = (value & 65535) + (value >> 16);
    return ~value;
}

static void le32(std::ofstream& file, uint32_t value) {
    for (int i = 0; i < 4; ++i) file.put(value >> (8 * i));
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "uso: make_test_pcap saida.pcap\n";
        return 1;
    }
    std::ofstream file(argv[1], std::ios::binary);
    le32(file, 0xa1b2c3d4); le32(file, 0x00040002);
    le32(file, 0); le32(file, 0); le32(file, 65535); le32(file, 1);

    // real udp frames: sid 2008414 positive and negative controls.
    for (int negative = 0; negative < 2; ++negative) {
        Bytes p(42 + 200, 0);
        p[0] = 2; p[5] = 2; p[6] = 2; p[11] = 1;
        be16(p, 12, 0x0800);
        p[14] = 0x45; be16(p, 16, p.size() - 14);
        p[22] = 64; p[23] = 17;
        p[26] = 198; p[27] = 51; p[28] = 100; p[29] = 1;
        p[30] = 10; p[33] = 2;
        be16(p, 24, fold(sum(p, 14, 34)));
        be16(p, 34, 12345 + negative); be16(p, 36, 69);
        be16(p, 38, p.size() - 34);
        const char pattern[] = "Rand0mSTRING\0netascii";
        for (size_t i = 0; i < sizeof(pattern) - 1; ++i)
            p[44 + i] = pattern[i];
        if (negative) p[44] = 'X';
        uint16_t checksum = fold(sum(p, 26, 34) + 17 + p.size() - 34 + sum(p, 34, p.size()));
        be16(p, 40, checksum ? checksum : 65535);
        le32(file, 1700000000 + negative); le32(file, 0);
        le32(file, p.size()); le32(file, p.size());
        file.write(reinterpret_cast<const char*>(p.data()), p.size());
    }
    return file ? 0 : 1;
}
