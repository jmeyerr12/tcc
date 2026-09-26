#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

namespace {

std::uint32_t read_u32(const unsigned char *p, bool little_endian) {
    if (little_endian) {
        return static_cast<std::uint32_t>(p[0]) |
               (static_cast<std::uint32_t>(p[1]) << 8U) |
               (static_cast<std::uint32_t>(p[2]) << 16U) |
               (static_cast<std::uint32_t>(p[3]) << 24U);
    }
    return (static_cast<std::uint32_t>(p[0]) << 24U) |
           (static_cast<std::uint32_t>(p[1]) << 16U) |
           (static_cast<std::uint32_t>(p[2]) << 8U) |
           static_cast<std::uint32_t>(p[3]);
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "uso: pcap_stats ARQUIVO.pcap\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    unsigned char global[24] = {};
    if (!input.read(reinterpret_cast<char *>(global), sizeof(global))) {
        std::cerr << "cabecalho PCAP ausente\n";
        return 1;
    }

    const bool little_endian =
        global[0] == 0xd4 && global[1] == 0xc3 && global[2] == 0xb2 && global[3] == 0xa1;
    const bool big_endian =
        global[0] == 0xa1 && global[1] == 0xb2 && global[2] == 0xc3 && global[3] == 0xd4;
    if (!little_endian && !big_endian) {
        std::cerr << "formato nao e PCAP classico\n";
        return 1;
    }

    std::uint64_t packets = 0;
    std::uint64_t captured_bytes = 0;
    std::uint64_t wire_bytes = 0;
    std::uint64_t truncated = 0;
    std::uint64_t at_most_96 = 0;
    std::uint64_t over_313 = 0;
    std::uint64_t over_1363 = 0;
    std::uint64_t over_1514 = 0;
    std::uint64_t over_2100 = 0;
    std::uint64_t bytes_over_1514 = 0;
    std::uint64_t bytes_over_2100 = 0;
    std::uint32_t largest = 0;
    unsigned char record[16] = {};
    while (input.read(reinterpret_cast<char *>(record), sizeof(record))) {
        const std::uint32_t captured = read_u32(record + 8, little_endian);
        const std::uint32_t wire = read_u32(record + 12, little_endian);
        input.ignore(captured);
        if (!input) {
            std::cerr << "registro PCAP incompleto depois de " << packets << " pacotes\n";
            return 1;
        }
        ++packets;
        captured_bytes += captured;
        wire_bytes += wire;
        truncated += captured < wire;
        at_most_96 += captured <= 96;
        over_313 += captured > 313;
        over_1363 += captured > 1363;
        over_1514 += captured > 1514;
        over_2100 += captured > 2100;
        if (captured > 1514) {
            bytes_over_1514 += captured;
        }
        if (captured > 2100) {
            bytes_over_2100 += captured;
        }
        if (captured > largest) {
            largest = captured;
        }
    }

    std::cout << "pacotes=" << packets << '\n'
              << "bytes_capturados=" << captured_bytes << '\n'
              << "bytes_no_fio=" << wire_bytes << '\n'
              << "pacotes_truncados=" << truncated << '\n'
              << "pacotes_ate_96_bytes=" << at_most_96 << '\n'
              << "pacotes_maiores_que_313=" << over_313 << '\n'
              << "pacotes_maiores_que_1363=" << over_1363 << '\n'
              << "pacotes_maiores_que_1514=" << over_1514 << '\n'
              << "pacotes_maiores_que_2100=" << over_2100 << '\n'
              << "bytes_em_pacotes_maiores_que_1514=" << bytes_over_1514 << '\n'
              << "bytes_em_pacotes_maiores_que_2100=" << bytes_over_2100 << '\n'
              << "maior_pacote=" << largest << '\n'
              << std::fixed << std::setprecision(2)
              << "tamanho_medio="
              << (packets == 0 ? 0.0 : static_cast<double>(captured_bytes) / packets)
              << '\n';
    return 0;
}
