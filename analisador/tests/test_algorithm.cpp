#include <cstdlib>
#include <climits>
#include <iostream>
#include <string>
#include <vector>

#include "algorithm.hpp"
#include "parser.hpp"

using namespace std;

static void check(bool condition, const string& message) {
    if (!condition) {
        cerr << "FALHOU: " << message << '\n';
        exit(1);
    }
}

static string rule(const string& protocol, const string& options) {
    return "alert " + protocol + " any any -> any any (" + options + " sid:1;)";
}

static void expect(const string& protocol, const string& options, RuleAction action) {
    string input = rule(protocol, options);
    RuleAnalysis result = analyzeRule(input);
    check(result.action == action, input);
    if (action != ADAPT_RULE) {
        check(result.intervals.empty(), "regra sem adaptacao contribuiu intervalos: " + input);
    }
}

static void expectIntervals(const vector<Interval>& actual, const vector<Interval>& expected) {
    check(actual.size() == expected.size(), "quantidade de intervalos");
    for (size_t i = 0; i < actual.size(); ++i)
        check(actual[i].start == expected[i].start && actual[i].end == expected[i].end,
              "limites inclusivos do intervalo");
}

int main() {
    const string content = "content:\"ABACATE\"; offset:100; depth:100;";

    expect("tcp", content, ADAPT_RULE);
    expect("tcp", "flow:established,to_server;" + content, ADAPT_RULE);
    expect("tcp", "flow:to_server,established;" + content, ADAPT_RULE);
    expect("tcp", "flow:established,to_client;" + content, ADAPT_RULE);
    expect("tcp", "pkt_data;" + content, ADAPT_RULE);
    expect("tcp", "raw_data;" + content, ADAPT_RULE);
    expect("tcp", "flow:no_stream; msg:\"flow:only_stream;\";" + content, ADAPT_RULE);
    expect("tcp", "flow:no_stream; metadata:only_stream;" + content, ADAPT_RULE);
    expect("tcp", "flow:no_stream; metadata:tcp.flags A;" + content, ADAPT_RULE);
    expect("tcp", "msg:\"flow:no_stream; tcp.flags:A;\";" + content, ADAPT_RULE);
    expect("tcp", "flow:no_stream_extra;" + content, ADAPT_RULE);
    expect("tcp", "flow:established,to_server,no_stream;" + content, ADAPT_RULE);
    expect("tcp", content + " flow: no_stream , to_server;", ADAPT_RULE);
    expect("tcp-pkt", content, ADAPT_RULE);
    expect("tcp-stream", content, ADAPT_RULE);
    expect("tcp-stream", "flow:no_stream;" + content, ADAPT_RULE);
    expect("tcp", "flow:only_stream;" + content, ADAPT_RULE);
    expect("tcp", "flow:only_stream,established,to_server;" + content, ADAPT_RULE);
    expect("tcp", content + " flow: established , to_server , only_stream ;", ADAPT_RULE);
    expect("tcp", "flow:established,only_stream,to_client;" + content, ADAPT_RULE);
    expect("tcp-stream", "flow:only_stream;" + content, ADAPT_RULE);
    expect("tcp-pkt", "flow:only_stream;" + content, ADAPT_RULE);
    expect("tcp", "flow:no_stream,only_stream;" + content, ADAPT_RULE);
    for (const string option : {"tcp.flags:A;", "flags:A;", "tcp.seq:1;", "seq:1;",
                               "tcp.ack:1;", "ack:1;", "tcp.window:10;", "window:10;",
                               "ttl:64;", "tos:0;", "id:1;", "fragbits:D;", "fragoffset:0;"}) {
        expect("tcp", "flow:established,to_server;" + option + content, ADAPT_RULE);
        expect("tcp", content + option, ADAPT_RULE);
        expect("tcp", "flow:only_stream;" + option + content, ADAPT_RULE);
    }
    expect("tcp", "tcp.hdr; content:\"|00 50|\"; pkt_data;" + content, ADAPT_RULE);
    expect("tcp", "tcp.hdr; pkt_data;" + content, ADAPT_RULE);
    expect("tcp", "ipv4.hdr; content:\"|45|\"; pkt_data;" + content, ADAPT_RULE);
    expect("tcp", "tcp.hdr; byte_test:1,=,80,3; pkt_data;" + content, ADAPT_RULE);
    expect("tcp", "flow:only_stream; flags:S;", KEEP_RULE);
    expect("tcp-stream", "flags:S;", KEEP_RULE);

    // header-only rules keep their existing behavior, even with only_stream.
    expect("tcp", "flags:S;", KEEP_RULE);
    expect("tcp", "flow:established,to_client; tcp.flags:A;", KEEP_RULE);
    expect("tcp", "flow:established,to_server; flowbits:isset,example;", KEEP_RULE);
    expect("tcp", "tcp.hdr; content:\"|00 50|\"; offset:2; depth:2;", KEEP_RULE);
    expect("tcp", "flow:only_stream; tcp.hdr; content:\"|00 50|\"; offset:2; depth:2;", KEEP_RULE);
    expect("tcp", "tcp.hdr; byte_test:1,=,80,3; flow:only_stream;", KEEP_RULE);
    expect("tcp", "flow:only_stream; tcp.hdr; content:\"|00 50|\"; offset:2; depth:2; pkt_data;" + content, ADAPT_RULE);
    expect("ip", "ipv4.hdr; content:\"|45|\"; offset:0; depth:1;", KEEP_RULE);
    expect("ip", content, ADAPT_RULE);
    expect("icmp", content, ADAPT_RULE);
    expect("udp", content, ADAPT_RULE);
    expect("udp", "flow:stateless,to_server;" + content, ADAPT_RULE);
    expect("udp", "flow:only_stream;" + content, ADAPT_RULE);

    // Checksum fields are intentionally preserved instead of recalculated by
    // the cutter, so rules that validate them must not reach the adapted set.
    for (const string option : {"ipv4-csum:invalid;", "tcpv4-csum:invalid;",
                                "udpv4-csum:invalid;", "tcpv6-csum:invalid;",
                                "udpv6-csum:invalid;"}) {
        expect("ip", option, DISCARD_RULE);
    }

    // The application protocols used by the selected rules are rewritten to
    // TCP when all payload inspection has finite raw windows.
    for (const string protocol : {"http", "ssh", "smb", "HTTP"}) {
        RuleAnalysis application = analyzeRule(rule(protocol, content));
        check(application.action == ADAPT_RULE &&
              application.replacementProtocol == "tcp", protocol + " vira tcp");
        check(adaptRule(rule(protocol, content), application,
                        getCuts(mergeIntervals(application.intervals))) ==
              rule("tcp", "flow:no_stream; content:\"ABACATE\"; offset:0; depth:100;"),
              protocol + " adaptado como tcp");
        expect(protocol, "http.uri;" + content, DISCARD_RULE);
        expect(protocol, "flow:established;", DISCARD_RULE);
        expect(protocol, "flow:only_stream;" + content, DISCARD_RULE);
    }

    RuleAnalysis applicationFlow = analyzeRule(rule(
        "http", "flow:established,to_server;" + content
    ));
    check(adaptRule(rule("http", "flow:established,to_server;" + content),
                    applicationFlow,
                    getCuts(mergeIntervals(applicationFlow.intervals))) ==
          rule("tcp", "flow:established,to_server,no_stream;content:\"ABACATE\"; offset:0; depth:100;"),
          "conversao TCP limita a inspecao ao pacote");
    // Other application headers are outside the selected and validated scope.
    for (const string protocol : {"http1", "http2", "tls", "ssl", "smtp",
                                 "ftp", "ftp-data", "mqtt", "modbus", "pgsql",
                                 "rdp", "rfb", "telnet", "quic", "snmp", "ntp",
                                 "dhcp", "ike", "bittorrent-dht", "dns", "krb5",
                                 "sip", "nfs", "dcerpc", "unknown-application"}) {
        expect(protocol, content, DISCARD_RULE);
    }
    expect("tcp", "msg:\"HTTP application traffic\";" + content, ADAPT_RULE);
    expect("tcp", "app-layer-protocol:http;" + content, DISCARD_RULE);
    expect("tcp", "http.uri;" + content, DISCARD_RULE);

    // existing interval and sticky buffer restrictions are unchanged.
    expect("tcp-pkt", "content:\"ABACATE\";", DISCARD_RULE);
    expect("tcp-pkt", "content:\"ABACATE\"; depth:100;", DISCARD_RULE);
    expect("tcp-pkt", content + " stream_size:client,>,100;", DISCARD_RULE);
    expect("tcp-pkt", "file.data;" + content, DISCARD_RULE);

    string input = rule("tcp", "flow:no_stream;" + content);
    RuleAnalysis packet = analyzeRule(input);
    check(packet.intervals.size() == 1 && packet.intervals[0].start == 100 &&
          packet.intervals[0].end == 199, "janela absoluta 100-199");
    vector<Interval> cuts = getCuts(mergeIntervals(packet.intervals));
    check(adaptRule(input, packet, cuts) ==
          rule("tcp", "flow:no_stream;content:\"ABACATE\"; offset:0; depth:100;"),
          "adaptacao preserva flow e depth e reajusta apenas offset");

    for (const string flow : {"", "flow:no_stream;", "flow:only_stream;",
                              "flow:established,to_server;"}) {
        RuleAnalysis variant = analyzeRule(rule("tcp", flow + content));
        check(variant.action == ADAPT_RULE, "flow nao descarta intervalo do pacote");
        expectIntervals(variant.intervals, {{100, 199}});
    }

    // Flow options do not change packet-based interval calculation.
    RuleAnalysis stream = analyzeRule(rule("tcp", "flow:only_stream; content:\"X\"; offset:0; depth:1000;"));
    check(stream.action == ADAPT_RULE && stream.intervals.size() == 1 &&
          stream.intervals[0].start == 0 && stream.intervals[0].end == 999,
          "flow nao altera o intervalo baseado no pacote");
    vector<Interval> intervals = packet.intervals;
    intervals.insert(intervals.end(), stream.intervals.begin(), stream.intervals.end());
    vector<Interval> merged = mergeIntervals(intervals);
    check(merged.size() == 1 && merged[0].start == 0 && merged[0].end == 999,
          "intervalos TCP sao combinados independentemente de flow");
    expect("tcp", "content:\"X\"; offset:0; depth:1000;", ADAPT_RULE);

    RuleAnalysis relative = analyzeRule(rule("tcp-pkt",
        "content:\"AB\"; offset:8; depth:4; content:\"CD\"; distance:2; within:4;"));
    check(relative.action == ADAPT_RULE && relative.intervals.size() == 1 &&
          relative.intervals[0].start == 8 && relative.intervals[0].end == 17,
          "cadeia relativa continua preservada por pacote");

    expectIntervals(mergeIntervals({{0, 0}}), {{0, 0}});
    expectIntervals(mergeIntervals({{8, 11}, {0, 3}}), {{0, 3}, {8, 11}});
    expectIntervals(mergeIntervals({{2, 6}, {0, 3}, {1, 2}}), {{0, 6}});
    expectIntervals(mergeIntervals({{4, 7}, {0, 3}}), {{0, 7}});
    expectIntervals(mergeIntervals({{LLONG_MAX, LLONG_MAX}, {0, LLONG_MAX}}), {{0, LLONG_MAX}});
    expectIntervals(getCuts({{0, 3}, {8, 11}}), {{4, 7}});
    expectIntervals(getCuts({{2, 3}, {8, 11}}), {{0, 1}, {4, 7}});
    expectIntervals(adjustIntervals({{2, 3}, {8, 11}}, {{0, 1}, {4, 7}}), {{0, 1}, {2, 5}});
    expectIntervals(analyzeRule(rule("udp", "content:\"A\"; offset:0; depth:1;")).intervals, {{0, 0}});
    input = rule("udp", "content:\"AB\"; offset:2; depth:2; content:\"CD\"; offset:8; depth:4;");
    RuleAnalysis two = analyzeRule(input);
    check(adaptRule(input, two, getCuts(mergeIntervals(two.intervals))) ==
          rule("udp", "content:\"AB\"; offset:0; depth:2; content:\"CD\"; offset:2; depth:4;"),
          "offsets no inicio dos dois intervalos");

    // positions after compaction equal the rank of each retained byte.
    vector<Interval> spans = {{1, 4}, {8, 12}};
    vector<Interval> gaps = getCuts(spans);
    for (long long length : {0, 1, 3, 5, 8, 10, 13, 20}) {
        long long rank = 0;
        for (const Interval& span : spans) {
            for (long long pos = span.start; pos <= span.end && pos < length; ++pos) {
                vector<Interval> mapped = adjustIntervals({{pos, pos}}, gaps);
                check(mapped[0].start == rank++, "mapeamento inclusive com payload curto");
            }
        }
        check(rank <= length, "compactacao nao aumenta payload");
    }

    RuleAnalysis negated = analyzeRule(rule("udp",
        "content:\"A\"; offset:100; depth:1; content:!\"B\"; within:1;"
        "content:\"C\"; distance:-50; within:1;"));
    check(negated.action == ADAPT_RULE, "cadeia negada suportada");
    expectIntervals(negated.intervals, {{51, 101}});
    expect("udp", "content:\"A\"; offset:100; depth:1; content:\"C\"; distance:-200; within:1;", DISCARD_RULE);
    expectIntervals(analyzeRule(rule("udp",
        "content:\"A\"; offset:10; depth:1; content:\"C\"; distance:-12; within:3;"
    )).intervals, {{0, 10}});
    expectIntervals(mergeIntervals(analyzeRule(rule("udp",
        "content:!\"A\"; offset:100; depth:1;"
    )).intervals), {{0, 0}, {100, 100}});
    expectIntervals(analyzeRule(rule("udp",
        "content:!\"B\"; offset:100; depth:1; content:\"C\"; distance:10; within:1;"
    )).intervals, {{0, 100}});
    expectIntervals(analyzeRule(rule("udp",
        "content:\"A\"; offset:10; depth:1; content:!\"B\"; offset:100; depth:1;"
        "content:\"C\"; distance:5; within:1;"
    )).intervals, {{10, 10}, {10, 100}});
    expect("udp", "content:\"A\"; offset:9223372036854775807; depth:1;", DISCARD_RULE);
    expect("udp", "content:\"A\"; offset:1; depth:9223372036854775807;", DISCARD_RULE);
    expect("udp", "content:\"A\"; offset:1; depth:1; content:\"B\"; distance:9223372036854775807; within:1;", DISCARD_RULE);
    expect("udp", "content:\"A\"; offset:10oops; depth:1;", DISCARD_RULE);
    expect("udp", "content:\"A\"; offset:1; depth:2.5;", DISCARD_RULE);
    vector<Token> tokens = tokenizeOptions("msg:\"offset:99; flow:only_stream;\"; content:\"|41 42|C\"; offset:2;");
    long long contentLength = 0;
    check(tokens.size() == 3 && tokens[1].key == "content" &&
          parseContentLength(tokens[1], contentLength) && contentLength == 3,
          "separadores entre aspas e tamanho de content misto");
    cout << "OK: intervalos por pacote, flow, headers, protocolos e limites\n";
}
