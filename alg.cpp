#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <regex>
#include <optional>
#include <cctype>
#include <stdexcept>
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

struct Interval {
    int start;
    int end;
};

enum class RuleAction {
    KEEP_HEADER,
    KEEP_PAYLOAD,
    EXCLUDE,
    NON_RULE
};

struct RuleDecision {
    RuleAction action;
    string reason;
};

struct Stats {
    int totalRules = 0;
    int keptHeader = 0;
    int keptPayload = 0;
    int excluded = 0;
    int nonRules = 0;
};

string trim(const string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == string::npos) return "";

    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

string csvEscape(const string& value) {
    string out = "\"";

    for (char c : value) {
        if (c == '"') {
            out += "\"\"";
        } else {
            out += c;
        }
    }

    out += "\"";
    return out;
}

// Separa a parte da regra e o comentario iniciado por # fora de aspas.
pair<string, string> splitCodeAndComment(const string& line) {
    bool insideQuotes = false;
    bool escaped = false;

    for (size_t i = 0; i < line.size(); ++i) {
        if (escaped) {
            escaped = false;
            continue;
        }

        if (line[i] == '\\') {
            escaped = true;
            continue;
        }

        if (line[i] == '"') {
            insideQuotes = !insideQuotes;
        }

        if (line[i] == '#' && !insideQuotes) {
            return {line.substr(0, i), line.substr(i)};
        }
    }

    return {line, ""};
}

bool isRuleLine(const string& line) {
    static const regex rulePattern(R"REGEX(^\s*(alert|log|pass|drop|reject|sdrop)\b)REGEX",
                                   regex_constants::icase);
    return regex_search(line, rulePattern);
}

string extractSid(const string& rule) {
    regex sidPattern(R"REGEX(\bsid\s*:?\s*(\d+))REGEX", regex_constants::icase);
    smatch match;

    if (regex_search(rule, match, sidPattern)) {
        return match[1];
    }

    return "";
}

optional<int> extractNumberOption(const string& text, const string& optionName) {
    // Aceita: offset 0, offset:0, offset : 0, depth 10, depth:10 etc.
    regex pattern("\\b" + optionName + "\\s*:?\\s*(-?\\d+)",
                  regex_constants::icase);

    smatch match;
    if (regex_search(text, match, pattern)) {
        return stoi(match[1]);
    }

    return nullopt;
}

bool hasRegex(const string& text, const string& pattern) {
    return regex_search(text, regex(pattern, regex_constants::icase));
}

string joinReasons(const vector<string>& items) {
    string result;

    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) result += "|";
        result += items[i];
    }

    return result;
}

int getContentLength(const string& content) {
    int length = 0;

    for (size_t i = 0; i < content.size();) {
        if (content[i] == '|') {
            size_t endPipe = content.find('|', i + 1);

            if (endPipe == string::npos) {
                length++;
                i++;
                continue;
            }

            string hexPart = content.substr(i + 1, endPipe - i - 1);

            string cleanHex;
            for (char c : hexPart) {
                if (!isspace(static_cast<unsigned char>(c))) {
                    cleanHex += c;
                }
            }

            // Cada par hexadecimal representa 1 byte.
            length += static_cast<int>(cleanHex.size()) / 2;
            i = endPipe + 1;
        } else if (content[i] == '\\' && i + 1 < content.size()) {
            // Trata escapes dentro da string, por exemplo \" ou \\.
            length++;
            i += 2;
        } else {
            length++;
            i++;
        }
    }

    return length;
}

string getOptionsText(const string& rule) {
    auto [codePart, ignoredComment] = splitCodeAndComment(rule);
    (void) ignoredComment;

    size_t openParen = codePart.find('(');
    size_t closeParen = codePart.rfind(')');

    if (openParen == string::npos || closeParen == string::npos || closeParen <= openParen) {
        return "";
    }

    return codePart.substr(openParen + 1, closeParen - openParen - 1);
}

vector<pair<size_t, size_t>> getContentBlockRanges(const string& optionsText) {
    vector<pair<size_t, size_t>> ranges;

    // Captura content:"..." e content:!"...", incluindo escapes simples dentro das aspas.
    regex contentPattern(R"REGEX(\bcontent\s*:\s*!?\s*"((?:\\.|[^"\\])*)")REGEX",
                         regex_constants::icase);

    vector<size_t> starts;

    auto begin = sregex_iterator(optionsText.begin(), optionsText.end(), contentPattern);
    auto end = sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        starts.push_back(static_cast<size_t>((*it).position()));
    }

    for (size_t i = 0; i < starts.size(); ++i) {
        size_t blockEnd = (i + 1 < starts.size()) ? starts[i + 1] : optionsText.size();
        ranges.push_back({starts[i], blockEnd});
    }

    return ranges;
}

bool hasContent(const string& optionsText) {
    return hasRegex(optionsText, R"REGEX(\bcontent\s*:\s*!?\s*")REGEX");
}

vector<string> unsupportedPayloadOptions(const string& optionsText) {
    vector<string> unsupported;

    // Opcoes que a implementacao atual ainda nao adapta com seguranca.
    // Elas podem depender de posicoes relativas, buffers normalizados,
    // tamanho do payload ou operacoes de leitura dinamica.
    vector<string> names = {
        "distance",
        "within",
        "pcre",
        "byte_test",
        "byte_jump",
        "byte_extract",
        "byte_math",
        "isdataat",
        "dsize",
        "stream_size",
        "file_data",
        "http_uri",
        "http_raw_uri",
        "http_header",
        "http_raw_header",
        "http_client_body",
        "http_cookie",
        "http_method",
        "http_stat_code",
        "http_stat_msg",
        "http_param",
        "http_true_ip",
        "base64_decode",
        "base64_data",
        "js_data",
        "vba_data",
        "pkt_data",
        "raw_data"
    };

    for (const string& name : names) {
        regex pattern("\\b" + name + "\\b", regex_constants::icase);
        if (regex_search(optionsText, pattern)) {
            unsupported.push_back(name);
        }
    }

    return unsupported;
}

bool allContentBlocksArePositioned(const string& optionsText, string& reason) {
    auto ranges = getContentBlockRanges(optionsText);

    if (ranges.empty()) {
        reason = "sem_content";
        return false;
    }

    for (const auto& range : ranges) {
        string block = optionsText.substr(range.first, range.second - range.first);

        auto offset = extractNumberOption(block, "offset");
        auto depth = extractNumberOption(block, "depth");

        if (!offset.has_value() && !depth.has_value()) {
            reason = "content_sem_offset_ou_depth";
            return false;
        }
    }

    reason = "todos_contents_posicionados";
    return true;
}

RuleDecision classifyRule(const string& line) {
    auto [codePartRaw, commentPart] = splitCodeAndComment(line);
    (void) commentPart;

    string codePart = trim(codePartRaw);

    if (codePart.empty() || !isRuleLine(codePart)) {
        return {RuleAction::NON_RULE, "nao_e_regra_ativa"};
    }

    string optionsText = getOptionsText(codePart);

    if (optionsText.empty()) {
        return {RuleAction::EXCLUDE, "regra_sem_bloco_de_opcoes"};
    }

    bool contentPresent = hasContent(optionsText);
    vector<string> unsupported = unsupportedPayloadOptions(optionsText);

    if (!contentPresent) {
        if (unsupported.empty()) {
            return {RuleAction::KEEP_HEADER, "regra_de_cabecalho_ou_comportamento_sem_payload"};
        }

        return {RuleAction::EXCLUDE, "sem_content_mas_com_opcao_payload_nao_tratada:" + joinReasons(unsupported)};
    }

    if (!unsupported.empty()) {
        return {RuleAction::EXCLUDE, "content_com_opcao_nao_tratada:" + joinReasons(unsupported)};
    }

    string positionedReason;
    if (!allContentBlocksArePositioned(optionsText, positionedReason)) {
        return {RuleAction::EXCLUDE, positionedReason};
    }

    return {RuleAction::KEEP_PAYLOAD, "payload_tratado_por_offset_ou_depth"};
}

vector<Interval> extractIntervalsFromRule(const string& rule, int payloadSize) {
    vector<Interval> intervals;

    string optionsText = getOptionsText(rule);

    if (optionsText.empty()) {
        return intervals;
    }

    regex contentPattern(R"REGEX(\bcontent\s*:\s*!?\s*"((?:\\.|[^"\\])*)")REGEX",
                         regex_constants::icase);

    auto begin = sregex_iterator(optionsText.begin(), optionsText.end(), contentPattern);
    auto end = sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        smatch contentMatch = *it;

        string contentValue = contentMatch[1];
        (void) contentValue;
        size_t contentStart = static_cast<size_t>(contentMatch.position());

        size_t nextContent;
        auto nextIt = it;
        ++nextIt;

        if (nextIt != end) {
            nextContent = static_cast<size_t>((*nextIt).position());
        } else {
            nextContent = optionsText.size();
        }

        string contentBlock = optionsText.substr(contentStart, nextContent - contentStart);

        auto offset = extractNumberOption(contentBlock, "offset");
        auto depth = extractNumberOption(contentBlock, "depth");

        if (!offset.has_value() && !depth.has_value()) {
            continue;
        }

        int start = offset.value_or(0);
        int endByte;

        if (depth.has_value()) {
            // content + depth:
            // - sem offset: janela do inicio do payload ate depth - 1
            // - com offset: janela de offset ate offset + depth - 1
            endByte = start + depth.value() - 1;
        } else {
            // content + offset sem depth:
            // criterio conservador: a busca pode seguir do offset ate o fim do payload.
            endByte = payloadSize - 1;
        }

        if (start < 0) start = 0;
        if (endByte >= payloadSize) endByte = payloadSize - 1;

        if (start <= endByte) {
            intervals.push_back({start, endByte});
        }
    }

    return intervals;
}

vector<string> readAllLines(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        throw runtime_error("Erro ao abrir o arquivo: " + filename);
    }

    vector<string> lines;
    string line;

    while (getline(file, line)) {
        lines.push_back(line);
    }

    return lines;
}

vector<Interval> readIntervalsFromSupportedRules(
    const vector<string>& lines,
    int payloadSize
) {
    vector<Interval> intervals;

    for (const string& line : lines) {
        RuleDecision decision = classifyRule(line);

        if (decision.action != RuleAction::KEEP_PAYLOAD) {
            continue;
        }

        vector<Interval> ruleIntervals = extractIntervalsFromRule(line, payloadSize);

        intervals.insert(intervals.end(), ruleIntervals.begin(), ruleIntervals.end());
    }

    return intervals;
}

vector<Interval> removeContained(vector<Interval> intervals) {
    sort(intervals.begin(), intervals.end(),
        [](const Interval& a, const Interval& b) {
            if (a.start == b.start)
                return a.end > b.end;
            return a.start < b.start;
        });

    vector<Interval> result;

    for (const auto& current : intervals) {
        if (result.empty()) {
            result.push_back(current);
            continue;
        }

        const auto& last = result.back();

        if (current.start >= last.start && current.end <= last.end) {
            continue;
        }

        result.push_back(current);
    }

    return result;
}

vector<Interval> mergeIntervals(vector<Interval> intervals) {
    if (intervals.empty()) {
        return {};
    }

    sort(intervals.begin(), intervals.end(),
        [](const Interval& a, const Interval& b) {
            if (a.start == b.start)
                return a.end < b.end;
            return a.start < b.start;
        });

    vector<Interval> result;
    result.push_back(intervals[0]);

    for (size_t i = 1; i < intervals.size(); ++i) {
        auto& last = result.back();
        const auto& current = intervals[i];

        // Usa <= para unir intervalos sobrepostos.
        // Troque para current.start <= last.end + 1 se quiser juntar tambem os adjacentes.
        if (current.start <= last.end) {
            last.end = max(last.end, current.end);
        } else {
            result.push_back(current);
        }
    }

    return result;
}

vector<Interval> getCutRanges(const vector<Interval>& intervals, int payloadSize) {
    vector<Interval> cuts;

    if (payloadSize <= 0) {
        return cuts;
    }

    if (intervals.empty()) {
        cuts.push_back({0, payloadSize - 1});
        return cuts;
    }

    if (intervals[0].start > 0) {
        cuts.push_back({0, intervals[0].start - 1});
    }

    for (size_t i = 0; i + 1 < intervals.size(); ++i) {
        int start = intervals[i].end + 1;
        int end = intervals[i + 1].start - 1;

        if (start <= end) {
            cuts.push_back({start, end});
        }
    }

    if (intervals.back().end < payloadSize - 1) {
        cuts.push_back({intervals.back().end + 1, payloadSize - 1});
    }

    return cuts;
}

int removedBeforePosition(int position, const vector<Interval>& cuts) {
    int removed = 0;

    for (const auto& cut : cuts) {
        int cutSize = cut.end - cut.start + 1;

        if (cut.end < position) {
            removed += cutSize;
        }
    }

    return removed;
}

int adjustPosition(int originalPosition, const vector<Interval>& cuts) {
    return originalPosition - removedBeforePosition(originalPosition, cuts);
}

vector<Interval> adjustIntervals(const vector<Interval>& merged, const vector<Interval>& cuts) {
    vector<Interval> adjusted;

    for (const auto& interval : merged) {
        int newStart = adjustPosition(interval.start, cuts);
        int newEnd = adjustPosition(interval.end, cuts);

        adjusted.push_back({newStart, newEnd});
    }

    return adjusted;
}

int totalIntervalBytes(const vector<Interval>& intervals) {
    int total = 0;

    for (const auto& interval : intervals) {
        if (interval.start <= interval.end) {
            total += interval.end - interval.start + 1;
        }
    }

    return total;
}

int remainingPayloadBytesFromMerged(const vector<Interval>& merged) {
    // Os intervalos merged representam exatamente os bytes do payload
    // que precisam ser preservados para as regras suportadas.
    return totalIntervalBytes(merged);
}

double percentage(int part, int total) {
    if (total <= 0) {
        return 0.0;
    }

    return 100.0 * static_cast<double>(part) / static_cast<double>(total);
}

int lastPayloadByteAfterAdjustment(const vector<Interval>& adjusted) {
    if (adjusted.empty()) {
        return -1;
    }

    int last = -1;
    for (const auto& interval : adjusted) {
        last = max(last, interval.end);
    }

    return last;
}

// Substitui todos os offsets de um bloco de content pelo offset novo.
// Mantem a formatacao original ao maximo: offset 5, offset:5, offset : 5 etc.
string replaceOffsetsInContentBlock(const string& block, const vector<Interval>& cuts) {
    regex offsetPattern(R"REGEX((\boffset\s*:?\s*)(-?\d+))REGEX",
                        regex_constants::icase);

    string result;
    size_t lastPos = 0;

    auto begin = sregex_iterator(block.begin(), block.end(), offsetPattern);
    auto end = sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        smatch match = *it;

        size_t matchPos = static_cast<size_t>(match.position());
        size_t matchLen = static_cast<size_t>(match.length());

        string prefix = match[1];
        int oldOffset = stoi(match[2]);
        int newOffset = adjustPosition(oldOffset, cuts);

        if (newOffset < 0) {
            newOffset = 0;
        }

        result += block.substr(lastPos, matchPos - lastPos);
        result += prefix;
        result += to_string(newOffset);

        lastPos = matchPos + matchLen;
    }

    result += block.substr(lastPos);
    return result;
}

string adaptRuleLine(const string& line, const vector<Interval>& cuts) {
    auto [codePart, commentPart] = splitCodeAndComment(line);

    size_t openParen = codePart.find('(');
    size_t closeParen = codePart.rfind(')');

    if (openParen == string::npos || closeParen == string::npos || closeParen <= openParen) {
        return line;
    }

    string beforeOptions = codePart.substr(0, openParen + 1);
    string optionsText = codePart.substr(openParen + 1, closeParen - openParen - 1);
    string afterOptions = codePart.substr(closeParen);

    regex contentPattern(R"REGEX(\bcontent\s*:\s*!?\s*"((?:\\.|[^"\\])*)")REGEX",
                         regex_constants::icase);

    string adaptedOptions;
    size_t cursor = 0;

    auto begin = sregex_iterator(optionsText.begin(), optionsText.end(), contentPattern);
    auto end = sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        smatch match = *it;
        size_t contentStart = static_cast<size_t>(match.position());

        // Copia tudo antes deste content sem alterar.
        adaptedOptions += optionsText.substr(cursor, contentStart - cursor);

        size_t nextContent;
        auto nextIt = it;
        ++nextIt;

        if (nextIt != end) {
            nextContent = static_cast<size_t>((*nextIt).position());
        } else {
            nextContent = optionsText.size();
        }

        string contentBlock = optionsText.substr(contentStart, nextContent - contentStart);
        adaptedOptions += replaceOffsetsInContentBlock(contentBlock, cuts);

        cursor = nextContent;
    }

    adaptedOptions += optionsText.substr(cursor);

    return beforeOptions + adaptedOptions + afterOptions + commentPart;
}

void writeExcludedReportHeader(ofstream& report) {
    report << "line,sid,reason,rule\n";
}

void writeExcludedReportRow(
    ofstream& report,
    int lineNumber,
    const string& line,
    const string& reason
) {
    string sid = extractSid(line);

    report << lineNumber << ",";
    report << csvEscape(sid) << ",";
    report << csvEscape(reason) << ",";
    report << csvEscape(trim(line)) << "\n";
}

Stats writeAdaptedRulesFile(
    const string& inputFilename,
    const string& outputFilename,
    const string& excludedReportFilename,
    const vector<Interval>& cuts
) {
    vector<string> lines = readAllLines(inputFilename);
    ofstream output(outputFilename);
    ofstream excludedReport(excludedReportFilename);

    if (!output.is_open()) {
        throw runtime_error("Erro ao criar o arquivo de saida: " + outputFilename);
    }

    if (!excludedReport.is_open()) {
        throw runtime_error("Erro ao criar o relatorio de excluidas: " + excludedReportFilename);
    }

    writeExcludedReportHeader(excludedReport);

    Stats stats;

    for (size_t i = 0; i < lines.size(); ++i) {
        const string& line = lines[i];
        RuleDecision decision = classifyRule(line);

        switch (decision.action) {
            case RuleAction::NON_RULE:
                stats.nonRules++;
                // Mantem comentarios e linhas em branco para preservar contexto do arquivo.
                output << line << "\n";
                break;

            case RuleAction::KEEP_HEADER:
                stats.totalRules++;
                stats.keptHeader++;
                // Regras de cabecalho/comportamento sao mantidas sem alteracao,
                // pois o MicroSec Traffic nao remove cabecalhos.
                output << line << "\n";
                break;

            case RuleAction::KEEP_PAYLOAD:
                stats.totalRules++;
                stats.keptPayload++;
                output << adaptRuleLine(line, cuts) << "\n";
                break;

            case RuleAction::EXCLUDE:
                stats.totalRules++;
                stats.excluded++;
                writeExcludedReportRow(excludedReport, static_cast<int>(i + 1), line, decision.reason);
                break;
        }
    }

    return stats;
}

void printIntervals(const vector<Interval>& intervals) {
    if (intervals.empty()) {
        cout << "(nenhum)\n";
        return;
    }

    for (const auto& i : intervals) {
        cout << i.start << "-" << i.end << "\n";
    }
}

void printUsage(const char* programName) {
    cout << "Uso:\n";
    cout << programName << " regras.rules tamanho_payload saida.rules [relatorio_excluidas.csv]\n\n";
    cout << "Exemplo:\n";
    cout << programName << " regras.rules 1500 regras-adaptadas.rules regras-excluidas.csv\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printUsage(argv[0]);
        return 1;
    }

    string inputFilename = argv[1];
    int payloadSize = 0;
    string outputFilename = argv[3];
    string excludedReportFilename;

    try {
        size_t parsedChars = 0;
        payloadSize = stoi(argv[2], &parsedChars);

        if (parsedChars != string(argv[2]).size()) {
            throw invalid_argument("caracteres extras");
        }
    } catch (const exception&) {
        cerr << "Erro: tamanho_payload deve ser um numero inteiro valido.\n";
        return 1;
    }

    if (argc >= 5) {
        excludedReportFilename = argv[4];
    } else {
        excludedReportFilename = outputFilename + ".excluded.csv";
    }

    if (payloadSize <= 0) {
        cerr << "Erro: tamanho_payload precisa ser maior que zero.\n";
        return 1;
    }

    try {
        vector<string> lines = readAllLines(inputFilename);
        vector<Interval> intervals = readIntervalsFromSupportedRules(lines, payloadSize);

        auto noContained = removeContained(intervals);
        auto merged = mergeIntervals(noContained);
        auto cuts = getCutRanges(merged, payloadSize);
        auto adjusted = adjustIntervals(merged, cuts);

        Stats stats = writeAdaptedRulesFile(inputFilename, outputFilename, excludedReportFilename, cuts);

        cout << "Intervals from supported Snort rules:\n";
        printIntervals(intervals);

        cout << "\nMerged:\n";
        printIntervals(merged);

        cout << "\nCuts:\n";
        printIntervals(cuts);

        cout << "\nAdjusted:\n";
        printIntervals(adjusted);

        // Metrica principal: soma dos intervalos que precisam ser preservados.
        int remainingPayloadBytes = remainingPayloadBytesFromMerged(merged);
        int removedPayloadBytes = payloadSize - remainingPayloadBytes;
        int lastPayloadByte = lastPayloadByteAfterAdjustment(adjusted);

        if (removedPayloadBytes < 0) {
            removedPayloadBytes = 0;
        }

        double payloadReduction = percentage(removedPayloadBytes, payloadSize);

        // Como os intervalos sao compactados apos os cortes, quando ha payload
        // preservado o maior indice reajustado + 1 deve ser igual ao total de bytes.
        bool payloadSizeConsistent =
            (remainingPayloadBytes == 0 && lastPayloadByte == -1) ||
            (remainingPayloadBytes > 0 && lastPayloadByte + 1 == remainingPayloadBytes);

        cout << fixed << setprecision(2);

        cout << "\nResumo do payload apos cortes:\n";
        cout << "Tamanho original do payload considerado: " << payloadSize << " bytes\n";
        cout << "Bytes preservados do payload: " << remainingPayloadBytes << " bytes\n";
        cout << "Bytes removidos do payload: " << removedPayloadBytes << " bytes\n";
        cout << "Reducao do payload: " << payloadReduction << "%\n";

        if (lastPayloadByte >= 0) {
            cout << "Maior indice de byte no payload reajustado: " << lastPayloadByte << "\n";
        } else {
            cout << "Maior indice de byte no payload reajustado: nenhum payload preservado\n";
        }

        cout << "Verificacao tamanho x maior indice: "
             << (payloadSizeConsistent ? "OK" : "INCONSISTENTE") << "\n";

        int supportedRules = stats.keptHeader + stats.keptPayload;
        double supportedPercentage = percentage(supportedRules, stats.totalRules);
        double excludedPercentage = percentage(stats.excluded, stats.totalRules);

        cout << "\nResumo das regras:\n";
        cout << "Regras analisadas: " << stats.totalRules << "\n";
        cout << "Mantidas sem alteracao (independentes do payload): " << stats.keptHeader << "\n";
        cout << "Adaptadas (payload tratado por offset/depth): " << stats.keptPayload << "\n";
        cout << "Excluidas (nao tratadas): " << stats.excluded << "\n";
        cout << "Regras suportadas: " << supportedRules << " (" << supportedPercentage << "%)\n";
        cout << "Taxa de descarte: " << excludedPercentage << "%\n";

        cout << "\nArquivo de regras adaptado gerado em:\n";
        cout << outputFilename << "\n";

        cout << "\nRelatorio de regras excluidas gerado em:\n";
        cout << excludedReportFilename << "\n";
    } catch (const exception& e) {
        cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}