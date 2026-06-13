#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <regex>
#include <optional>
#include <cctype>
#include <stdexcept>
#include <string>

using namespace std;

struct Interval {
    int start;
    int end;
};

string trim(const string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == string::npos) return "";

    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

// Separa a parte da regra e o comentario iniciado por # fora de aspas.
pair<string, string> splitCodeAndComment(const string& line) {
    bool insideQuotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '"') {
            insideQuotes = !insideQuotes;
        }

        if (line[i] == '#' && !insideQuotes) {
            return {line.substr(0, i), line.substr(i)};
        }
    }

    return {line, ""};
}

optional<int> extractNumberOption(const string& text, const string& optionName) {
    // Aceita: offset 0, offset:0, offset : 0, depth 10, depth:10 etc.
    regex pattern("\\b" + optionName + "\\s*:?\\s*(-?\\d+)");

    smatch match;
    if (regex_search(text, match, pattern)) {
        return stoi(match[1]);
    }

    return nullopt;
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

vector<Interval> extractIntervalsFromRule(const string& rule, int packetSize) {
    vector<Interval> intervals;

    auto [codePart, ignoredComment] = splitCodeAndComment(rule);
    (void) ignoredComment;

    size_t openParen = codePart.find('(');
    size_t closeParen = codePart.rfind(')');

    if (openParen == string::npos || closeParen == string::npos || closeParen <= openParen) {
        return intervals;
    }

    string optionsText = codePart.substr(openParen + 1, closeParen - openParen - 1);

    // Captura content:"...", incluindo escapes simples dentro das aspas.
    regex contentPattern(R"REGEX(content\s*:\s*"((?:\\.|[^"\\])*)")REGEX");

    auto begin = sregex_iterator(optionsText.begin(), optionsText.end(), contentPattern);
    auto end = sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        smatch contentMatch = *it;

        string contentValue = contentMatch[1];
        size_t contentStart = static_cast<size_t>(contentMatch.position());

        // O bloco deste content vai ate o proximo content ou ate o fim da regra.
        size_t nextContent = optionsText.find("content", contentStart + 1);

        string contentBlock;
        if (nextContent == string::npos) {
            contentBlock = optionsText.substr(contentStart);
        } else {
            contentBlock = optionsText.substr(contentStart, nextContent - contentStart);
        }

        auto offset = extractNumberOption(contentBlock, "offset");
        auto depth = extractNumberOption(contentBlock, "depth");

        // Regra sem offset/depth nao gera intervalo absoluto confiavel.
        if (!offset.has_value() && !depth.has_value()) {
            continue;
        }

        int start = offset.value_or(0);
        int endByte;

        if (depth.has_value()) {
            // Janela de busca definida pelo Snort: offset ate offset + depth - 1.
            endByte = start + depth.value() - 1;
        } else {
            // Caso comum no arquivo enviado: offset sem depth.
            // Aqui consideramos o intervalo ocupado pelo proprio content.
            int contentLength = getContentLength(contentValue);
            endByte = start + contentLength - 1;
        }

        if (start < 0) start = 0;
        if (endByte >= packetSize) endByte = packetSize - 1;

        if (start <= endByte) {
            intervals.push_back({start, endByte});
        }
    }

    return intervals;
}

vector<Interval> readIntervalsFromSnortFile(const string& filename, int packetSize) {
    ifstream file(filename);

    if (!file.is_open()) {
        throw runtime_error("Erro ao abrir o arquivo: " + filename);
    }

    vector<Interval> intervals;
    string line;

    while (getline(file, line)) {
        string codePart = trim(splitCodeAndComment(line).first);

        if (codePart.empty()) {
            continue;
        }

        vector<Interval> ruleIntervals = extractIntervalsFromRule(line, packetSize);

        intervals.insert(intervals.end(), ruleIntervals.begin(), ruleIntervals.end());
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

vector<Interval> getCutRanges(const vector<Interval>& intervals, int packetSize) {
    vector<Interval> cuts;

    if (packetSize <= 0) {
        return cuts;
    }

    if (intervals.empty()) {
        cuts.push_back({0, packetSize - 1});
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

    if (intervals.back().end < packetSize - 1) {
        cuts.push_back({intervals.back().end + 1, packetSize - 1});
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

// Substitui todos os offsets de um bloco de content pelo offset novo.
// Mantem a formatacao original ao maximo: offset 5, offset:5, offset : 5 etc.
string replaceOffsetsInContentBlock(const string& block, const vector<Interval>& cuts) {
    regex offsetPattern(R"REGEX((\boffset\s*:?\s*)(-?\d+))REGEX");

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

    regex contentPattern(R"REGEX(content\s*:\s*"((?:\\.|[^"\\])*)")REGEX");

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

void writeAdaptedRulesFile(
    const string& inputFilename,
    const string& outputFilename,
    const vector<Interval>& cuts
) {
    vector<string> lines = readAllLines(inputFilename);
    ofstream output(outputFilename);

    if (!output.is_open()) {
        throw runtime_error("Erro ao criar o arquivo de saida: " + outputFilename);
    }

    //output << "# Arquivo gerado automaticamente a partir de: " << inputFilename << "\n";
    //output << "# Offsets ajustados apos remocao dos intervalos cortados do payload.\n";
    //output << "# Atencao: regras sem offset absoluto foram mantidas como estavam.\n\n";

    for (const string& line : lines) {
        output << adaptRuleLine(line, cuts) << "\n";
    }
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
    cout << programName << " regras.rules tamanho_pacote saida.rules\n\n";
    cout << "Exemplo:\n";
    cout << programName << " original-pcap.rules 100 regras-adaptadas.rules\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printUsage(argv[0]);
        return 1;
    }

    string inputFilename = argv[1];
    int packetSize = stoi(argv[2]);
    string outputFilename = argv[3];

    if (packetSize <= 0) {
        cerr << "Erro: tamanho_pacote precisa ser maior que zero.\n";
        return 1;
    }

    try {
        vector<Interval> intervals = readIntervalsFromSnortFile(inputFilename, packetSize);

        auto noContained = removeContained(intervals);
        auto merged = mergeIntervals(noContained);
        auto cuts = getCutRanges(merged, packetSize);
        auto adjusted = adjustIntervals(merged, cuts);

        writeAdaptedRulesFile(inputFilename, outputFilename, cuts);

        cout << "Intervals from Snort rules:\n";
        printIntervals(intervals);

        cout << "\nMerged:\n";
        printIntervals(merged);

        cout << "\nCuts:\n";
        printIntervals(cuts);

        cout << "\nAdjusted:\n";
        printIntervals(adjusted);

        cout << "\nArquivo de regras adaptado gerado em:\n";
        cout << outputFilename << "\n";
    } catch (const exception& e) {
        cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}