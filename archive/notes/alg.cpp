#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <regex>
#include <map>
#include <cctype>
#include <climits>

using namespace std;

// data structures

struct Interval {
    long long start;
    long long end;
};

struct Token {
    size_t start;
    size_t end;
    string text;
    string key;
};

enum BufferKind {
    RAW_PAYLOAD,
    PACKET_HEADER
};

enum RuleAction {
    KEEP_RULE,
    ADAPT_RULE,
    DISCARD_RULE,
    NON_RULE
};

struct ContentInfo {
    BufferKind buffer;
    bool hasOffset;
    bool hasDepth;
    bool hasDistance;
    bool hasWithin;
    long long offset;
    long long depth;
    long long distance;
    long long within;
    long long contentLength;
    size_t offsetTokenIndex;

    ContentInfo()
        : buffer(RAW_PAYLOAD), hasOffset(false), hasDepth(false),
          hasDistance(false), hasWithin(false), offset(0), depth(0),
          distance(0), within(0), contentLength(0),
          offsetTokenIndex((size_t)-1) {}
};

struct SearchState {
    long long minStart;
    long long maxEnd;
    long long contentLength;
};

struct ChainState {
    Interval envelope;
    SearchState previous;
};

struct RuleAnalysis {
    RuleAction action;
    vector<Interval> intervals;
    vector<size_t> offsetTokens;

    RuleAnalysis() : action(DISCARD_RULE) {}
};

struct Stats {
    long long analyzed;
    long long keptUnchanged;
    long long adapted;
    long long discarded;

    Stats()
        : analyzed(0), keptUnchanged(0),
          adapted(0), discarded(0) {}
};

struct PipelineData {
    vector<string> lines;
    vector<RuleAnalysis> analyses;
    vector<Interval> intervals;
    vector<Interval> merged;
    vector<Interval> cuts;
    Stats stats;
};

// parsing

static string trim(const string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

static string lowerCopy(string s) {
    for (size_t i = 0; i < s.size(); ++i) {
        s[i] = (char)tolower((unsigned char)s[i]);
    }
    return s;
}

static bool startsWithText(const string& s, const string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static bool isCommentOrBlank(const string& line) {
    string t = trim(line);
    return t.empty() || t[0] == '#';
}

static bool isRuleLine(const string& line) {
    static const regex pattern(
        "^\\s*(alert|log|pass|drop|reject|sdrop)\\b",
        regex_constants::icase
    );
    return regex_search(line, pattern);
}

static string getRuleProtocol(const string& rule) {
    static const regex pattern(
        "^\\s*(?:alert|log|pass|drop|reject|sdrop)\\s+([^\\s]+)",
        regex_constants::icase
    );

    smatch match;
    if (!regex_search(rule, match, pattern)) return "";
    return lowerCopy(match[1]);
}

static bool getOptionsBounds(const string& rule, size_t& openPos, size_t& closePos) {
    openPos = rule.find('(');
    closePos = rule.rfind(')');
    return openPos != string::npos && closePos != string::npos && closePos > openPos;
}

static string optionKey(const string& text) {
    string t = trim(text);
    size_t i = 0;

    while (i < t.size()) {
        char c = t[i];
        if (isalnum((unsigned char)c) || c == '_' || c == '.' || c == '-') {
            ++i;
        } else {
            break;
        }
    }

    return lowerCopy(t.substr(0, i));
}

static vector<Token> tokenizeOptions(const string& options) {
    vector<Token> tokens;
    bool quoted = false;
    bool escaped = false;
    size_t start = 0;

    for (size_t i = 0; i < options.size(); ++i) {
        char c = options[i];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (c == '\\') {
            escaped = true;
            continue;
        }

        if (c == '"') {
            quoted = !quoted;
            continue;
        }

        if (c == ';' && !quoted) {
            string text = options.substr(start, i - start);
            if (!trim(text).empty()) {
                Token token;
                token.start = start;
                token.end = i;
                token.text = text;
                token.key = optionKey(text);
                tokens.push_back(token);
            }
            start = i + 1;
        }
    }

    if (start < options.size()) {
        string text = options.substr(start);
        if (!trim(text).empty()) {
            Token token;
            token.start = start;
            token.end = options.size();
            token.text = text;
            token.key = optionKey(text);
            tokens.push_back(token);
        }
    }

    return tokens;
}

static bool parseIntegerOption(const Token& token, const string& name, long long& value) {
    regex pattern("\\b" + name + "\\s*:\\s*(-?\\d+)", regex_constants::icase);
    smatch match;

    if (!regex_search(token.text, match, pattern)) return false;

    try {
        value = stoll(match[1]);
    } catch (...) {
        return false;
    }

    return true;
}

static long long encodedContentLength(const string& value) {
    long long length = 0;

    for (size_t i = 0; i < value.size();) {
        if (value[i] == '|') {
            size_t end = value.find('|', i + 1);

            if (end == string::npos) {
                ++length;
                ++i;
                continue;
            }

            string hex = value.substr(i + 1, end - i - 1);
            string clean;

            for (size_t j = 0; j < hex.size(); ++j) {
                if (!isspace((unsigned char)hex[j])) clean += hex[j];
            }

            length += (long long)clean.size() / 2;
            i = end + 1;
        } else if (value[i] == '\\' && i + 1 < value.size()) {
            ++length;
            i += 2;
        } else {
            ++length;
            ++i;
        }
    }

    return length;
}

static bool parseContentLength(const Token& token, long long& length) {
    size_t first = token.text.find('"');
    if (first == string::npos) return false;

    bool escaped = false;

    for (size_t i = first + 1; i < token.text.size(); ++i) {
        char c = token.text[i];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (c == '\\') {
            escaped = true;
            continue;
        }

        if (c == '"') {
            length = encodedContentLength(token.text.substr(first + 1, i - first - 1));
            return true;
        }
    }

    return false;
}

// scope checks

static bool isNetworkTransportProtocol(const string& protocol) {
    return protocol == "ip" || protocol == "tcp" || protocol == "udp" ||
           protocol == "icmp" || protocol == "icmpv6" || protocol == "ipv6" ||
           protocol == "sctp" || protocol == "tcp-pkt" || protocol == "pkthdr";
}

static bool isHeaderBuffer(const string& key) {
    return key == "tcp.hdr" || key == "udp.hdr" ||
           key == "ipv4.hdr" || key == "ipv6.hdr" ||
           key == "icmpv4.hdr" || key == "icmpv6.hdr";
}

static bool isRawPayloadBuffer(const string& key) {
    return key == "pkt_data" || key == "raw_data";
}

static bool isApplicationBuffer(const string& key) {
    const char* prefixes[] = {
        "http.", "dns.", "tls.", "ssl.", "ssh.", "smtp.", "ftp.",
        "smb.", "dcerpc.", "krb5.", "mqtt.", "modbus.", "pgsql.",
        "rdp.", "snmp.", "sip.", "rfb.", "nfs.", "ike.", "quic."
    };

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        if (startsWithText(key, prefixes[i])) return true;
    }

    return key == "file.data" || key == "file_data" ||
           key == "base64_data" || key == "js_data" || key == "vba_data" ||
           key == "http_uri" || key == "http_raw_uri" ||
           key == "http_header" || key == "http_raw_header" ||
           key == "http_client_body" || key == "http_cookie" ||
           key == "http_method" || key == "http_stat_code" ||
           key == "http_stat_msg" || key == "uricontent";
}

static bool isUnsupportedPayloadOperation(const string& key) {
    return key == "pcre" || key == "byte_test" || key == "byte_jump" ||
           key == "byte_extract" || key == "byte_math" || key == "isdataat" ||
           key == "asn1" || key == "rpc";
}

static bool isUnsupportedSemantic(const string& key) {
    return key == "dsize" || key == "stream_size" || key == "stream-event" ||
           key == "app-layer-event" || key == "app-layer-protocol";
}

// algorithm logic

static bool safeAdd(long long a, long long b, long long& out) {
    if ((b > 0 && a > LLONG_MAX - b) ||
        (b < 0 && a < LLONG_MIN - b)) {
        return false;
    }

    out = a + b;
    return true;
}

static RuleAnalysis analyzeRule(const string& line) {
    RuleAnalysis result;

    if (isCommentOrBlank(line) || !isRuleLine(line)) {
        result.action = NON_RULE;
        return result;
    }

    size_t openPos;
    size_t closePos;

    if (!getOptionsBounds(line, openPos, closePos)) {
        return result;
    }

    if (!isNetworkTransportProtocol(getRuleProtocol(line))) {
        return result;
    }

    string options = line.substr(openPos + 1, closePos - openPos - 1);
    vector<Token> tokens = tokenizeOptions(options);
    vector<ContentInfo> contents;
    BufferKind currentBuffer = RAW_PAYLOAD;
    long long currentContent = -1;

    // collect content constraints and reject unsupported options
    for (size_t i = 0; i < tokens.size(); ++i) {
        const string& key = tokens[i].key;

        if (isHeaderBuffer(key)) {
            currentBuffer = PACKET_HEADER;
            currentContent = -1;
            continue;
        }

        if (isRawPayloadBuffer(key)) {
            currentBuffer = RAW_PAYLOAD;
            currentContent = -1;
            continue;
        }

        if (isApplicationBuffer(key) || isUnsupportedSemantic(key)) {
            return result;
        }

        if (key == "content") {
            ContentInfo content;
            content.buffer = currentBuffer;

            if (!parseContentLength(tokens[i], content.contentLength) ||
                content.contentLength <= 0) {
                return result;
            }

            contents.push_back(content);
            currentContent = (long long)contents.size() - 1;
            continue;
        }

        if (key == "startswith") {
            if (currentContent < 0) return result;

            if (contents[(size_t)currentContent].buffer == PACKET_HEADER) {
                continue;
            }

            return result;
        }

        if (key == "endswith") {
            if (currentContent >= 0 &&
                contents[(size_t)currentContent].buffer == PACKET_HEADER) {
                continue;
            }

            return result;
        }

        if (key == "offset" || key == "depth" ||
            key == "distance" || key == "within") {
            if (currentContent < 0) return result;

            ContentInfo& content = contents[(size_t)currentContent];
            long long value;

            if (!parseIntegerOption(tokens[i], key, value)) {
                return result;
            }

            if (key == "offset") {
                content.hasOffset = true;
                content.offset = value;
                content.offsetTokenIndex = i;
            } else if (key == "depth") {
                content.hasDepth = true;
                content.depth = value;
            } else if (key == "distance") {
                content.hasDistance = true;
                content.distance = value;
            } else {
                content.hasWithin = true;
                content.within = value;
            }

            continue;
        }

        if (isUnsupportedPayloadOperation(key)) {
            currentContent = -1;

            if (currentBuffer != PACKET_HEADER) {
                return result;
            }
        }
    }

    vector<ChainState> chains;
    long long lastRawContent = -1;
    long long lastChain = -1;
    bool usesPayload = false;

    // convert supported content constraints into finite intervals
    for (size_t i = 0; i < contents.size(); ++i) {
        ContentInfo& content = contents[i];

        if (content.buffer == PACKET_HEADER) {
            lastRawContent = -1;
            lastChain = -1;
            continue;
        }

        usesPayload = true;

        bool absolute = content.hasOffset || content.hasDepth;
        bool relative = content.hasDistance || content.hasWithin;

        if (absolute && relative) return result;
        if (content.hasOffset && content.offset < 0) return result;
        if (content.hasDepth && content.depth <= 0) return result;
        if (content.hasWithin && content.within <= 0) return result;

        // only finite searches are supported
        if (content.hasOffset && !content.hasDepth) return result;
        if (relative && !content.hasWithin) return result;
        if (!absolute && !relative) return result;

        if (absolute) {
            SearchState state;
            state.minStart = content.hasOffset ? content.offset : 0;

            if (!safeAdd(state.minStart, content.depth - 1, state.maxEnd)) {
                return result;
            }

            state.contentLength = content.contentLength;

            ChainState chain;
            chain.envelope.start = state.minStart;
            chain.envelope.end = state.maxEnd;
            chain.previous = state;
            chains.push_back(chain);

            lastChain = (long long)chains.size() - 1;
            lastRawContent = (long long)i;

            if (content.hasOffset) {
                result.offsetTokens.push_back(content.offsetTokenIndex);
            }

            continue;
        }

        // preserve the complete relative search envelope
        if (lastRawContent != (long long)i - 1 || lastChain < 0) {
            return result;
        }

        ChainState& chain = chains[(size_t)lastChain];
        SearchState previous = chain.previous;
        SearchState current;
        long long distance = content.hasDistance ? content.distance : 0;
        long long temporary;

        if (!safeAdd(previous.minStart, previous.contentLength, temporary) ||
            !safeAdd(temporary, distance, current.minStart)) {
            return result;
        }

        if (current.minStart < 0) current.minStart = 0;

        if (!safeAdd(previous.maxEnd, distance, temporary) ||
            !safeAdd(temporary, content.within, current.maxEnd)) {
            return result;
        }

        if (current.maxEnd < 0) current.maxEnd = 0;
        current.contentLength = content.contentLength;

        chain.envelope.start = min(chain.envelope.start, current.minStart);
        chain.envelope.end = max(chain.envelope.end, current.maxEnd);
        chain.previous = current;
        lastRawContent = (long long)i;
    }

    for (size_t i = 0; i < chains.size(); ++i) {
        result.intervals.push_back(chains[i].envelope);
    }

    result.action = usesPayload ? ADAPT_RULE : KEEP_RULE;
    return result;
}

static vector<Interval> mergeIntervals(vector<Interval> intervals) {
    if (intervals.empty()) return intervals;

    sort(intervals.begin(), intervals.end(), [](const Interval& a, const Interval& b) {
        if (a.start != b.start) return a.start < b.start;
        return a.end < b.end;
    });

    vector<Interval> merged;
    merged.push_back(intervals[0]);

    for (size_t i = 1; i < intervals.size(); ++i) {
        Interval& last = merged.back();
        const Interval& current = intervals[i];

        if (current.start <= last.end + 1) {
            last.end = max(last.end, current.end);
        } else {
            merged.push_back(current);
        }
    }

    return merged;
}

static vector<Interval> getCuts(const vector<Interval>& merged) {
    vector<Interval> cuts;
    if (merged.empty()) return cuts;

    if (merged[0].start > 0) {
        cuts.push_back(Interval{0, merged[0].start - 1});
    }

    for (size_t i = 0; i + 1 < merged.size(); ++i) {
        long long start = merged[i].end + 1;
        long long end = merged[i + 1].start - 1;

        if (start <= end) {
            cuts.push_back(Interval{start, end});
        }
    }

    return cuts;
}

static long long removedBefore(long long position, const vector<Interval>& cuts) {
    long long removed = 0;

    for (size_t i = 0; i < cuts.size(); ++i) {
        if (cuts[i].end < position) {
            removed += cuts[i].end - cuts[i].start + 1;
        }
    }

    return removed;
}

static long long adjustPosition(long long position, const vector<Interval>& cuts) {
    return position - removedBefore(position, cuts);
}

static vector<Interval> adjustIntervals(
    const vector<Interval>& intervals,
    const vector<Interval>& cuts
) {
    vector<Interval> adjusted;

    for (size_t i = 0; i < intervals.size(); ++i) {
        Interval interval;

        interval.start = adjustPosition(intervals[i].start, cuts);
        interval.end = adjustPosition(intervals[i].end, cuts);

        adjusted.push_back(interval);
    }

    return adjusted;
}

static string replaceOffsetToken(const string& tokenText, long long newOffset) {
    static const regex pattern(
        "(\\boffset\\s*:\\s*)(-?\\d+)",
        regex_constants::icase
    );

    smatch match;
    if (!regex_search(tokenText, match, pattern)) return tokenText;

    return match.prefix().str() + match[1].str() +
           to_string(newOffset) + match.suffix().str();
}

static string adaptRule(
    const string& line,
    const RuleAnalysis& analysis,
    const vector<Interval>& cuts
) {
    if (analysis.action != ADAPT_RULE || analysis.offsetTokens.empty()) {
        return line;
    }

    size_t openPos;
    size_t closePos;
    getOptionsBounds(line, openPos, closePos);

    string options = line.substr(openPos + 1, closePos - openPos - 1);
    vector<Token> tokens = tokenizeOptions(options);
    map<size_t, bool> shouldReplace;

    for (size_t i = 0; i < analysis.offsetTokens.size(); ++i) {
        shouldReplace[analysis.offsetTokens[i]] = true;
    }

    string newOptions;
    size_t cursor = 0;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!shouldReplace[i]) continue;

        newOptions += options.substr(cursor, tokens[i].start - cursor);

        long long oldOffset = 0;
        parseIntegerOption(tokens[i], "offset", oldOffset);
        long long newOffset = adjustPosition(oldOffset, cuts);

        newOptions += replaceOffsetToken(tokens[i].text, newOffset);
        cursor = tokens[i].end;
    }

    newOptions += options.substr(cursor);

    return line.substr(0, openPos + 1) + newOptions + line.substr(closePos);
}

// pipeline

static bool loadRules(const string& filename, vector<string>& lines) {
    ifstream input(filename.c_str());
    if (!input) return false;

    string line;
    while (getline(input, line)) {
        lines.push_back(line);
    }

    return true;
}

static void printIntervals(const vector<Interval>& intervals) {
    if (intervals.empty()) {
        cout << "(nenhum)\n";
        return;
    }

    for (size_t i = 0; i < intervals.size(); ++i) {
        cout << intervals[i].start
             << "-"
             << intervals[i].end
             << "\n";
    }
}

static void analyzeRules(PipelineData& data) {
    data.analyses.reserve(data.lines.size());

    for (size_t i = 0; i < data.lines.size(); ++i) {
        RuleAnalysis analysis = analyzeRule(data.lines[i]);

        for (size_t j = 0; j < analysis.intervals.size(); ++j) {
            data.intervals.push_back(analysis.intervals[j]);
        }

        data.analyses.push_back(analysis);
    }
}

static bool writeRules(
    const string& filename,
    const PipelineData& data,
    Stats& stats
) {
    ofstream output(filename.c_str());
    if (!output) return false;

    for (size_t i = 0; i < data.lines.size(); ++i) {
        const RuleAnalysis& analysis = data.analyses[i];

        if (analysis.action == NON_RULE) {
            //output << data.lines[i] << "\n"; so i dont get comments
            continue;
        }

        ++stats.analyzed;

        if (analysis.action == DISCARD_RULE) {
            ++stats.discarded;
            continue;
        }

        if (analysis.action == ADAPT_RULE) {
            ++stats.adapted;
            output << adaptRule(data.lines[i], analysis, data.cuts) << "\n";
        } else {
            ++stats.keptUnchanged;
            output << data.lines[i] << "\n";
        }
    }

    return true;
}

static int runPipeline(int argc, char* argv[]) {
    if (argc != 3) {
        cout << "Uso:\n";
        cout << argv[0] << " regras.rules saida.rules\n";
        return 1;
    }

    PipelineData data;

    // stage 1: read rules
    if (!loadRules(argv[1], data.lines)) {
        cerr << "Erro ao abrir " << argv[1] << "\n";
        return 1;
    }

    // stage 2: analyze rules and collect finite intervals
    analyzeRules(data);

    // stage 3: merge required intervals
    data.merged = mergeIntervals(data.intervals);

    // stage 4: find removable gaps
    data.cuts = getCuts(data.merged);

    // stage 5: write supported rules and adapt absolute offsets
    if (!writeRules(argv[2], data, data.stats)) {
        cerr << "Erro ao criar " << argv[2] << "\n";
        return 1;
    }

    cout << "Regras mantidas: " << data.stats.kept << "\n";
    cout << "Regras descartadas: " << data.stats.discarded << "\n";

    return 0;
}

int main(int argc, char* argv[]) {
    try {
        return runPipeline(argc, argv);
    } catch (const exception& error) {
        cerr << "Erro: " << error.what() << "\n";
        return 1;
    }
}