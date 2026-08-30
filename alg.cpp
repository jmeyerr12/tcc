#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <regex>
#include <map>
#include <iomanip>
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
    PACKET_HEADER,
    APPLICATION_BUFFER
};

enum RuleAction {
    KEEP_HEADER,
    ADAPT_PAYLOAD,
    EXCLUDE_RULE,
    NON_RULE
};

struct ContentInfo {
    BufferKind buffer;
    bool hasOffset;
    bool hasDepth;
    bool hasDistance;
    bool hasWithin;
    bool startsWith;
    long long offset;
    long long depth;
    long long distance;
    long long within;
    long long contentLength;
    size_t offsetTokenIndex;

    ContentInfo()
        : buffer(RAW_PAYLOAD), hasOffset(false), hasDepth(false),
          hasDistance(false), hasWithin(false), startsWith(false),
          offset(0), depth(0), distance(0), within(0), contentLength(0),
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
    string reason;
    vector<Interval> intervals;
    vector<size_t> rawOffsetTokens;

    RuleAnalysis() : action(EXCLUDE_RULE), reason("nao_classificada") {}
};

struct RuleUsage {
    bool networkTransportProtocol;
    bool applicationProtocol;
    bool networkTransportHeaderOnly;
    bool applicationHeader;
    bool applicationBuffer;
    bool rawPayload;
    bool otherNonHeaderSemantic;
    vector<string> applicationHeaderBuffers;

    RuleUsage()
        : networkTransportProtocol(false), applicationProtocol(false),
          networkTransportHeaderOnly(false), applicationHeader(false),
          applicationBuffer(false), rawPayload(false),
          otherNonHeaderSemantic(false) {}
};

struct Stats {
    long long totalRules;
    long long keptHeader;
    long long adaptedPayload;
    long long excluded;
    long long nonRules;

    long long networkTransportHeaderRules;
    long long networkTransportHeaderKept;
    long long networkTransportHeaderExcluded;

    long long applicationHeaderRules;
    long long applicationHeaderKept;
    long long applicationHeaderExcluded;

    long long networkTransportPayloadRules;
    long long networkTransportPayloadAdapted;
    long long networkTransportPayloadExcluded;

    long long otherApplicationRules;

    map<string, long long> applicationHeaderBuffers;
    map<string, long long> reasons;

    Stats()
        : totalRules(0), keptHeader(0), adaptedPayload(0),
          excluded(0), nonRules(0),
          networkTransportHeaderRules(0), networkTransportHeaderKept(0),
          networkTransportHeaderExcluded(0),
          applicationHeaderRules(0), applicationHeaderKept(0),
          applicationHeaderExcluded(0),
          networkTransportPayloadRules(0), networkTransportPayloadAdapted(0),
          networkTransportPayloadExcluded(0), otherApplicationRules(0) {}
};

struct PipelineData {
    vector<string> lines;
    vector<Interval> intervals;
    vector<Interval> merged;
    vector<Interval> cuts;
    vector<Interval> adjusted;
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
    for (size_t i = 0; i < s.size(); ++i)
        s[i] = (char)tolower((unsigned char)s[i]);
    return s;
}

static bool startsWithText(const string& s, const string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static string csvEscape(const string& s) {
    string out = "\"";
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '"') out += "\"\"";
        else out += s[i];
    }
    out += "\"";
    return out;
}

// comments are recognized only when the trimmed line starts with '#'
// this avoids breaking references that contain '#' inside urls
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

static string extractSid(const string& rule) {
    static const regex pattern("\\bsid\\s*:\\s*(\\d+)", regex_constants::icase);
    smatch match;
    if (regex_search(rule, match, pattern)) return match[1];
    return "";
}

static string getRuleProtocol(const string& rule) {
    static const regex pattern(
        "^\\s*(?:alert|log|pass|drop|reject|sdrop)\\s+([^\\s]+)",
        regex_constants::icase
    );
    smatch match;
    if (regex_search(rule, match, pattern)) return lowerCopy(match[1]);
    return "";
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
        if (isalnum((unsigned char)c) || c == '_' || c == '.' || c == '-') ++i;
        else break;
    }

    return lowerCopy(t.substr(0, i));
}

// options are split by ';' while quoted strings are preserved
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
    size_t last = string::npos;

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
            last = i;
            break;
        }
    }

    if (last == string::npos) return false;

    length = encodedContentLength(token.text.substr(first + 1, last - first - 1));
    return true;
}

// rule classification helpers

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

static bool isApplicationHeaderBuffer(const string& key) {
    return key == "http.header" || key == "http.header.raw" ||
           key == "http.header_names" || key == "http.request_header" ||
           key == "http.response_header" || key == "http_header" ||
           key == "http_raw_header";
}

static bool isApplicationBuffer(const string& key) {
    if (key.empty()) return false;

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

// application headers are parsed from payload and are reported separately
static bool getApplicationHeaderBuffers(
    const string& rule,
    vector<string>& buffers
) {
    size_t openPos;
    size_t closePos;

    if (!getOptionsBounds(rule, openPos, closePos)) return false;

    string options = rule.substr(openPos + 1, closePos - openPos - 1);
    vector<Token> tokens = tokenizeOptions(options);
    map<string, bool> seen;

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!isApplicationHeaderBuffer(tokens[i].key)) continue;
        if (seen[tokens[i].key]) continue;

        seen[tokens[i].key] = true;
        buffers.push_back(tokens[i].key);
    }

    return !buffers.empty();
}

static bool isPayloadOperation(const string& key) {
    return key == "pcre" || key == "byte_test" || key == "byte_jump" ||
           key == "byte_extract" || key == "byte_math" || key == "isdataat" ||
           key == "asn1" || key == "rpc";
}

static bool isUnsupportedPayloadSemantic(const string& key) {
    return key == "dsize" || key == "stream_size" || key == "stream-event" ||
           key == "app-layer-event" || key == "app-layer-protocol";
}

// rule usage is classified independently from the adaptation result
static RuleUsage classifyRuleUsage(const string& rule) {
    RuleUsage usage;
    string protocol = getRuleProtocol(rule);

    usage.networkTransportProtocol = isNetworkTransportProtocol(protocol);
    usage.applicationProtocol = !protocol.empty() && !usage.networkTransportProtocol;

    size_t openPos;
    size_t closePos;

    if (!getOptionsBounds(rule, openPos, closePos)) return usage;

    string options = rule.substr(openPos + 1, closePos - openPos - 1);
    vector<Token> tokens = tokenizeOptions(options);
    BufferKind currentBuffer = RAW_PAYLOAD;
    map<string, bool> seenApplicationHeaders;

    for (size_t i = 0; i < tokens.size(); ++i) {
        const string& key = tokens[i].key;

        if (isHeaderBuffer(key)) {
            currentBuffer = PACKET_HEADER;
            continue;
        }

        if (isRawPayloadBuffer(key)) {
            currentBuffer = RAW_PAYLOAD;
            continue;
        }

        if (isApplicationBuffer(key)) {
            currentBuffer = APPLICATION_BUFFER;
            usage.applicationBuffer = true;

            if (isApplicationHeaderBuffer(key)) {
                usage.applicationHeader = true;

                if (!seenApplicationHeaders[key]) {
                    seenApplicationHeaders[key] = true;
                    usage.applicationHeaderBuffers.push_back(key);
                }
            }

            continue;
        }

        if (key == "content" || isPayloadOperation(key)) {
            if (currentBuffer == RAW_PAYLOAD) usage.rawPayload = true;
            if (currentBuffer == APPLICATION_BUFFER) usage.applicationHeader =
                usage.applicationHeader;
            continue;
        }

        if (isUnsupportedPayloadSemantic(key)) {
            usage.otherNonHeaderSemantic = true;
        }
    }

    usage.networkTransportHeaderOnly =
        usage.networkTransportProtocol &&
        !usage.rawPayload &&
        !usage.applicationBuffer &&
        !usage.otherNonHeaderSemantic;

    return usage;
}

static bool safeAdd(long long a, long long b, long long& out) {
    if ((b > 0 && a > LLONG_MAX - b) ||
        (b < 0 && a < LLONG_MIN - b)) {
        return false;
    }

    out = a + b;
    return true;
}

// algorithm logic

// stage 1 analyzes one rule and extracts every finite payload interval
static RuleAnalysis analyzeRule(
    const string& line,
    vector<Token>* tokensOut = NULL,
    string* optionsOut = NULL
) {
    RuleAnalysis result;

    if (isCommentOrBlank(line) || !isRuleLine(line)) {
        result.action = NON_RULE;
        result.reason = "nao_e_regra_ativa";
        return result;
    }

    size_t openPos;
    size_t closePos;

    if (!getOptionsBounds(line, openPos, closePos)) {
        result.action = EXCLUDE_RULE;
        result.reason = "regra_sem_bloco_de_opcoes";
        return result;
    }

    string protocol = getRuleProtocol(line);

    if (!isNetworkTransportProtocol(protocol)) {
        result.action = EXCLUDE_RULE;
        result.reason = "protocolo_de_aplicacao_nao_tratado:" + protocol;
        return result;
    }

    string options = line.substr(openPos + 1, closePos - openPos - 1);
    vector<Token> tokens = tokenizeOptions(options);

    if (tokensOut) *tokensOut = tokens;
    if (optionsOut) *optionsOut = options;

    BufferKind currentBuffer = RAW_PAYLOAD;
    vector<ContentInfo> contents;
    long long currentContent = -1;
    bool anyHeaderInspection = false;

    // first pass collects content constraints and rejects unsupported semantics
    for (size_t i = 0; i < tokens.size(); ++i) {
        const string& key = tokens[i].key;

        if (isHeaderBuffer(key)) {
            currentBuffer = PACKET_HEADER;
            currentContent = -1;
            anyHeaderInspection = true;
            continue;
        }

        if (isRawPayloadBuffer(key)) {
            currentBuffer = RAW_PAYLOAD;
            currentContent = -1;
            continue;
        }

        if (isApplicationBuffer(key)) {
            result.action = EXCLUDE_RULE;
            result.reason = "buffer_de_aplicacao_nao_tratado:" + key;
            return result;
        }

        if (isUnsupportedPayloadSemantic(key)) {
            result.action = EXCLUDE_RULE;
            result.reason = "semantica_nao_preservada:" + key;
            return result;
        }

        if (key == "endswith") {
            if (currentContent >= 0 &&
                contents[(size_t)currentContent].buffer == PACKET_HEADER) {
                anyHeaderInspection = true;
                continue;
            }

            result.action = EXCLUDE_RULE;
            result.reason = "modificador_de_fim_de_buffer_nao_tratado:endswith";
            return result;
        }

        if (key == "content") {
            ContentInfo content;
            content.buffer = currentBuffer;

            if (!parseContentLength(tokens[i], content.contentLength) ||
                content.contentLength <= 0) {
                result.action = EXCLUDE_RULE;
                result.reason = "content_invalido_ou_vazio";
                return result;
            }

            contents.push_back(content);
            currentContent = (long long)contents.size() - 1;
            continue;
        }

        if (key == "offset" || key == "depth" || key == "distance" ||
            key == "within" || key == "startswith") {
            if (currentContent < 0) {
                result.action = EXCLUDE_RULE;
                result.reason = "modificador_sem_content:" + key;
                return result;
            }

            ContentInfo& content = contents[(size_t)currentContent];

            if (key == "startswith") {
                content.startsWith = true;
                continue;
            }

            long long value;

            if (!parseIntegerOption(tokens[i], key, value)) {
                result.action = EXCLUDE_RULE;
                result.reason = key + "_nao_numerico";
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

        if (isPayloadOperation(key)) {
            currentContent = -1;

            if (currentBuffer != PACKET_HEADER) {
                result.action = EXCLUDE_RULE;
                result.reason = "operacao_de_payload_nao_tratada:" + key;
                return result;
            }

            anyHeaderInspection = true;
        }
    }

    vector<ChainState> chains;
    long long lastRawContent = -1;
    long long lastChain = -1;
    bool anyRawPayload = false;

    // second pass converts absolute and relative constraints into finite intervals
    for (size_t i = 0; i < contents.size(); ++i) {
        ContentInfo& content = contents[i];

        if (content.buffer == PACKET_HEADER) {
            anyHeaderInspection = true;
            lastRawContent = -1;
            lastChain = -1;
            continue;
        }

        if (content.buffer != RAW_PAYLOAD) {
            result.action = EXCLUDE_RULE;
            result.reason = "content_em_buffer_nao_tratado";
            return result;
        }

        anyRawPayload = true;

        bool absolute = content.hasOffset || content.hasDepth || content.startsWith;
        bool relative = content.hasDistance || content.hasWithin;

        if (content.startsWith && (content.hasOffset || content.hasDepth || relative)) {
            result.action = EXCLUDE_RULE;
            result.reason = "startswith_com_modificador_incompativel";
            return result;
        }

        if (absolute && relative) {
            result.action = EXCLUDE_RULE;
            result.reason = "mistura_modificador_absoluto_relativo";
            return result;
        }

        if (content.hasOffset && content.offset < 0) {
            result.action = EXCLUDE_RULE;
            result.reason = "offset_negativo_nao_tratado";
            return result;
        }

        if (content.hasDepth && content.depth <= 0) {
            result.action = EXCLUDE_RULE;
            result.reason = "depth_invalido";
            return result;
        }

        if (content.hasWithin && content.within <= 0) {
            result.action = EXCLUDE_RULE;
            result.reason = "within_invalido";
            return result;
        }

        // open searches are excluded because the algorithm only keeps finite intervals
        if (absolute && content.hasOffset && !content.hasDepth && !content.startsWith) {
            result.action = EXCLUDE_RULE;
            result.reason = "offset_sem_depth_intervalo_aberto";
            return result;
        }

        if (relative && !content.hasWithin) {
            result.action = EXCLUDE_RULE;
            result.reason = "distance_sem_within_intervalo_aberto";
            return result;
        }

        if (!absolute && !relative) {
            result.action = EXCLUDE_RULE;
            result.reason = "content_sem_modificador_de_intervalo";
            return result;
        }

        if (absolute) {
            SearchState state;

            if (content.startsWith) {
                state.minStart = 0;
                state.maxEnd = content.contentLength - 1;
            } else {
                state.minStart = content.hasOffset ? content.offset : 0;

                if (!safeAdd(state.minStart, content.depth - 1, state.maxEnd)) {
                    result.action = EXCLUDE_RULE;
                    result.reason = "intervalo_excede_limite";
                    return result;
                }
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
                result.rawOffsetTokens.push_back(content.offsetTokenIndex);
            }

            continue;
        }

        // relative windows stay unchanged and their full envelope is preserved
        if (lastRawContent != (long long)i - 1 || lastChain < 0) {
            result.action = EXCLUDE_RULE;
            result.reason = "modificador_relativo_sem_content_anterior_compativel";
            return result;
        }

        ChainState& chain = chains[(size_t)lastChain];
        SearchState previous = chain.previous;
        SearchState current;
        long long distance = content.hasDistance ? content.distance : 0;
        long long temporary;

        if (!safeAdd(previous.minStart, previous.contentLength, temporary) ||
            !safeAdd(temporary, distance, current.minStart)) {
            result.action = EXCLUDE_RULE;
            result.reason = "intervalo_relativo_excede_limite";
            return result;
        }

        if (current.minStart < 0) current.minStart = 0;

        if (!safeAdd(previous.maxEnd, distance, temporary) ||
            !safeAdd(temporary, content.within, current.maxEnd)) {
            result.action = EXCLUDE_RULE;
            result.reason = "intervalo_relativo_excede_limite";
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

    if (anyRawPayload) {
        result.action = ADAPT_PAYLOAD;
        result.reason = "payload_com_intervalos_finitos_offset_depth_distance_within_startswith";
    } else {
        result.action = KEEP_HEADER;
        result.reason = anyHeaderInspection ? "inspecao_de_header" : "independente_do_payload";
    }

    return result;
}

// stage 2 merges overlapping or adjacent intervals
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

// stage 3 finds every removable gap before the last required byte
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

static long long intervalLength(const Interval& interval) {
    return interval.end - interval.start + 1;
}

static long long removedBefore(long long position, const vector<Interval>& cuts) {
    long long removed = 0;

    for (size_t i = 0; i < cuts.size(); ++i) {
        if (cuts[i].end < position) {
            removed += intervalLength(cuts[i]);
        }
    }

    return removed;
}

static long long adjustPosition(long long position, const vector<Interval>& cuts) {
    return position - removedBefore(position, cuts);
}

// stage 4 maps required intervals to their new positions after the cuts
static vector<Interval> adjustIntervals(
    const vector<Interval>& merged,
    const vector<Interval>& cuts
) {
    vector<Interval> adjusted;

    for (size_t i = 0; i < merged.size(); ++i) {
        adjusted.push_back(Interval{
            adjustPosition(merged[i].start, cuts),
            adjustPosition(merged[i].end, cuts)
        });
    }

    return adjusted;
}

// rule adaptation

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

// only absolute raw payload offsets are rewritten
// distance and within remain unchanged because their relative spacing is preserved
static string adaptRule(const string& line, const vector<Interval>& cuts) {
    vector<Token> tokens;
    string options;
    RuleAnalysis analysis = analyzeRule(line, &tokens, &options);

    if (analysis.action != ADAPT_PAYLOAD || analysis.rawOffsetTokens.empty()) {
        return line;
    }

    map<size_t, bool> shouldReplace;

    for (size_t i = 0; i < analysis.rawOffsetTokens.size(); ++i) {
        shouldReplace[analysis.rawOffsetTokens[i]] = true;
    }

    size_t openPos;
    size_t closePos;
    getOptionsBounds(line, openPos, closePos);

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

// pipeline input and output

// stage 0 loads the complete rule file before any transformation
static bool loadRules(const string& filename, vector<string>& lines) {
    ifstream input(filename.c_str());
    if (!input) return false;

    string line;
    while (getline(input, line)) {
        lines.push_back(line);
    }

    return true;
}

// stage 1 scans supported rules and records their finite intervals
static bool extractIntervals(
    const vector<string>& lines,
    vector<Interval>& intervals,
    const string& reportName
) {
    ofstream report(reportName.c_str());
    if (!report) return false;

    report << "line,sid,start,end,type,rule\n";

    for (size_t i = 0; i < lines.size(); ++i) {
        RuleAnalysis analysis = analyzeRule(lines[i]);

        if (analysis.action != ADAPT_PAYLOAD) continue;

        for (size_t j = 0; j < analysis.intervals.size(); ++j) {
            intervals.push_back(analysis.intervals[j]);

            report << (i + 1) << ","
                   << csvEscape(extractSid(lines[i])) << ","
                   << analysis.intervals[j].start << ","
                   << analysis.intervals[j].end << ","
                   << csvEscape("finite") << ","
                   << csvEscape(trim(lines[i])) << "\n";
        }
    }

    return true;
}

// stage 5 writes supported rules and records every excluded rule
static bool writeRules(
    const vector<string>& lines,
    const vector<Interval>& cuts,
    const string& outputName,
    const string& excludedName,
    Stats& stats
) {
    ofstream output(outputName.c_str());
    ofstream excluded(excludedName.c_str());

    if (!output || !excluded) return false;

    excluded << "line,sid,reason,rule\n";

    for (size_t i = 0; i < lines.size(); ++i) {
        RuleAnalysis analysis = analyzeRule(lines[i]);

        if (analysis.action == NON_RULE) {
            ++stats.nonRules;
            output << lines[i] << "\n";
            continue;
        }

        ++stats.totalRules;

        RuleUsage usage = classifyRuleUsage(lines[i]);

        if (usage.networkTransportHeaderOnly) {
            ++stats.networkTransportHeaderRules;

            if (analysis.action == KEEP_HEADER) {
                ++stats.networkTransportHeaderKept;
            } else {
                ++stats.networkTransportHeaderExcluded;
            }
        } else if (usage.applicationHeader) {
            ++stats.applicationHeaderRules;

            for (size_t j = 0; j < usage.applicationHeaderBuffers.size(); ++j) {
                ++stats.applicationHeaderBuffers[usage.applicationHeaderBuffers[j]];
            }

            if (analysis.action == ADAPT_PAYLOAD || analysis.action == KEEP_HEADER) {
                ++stats.applicationHeaderKept;
            } else {
                ++stats.applicationHeaderExcluded;
            }
        } else if (usage.networkTransportProtocol) {
            ++stats.networkTransportPayloadRules;

            if (analysis.action == ADAPT_PAYLOAD) {
                ++stats.networkTransportPayloadAdapted;
            } else if (analysis.action == EXCLUDE_RULE) {
                ++stats.networkTransportPayloadExcluded;
            }
        } else {
            ++stats.otherApplicationRules;
        }

        if (analysis.action == KEEP_HEADER) {
            ++stats.keptHeader;
            output << lines[i] << "\n";
            continue;
        }

        if (analysis.action == ADAPT_PAYLOAD) {
            ++stats.adaptedPayload;
            output << adaptRule(lines[i], cuts) << "\n";
            continue;
        }

        ++stats.excluded;
        ++stats.reasons[analysis.reason];

        excluded << (i + 1) << ","
                 << csvEscape(extractSid(lines[i])) << ","
                 << csvEscape(analysis.reason) << ","
                 << csvEscape(trim(lines[i])) << "\n";
    }

    return true;
}

static void printInterval(const Interval& interval) {
    cout << interval.start << "-" << interval.end;
}

static void printSummary(
    const PipelineData& data,
    const string& outputName,
    const string& excludedName,
    const string& intervalsName
) {
    cout << "Resumo dos intervalos:\n";
    cout << "Intervalos extraidos: " << data.intervals.size() << "\n";
    cout << "Intervalos apos merge: " << data.merged.size() << "\n";

    cout << "\nMerged:\n";
    if (data.merged.empty()) {
        cout << "(nenhum)\n";
    } else {
        for (size_t i = 0; i < data.merged.size(); ++i) {
            printInterval(data.merged[i]);
            cout << "\n";
        }
    }

    cout << "\nCortes finitos:\n";
    if (data.cuts.empty()) {
        cout << "(nenhum)\n";
    } else {
        for (size_t i = 0; i < data.cuts.size(); ++i) {
            printInterval(data.cuts[i]);
            cout << "\n";
        }
    }

    cout << "\nAdjusted:\n";
    if (data.adjusted.empty()) {
        cout << "(nenhum)\n";
    } else {
        for (size_t i = 0; i < data.adjusted.size(); ++i) {
            printInterval(data.adjusted[i]);
            cout << "\n";
        }
    }

    cout << "\nResumo do payload:\n";

    if (data.merged.empty()) {
        cout << "Nenhuma regra adaptada exige bytes do payload.\n";
    } else {
        long long preservedBytes = 0;
        long long removedBytes = 0;

        for (size_t i = 0; i < data.merged.size(); ++i) {
            preservedBytes += intervalLength(data.merged[i]);
        }

        for (size_t i = 0; i < data.cuts.size(); ++i) {
            removedBytes += intervalLength(data.cuts[i]);
        }

        long long maxByte = data.merged.back().end;

        cout << "Maior indice original de payload necessario: " << maxByte << "\n";
        cout << "Bytes preservados apos compactacao: " << preservedBytes << " bytes\n";
        cout << "Bytes removiveis nas lacunas ate o maior byte necessario: "
             << removedBytes << " bytes\n";
        cout << "Todos os bytes apos o indice " << maxByte
             << " tambem podem ser removidos.\n";
        cout << "Maior indice no payload reajustado: " << (preservedBytes - 1) << "\n";
    }

    double supportedPct = data.stats.totalRules
        ? 100.0 * (data.stats.keptHeader + data.stats.adaptedPayload) / data.stats.totalRules
        : 0.0;

    double discardPct = data.stats.totalRules
        ? 100.0 * data.stats.excluded / data.stats.totalRules
        : 0.0;

    cout << "\nResumo das regras:\n";
    cout << "Regras analisadas: " << data.stats.totalRules << "\n";
    cout << "Mantidas sem alteracao (header/independentes do payload): "
         << data.stats.keptHeader << "\n";
    cout << "Adaptadas (offset/depth/distance/within/startswith): "
         << data.stats.adaptedPayload << "\n";
    cout << "Excluidas (nao tratadas): " << data.stats.excluded << "\n";

    cout << fixed << setprecision(2);

    cout << "\nSeparacao por tipo de dado inspecionado:\n";
    cout << "Regras de rede/transporte sem dependencia do payload: "
         << data.stats.networkTransportHeaderRules << "\n";
    cout << "  Mantidas sem alteracao: "
         << data.stats.networkTransportHeaderKept << "\n";
    cout << "  Excluidas: "
         << data.stats.networkTransportHeaderExcluded << "\n";

    cout << "Regras que inspecionam header de aplicacao: "
         << data.stats.applicationHeaderRules << "\n";
    cout << "  Tratadas pela implementacao atual: "
         << data.stats.applicationHeaderKept << "\n";
    cout << "  Excluidas: "
         << data.stats.applicationHeaderExcluded << "\n";

    cout << "Regras de payload sob protocolo de rede/transporte: "
         << data.stats.networkTransportPayloadRules << "\n";
    cout << "  Adaptadas por intervalos finitos: "
         << data.stats.networkTransportPayloadAdapted << "\n";
    cout << "  Excluidas: "
         << data.stats.networkTransportPayloadExcluded << "\n";

    cout << "Outras regras de aplicacao: "
         << data.stats.otherApplicationRules << "\n";

    cout << "\nBuffers de header de aplicacao encontrados:\n";
    if (data.stats.applicationHeaderBuffers.empty()) {
        cout << "  (nenhum)\n";
    } else {
        for (map<string, long long>::const_iterator it =
                 data.stats.applicationHeaderBuffers.begin();
             it != data.stats.applicationHeaderBuffers.end(); ++it) {
            cout << "  " << it->first << ": " << it->second << "\n";
        }
    }

    cout << fixed << setprecision(2);
    cout << "Regras suportadas: "
         << (data.stats.keptHeader + data.stats.adaptedPayload)
         << " (" << supportedPct << "%)\n";
    cout << "Taxa de descarte: " << discardPct << "%\n";

    cout << "\nMotivos de descarte:\n";
    for (map<string, long long>::const_iterator it = data.stats.reasons.begin();
         it != data.stats.reasons.end(); ++it) {
        cout << it->first << ": " << it->second << "\n";
    }

    cout << "\nArquivo adaptado: " << outputName << "\n";
    cout << "Relatorio de excluidas: " << excludedName << "\n";
    cout << "Relatorio dos intervalos: " << intervalsName << "\n";
}

// pipeline

static int runPipeline(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        cout << "Uso:\n";
        cout << argv[0] << " regras.rules saida.rules [relatorio_excluidas.csv]\n\n";
        cout << "Exemplo:\n";
        cout << argv[0]
             << " suricata.rules suricata-adapted.rules suricata-excluded.csv\n";
        return 1;
    }

    string inputName = argv[1];
    string outputName = argv[2];
    string excludedName = argc == 4 ? argv[3] : outputName + ".excluded.csv";
    string intervalsName = outputName + ".intervals.csv";

    PipelineData data;

    // stage 0: read rules
    if (!loadRules(inputName, data.lines)) {
        cerr << "Erro ao abrir " << inputName << "\n";
        return 1;
    }

    // stage 1: parse rules and extract finite intervals
    if (!extractIntervals(data.lines, data.intervals, intervalsName)) {
        cerr << "Erro ao criar relatorio de intervalos.\n";
        return 1;
    }

    // stage 2: merge required intervals
    data.merged = mergeIntervals(data.intervals);

    // stage 3: calculate removable gaps
    data.cuts = getCuts(data.merged);

    // stage 4: calculate positions after packet washing
    data.adjusted = adjustIntervals(data.merged, data.cuts);

    // stage 5: adapt supported rules and discard unsupported rules
    if (!writeRules(data.lines, data.cuts, outputName, excludedName, data.stats)) {
        cerr << "Erro ao criar arquivos de saida.\n";
        return 1;
    }

    // stage 6: print experiment metrics
    printSummary(data, outputName, excludedName, intervalsName);

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