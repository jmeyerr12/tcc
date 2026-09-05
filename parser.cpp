#include "parser.hpp"

#include <cctype>
#include <regex>

using namespace std;

// parsing

string trim(const string& text) {
    size_t first = text.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";

    size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

string lowerCopy(string text) {
    for (size_t i = 0; i < text.size(); ++i) {
        text[i] = (char)tolower((unsigned char)text[i]);
    }

    return text;
}

bool startsWithText(const string& text, const string& prefix) {
    return text.size() >= prefix.size() &&
           text.compare(0, prefix.size(), prefix) == 0;
}

bool isCommentOrBlank(const string& line) {
    string value = trim(line);
    return value.empty() || value[0] == '#';
}

bool isRuleLine(const string& line) {
    static const regex pattern(
        "^\\s*(alert|log|pass|drop|reject|sdrop)\\b",
        regex_constants::icase
    );

    return regex_search(line, pattern);
}

string getRuleProtocol(const string& rule) {
    static const regex pattern(
        "^\\s*(?:alert|log|pass|drop|reject|sdrop)\\s+([^\\s]+)",
        regex_constants::icase
    );

    smatch match;
    if (!regex_search(rule, match, pattern)) return "";

    return lowerCopy(match[1]);
}

bool getOptionsBounds(const string& rule, size_t& openPos, size_t& closePos) {
    openPos = rule.find('(');
    closePos = rule.rfind(')');

    return openPos != string::npos &&
           closePos != string::npos &&
           closePos > openPos;
}

static string optionKey(const string& text) {
    string value = trim(text);
    size_t i = 0;

    while (i < value.size()) {
        char c = value[i];

        if (isalnum((unsigned char)c) || c == '_' || c == '.' || c == '-') {
            ++i;
        } else {
            break;
        }
    }

    return lowerCopy(value.substr(0, i));
}

vector<Token> tokenizeOptions(const string& options) {
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

bool parseIntegerOption(const Token& token, const string& name, long long& value) {
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

bool parseContentLength(const Token& token, long long& length) {
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
            length = encodedContentLength(
                token.text.substr(first + 1, i - first - 1)
            );
            return true;
        }
    }

    return false;
}
