#ifndef TYPES_HPP
#define TYPES_HPP

#include <cstddef>
#include <string>
#include <vector>

struct Interval {
    long long start;
    long long end;
};

struct Token {
    std::size_t start;
    std::size_t end;
    std::string text;
    std::string key;
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
    std::size_t offsetTokenIndex;

    ContentInfo()
        : buffer(RAW_PAYLOAD), hasOffset(false), hasDepth(false),
          hasDistance(false), hasWithin(false), offset(0), depth(0),
          distance(0), within(0), contentLength(0),
          offsetTokenIndex((std::size_t)-1) {}
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
    std::vector<Interval> intervals;
    std::vector<std::size_t> offsetTokens;

    RuleAnalysis() : action(DISCARD_RULE) {}
};

struct Stats {
    long long analyzed;
    long long keptUnchanged;
    long long adapted;
    long long discarded;

    Stats()
        : analyzed(0), keptUnchanged(0), adapted(0), discarded(0) {}
};

struct PipelineData {
    std::vector<std::string> lines;
    std::vector<RuleAnalysis> analyses;
    std::vector<Interval> intervals;
    std::vector<Interval> merged;
    std::vector<Interval> cuts;
    Stats stats;
};

#endif
