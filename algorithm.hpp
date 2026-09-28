#ifndef ALGORITHM_HPP
#define ALGORITHM_HPP

#include <string>
#include <vector>

#include "types.hpp"

RuleAnalysis analyzeRule(const std::string& line);
std::vector<Interval> mergeIntervals(std::vector<Interval> intervals);
std::vector<Interval> getCuts(const std::vector<Interval>& merged);
std::vector<Interval> adjustIntervals(
    const std::vector<Interval>& intervals,
    const std::vector<Interval>& cuts
);
std::string adaptRule(
    const std::string& line,
    const RuleAnalysis& analysis,
    const std::vector<Interval>& cuts
);

#endif
