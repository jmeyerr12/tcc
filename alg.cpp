#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

struct Interval {
    int start;
    int end;
};

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

        if (current.start >= last.start &&
            current.end <= last.end) {
            continue;
        }

        result.push_back(current);
    }

    return result;
}

vector<Interval> mergeIntervals(vector<Interval> intervals) {
    if (intervals.empty())
        return {};

    sort(intervals.begin(), intervals.end(),
        [](const Interval& a, const Interval& b) {
            return a.start < b.start;
        });

    vector<Interval> result;
    result.push_back(intervals[0]);

    for (size_t i = 1; i < intervals.size(); ++i) {
        auto& last = result.back();
        const auto& current = intervals[i];

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

vector<Interval> adjustIntervals(
    const vector<Interval>& merged,
    const vector<Interval>& cuts
) {
    vector<Interval> adjusted;

    for (const auto& interval : merged) {
        int removedBeforeStart = 0;
        int removedBeforeEnd = 0;

        for (const auto& cut : cuts) {
            int cutSize = cut.end - cut.start + 1;

            if (cut.end < interval.start) {
                removedBeforeStart += cutSize;
            }

            if (cut.end < interval.end) {
                removedBeforeEnd += cutSize;
            }
        }

        adjusted.push_back({
            interval.start - removedBeforeStart,
            interval.end - removedBeforeEnd
        });
    }

    return adjusted;
}

void printIntervals(const vector<Interval>& intervals) {
    for (const auto& i : intervals) {
        cout << i.start << "-" << i.end << "\n";
    }
}

int main() {
    vector<Interval> intervals = {
        {1, 10},
        {2, 8},
        {20, 30},
        {25, 40},
        {50, 60},
        {55, 58},
        {70, 80}
    };

    int packetSize = 100;

    auto noContained = removeContained(intervals);
    auto merged = mergeIntervals(noContained);
    auto cuts = getCutRanges(merged, packetSize);
    auto adjusted = adjustIntervals(merged, cuts);

    cout << "Merged:\n";
    printIntervals(merged);

    cout << "\nCuts:\n";
    printIntervals(cuts);

    cout << "\nAdjusted:\n";
    printIntervals(adjusted);

    return 0;
}