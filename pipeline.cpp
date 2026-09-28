#include "pipeline.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "algorithm.hpp"
#include "types.hpp"

using namespace std;

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

static void printIntervals(const vector<Interval>& intervals) {
    if (intervals.empty()) {
        cout << "(nenhum)\n";
        return;
    }

    for (size_t i = 0; i < intervals.size(); ++i) {
        cout << intervals[i].start << "-" << intervals[i].end << "\n";
    }
}

static void printSummary(const PipelineData& data) {
    vector<Interval> adjusted = adjustIntervals(data.merged, data.cuts);

    cout << "Resumo dos intervalos:\n";
    cout << "Intervalos extraidos: " << data.intervals.size() << "\n";
    cout << "Intervalos apos merge: " << data.merged.size() << "\n\n";

    cout << "Merged:\n";
    printIntervals(data.merged);

    cout << "\nCortes finitos:\n";
    printIntervals(data.cuts);

    cout << "\nAdjusted:\n";
    printIntervals(adjusted);

    cout << "\nResumo do payload:\n";

    if (data.merged.empty()) {
        cout << "Nenhum intervalo de payload necessario.\n";
    } else {
        long long maxOriginal = data.merged.back().end;
        long long preserved = 0;
        long long removed = 0;

        for (size_t i = 0; i < data.merged.size(); ++i) {
            preserved += data.merged[i].end - data.merged[i].start + 1;
        }

        for (size_t i = 0; i < data.cuts.size(); ++i) {
            removed += data.cuts[i].end - data.cuts[i].start + 1;
        }

        long long maxAdjusted = adjusted.back().end;

        cout << "Maior indice original de payload necessario: "
             << maxOriginal << "\n";
        cout << "Bytes preservados apos compactacao: "
             << preserved << " bytes\n";
        cout << "Bytes removiveis nas lacunas ate o maior byte necessario: "
             << removed << " bytes\n";
        cout << "Todos os bytes apos o indice "
             << maxOriginal << " tambem podem ser removidos.\n";
        cout << "Maior indice no payload reajustado: "
             << maxAdjusted << "\n";
    }

    cout << "\nResumo das regras:\n";
    cout << "Regras analisadas: " << data.stats.analyzed << "\n";
    cout << "Mantidas sem alteracao (header/independentes do payload): "
         << data.stats.keptUnchanged << "\n";
    cout << "Adaptadas (offset/depth/distance/within): "
         << data.stats.adapted << "\n";
    cout << "Excluidas (nao tratadas): "
         << data.stats.discarded << "\n";
}

int runPipeline(int argc, char* argv[]) {
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

    // stage 6: print summary
    printSummary(data);

    return 0;
}
