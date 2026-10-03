#include <exception>
#include <iostream>

#include "pipeline.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    try {
        return runPipeline(argc, argv);
    } catch (const exception& error) {
        cerr << "Erro: " << error.what() << "\n";
        return 1;
    }
}
