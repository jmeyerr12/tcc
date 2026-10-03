CXX = g++
CLANG = clang

CXXFLAGS = -Wall -Wextra -pedantic
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include/$(shell uname -m)-linux-gnu

BUILD_DIR = build
TARGET = $(BUILD_DIR)/alg
BPF_TARGET = $(BUILD_DIR)/af_xdp_kern.o
WASH_TARGET = $(BUILD_DIR)/wash_pcap
PCAP_STATS_TARGET = $(BUILD_DIR)/pcap_stats

ANALYZER_DIR = analisador
ANALYZER_SOURCES = $(wildcard $(ANALYZER_DIR)/src/*.cpp $(ANALYZER_DIR)/src/*.hpp)

INPUT ?= suricata.rules
OUTPUT ?= $(BUILD_DIR)/suricata-adapted.rules

all: $(TARGET) $(BPF_TARGET)

$(TARGET): $(ANALYZER_SOURCES) $(ANALYZER_DIR)/Makefile Makefile | $(BUILD_DIR)
	$(MAKE) -C $(ANALYZER_DIR) BUILD_DIR=build TARGET=build/alg CXX="$(CXX)" CXXFLAGS="$(CXXFLAGS)"
	cp $(ANALYZER_DIR)/build/alg $@

$(BUILD_DIR):
	mkdir -p $@

$(BPF_TARGET): af_xdp_kern.c xdp/parsing_helpers.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c af_xdp_kern.c -o $(BPF_TARGET)

run: $(TARGET)
	./$(TARGET) $(INPUT) $(OUTPUT)

bpf: $(BPF_TARGET)

alg: $(TARGET)

rule-groups: $(TARGET)
	python3 $(ANALYZER_DIR)/generate_rule_groups.py --algorithm "$(abspath $(TARGET))"

$(WASH_TARGET): tests/wash_pcap.cpp $(BPF_TARGET) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -std=c++11 tests/wash_pcap.cpp -lbpf -lelf -lz -o $@

$(PCAP_STATS_TARGET): experiments/pcap_stats.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -std=c++11 experiments/pcap_stats.cpp -o $@

precut-tools: $(TARGET) $(BPF_TARGET) $(WASH_TARGET) $(PCAP_STATS_TARGET)

test: $(TARGET)
	$(MAKE) -C $(ANALYZER_DIR) test BUILD_DIR=build TARGET=build/alg CXX="$(CXX)" CXXFLAGS="$(CXXFLAGS)" ALGORITHM="$(abspath $(TARGET))"
	python3 tests/test_replay_rate.py

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(ANALYZER_DIR) clean BUILD_DIR=build

.PHONY: all alg run bpf precut-tools rule-groups test clean
