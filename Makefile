CXX = g++
CLANG = clang

CXXFLAGS = -Wall -Wextra -pedantic
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include/$(shell uname -m)-linux-gnu

BUILD_DIR = build
TARGET = $(BUILD_DIR)/alg
BPF_TARGET = $(BUILD_DIR)/af_xdp_kern.o

SOURCES = main.cpp parser.cpp algorithm.cpp pipeline.cpp
OBJECTS = $(SOURCES:%.cpp=$(BUILD_DIR)/%.o)

INPUT ?= suricata.rules
OUTPUT ?= $(BUILD_DIR)/suricata-adapted.rules

all: $(TARGET) $(BPF_TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/main.o: main.cpp pipeline.hpp

$(BUILD_DIR)/parser.o: parser.cpp parser.hpp types.hpp

$(BUILD_DIR)/algorithm.o: algorithm.cpp algorithm.hpp parser.hpp types.hpp

$(BUILD_DIR)/pipeline.o: pipeline.cpp pipeline.hpp algorithm.hpp types.hpp

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BPF_TARGET): af_xdp_kern.c xdp/parsing_helpers.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c af_xdp_kern.c -o $(BPF_TARGET)

run: $(TARGET)
	./$(TARGET) $(INPUT) $(OUTPUT)

bpf: $(BPF_TARGET)

alg: $(TARGET)

$(BUILD_DIR)/test_algorithm: tests/test_algorithm.cpp algorithm.cpp parser.cpp algorithm.hpp parser.hpp types.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -std=c++11 -fsanitize=undefined -fno-sanitize-recover=all -g -I. tests/test_algorithm.cpp algorithm.cpp parser.cpp -o $@

test: $(TARGET) $(BUILD_DIR)/test_algorithm
	./$(BUILD_DIR)/test_algorithm
	python3 tests/test_rule_scope.py ./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all alg run bpf test clean
