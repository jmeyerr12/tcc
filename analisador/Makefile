CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic

BUILD_DIR = build
TARGET = $(BUILD_DIR)/alg
SOURCES = src/main.cpp src/parser.cpp src/algorithm.cpp src/pipeline.cpp
HEADERS = $(wildcard src/*.hpp)
OBJECTS = $(patsubst src/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))

INPUT ?= ../suricata.rules
OUTPUT ?= $(BUILD_DIR)/suricata-adapted.rules
ALGORITHM ?= $(abspath $(TARGET))

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: src/%.cpp $(HEADERS) Makefile | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@

run: $(TARGET)
	./$(TARGET) $(INPUT) $(OUTPUT)

rule-groups: $(TARGET)
	python3 generate_rule_groups.py --algorithm "$(abspath $(TARGET))"

$(BUILD_DIR)/test_algorithm: tests/test_algorithm.cpp src/algorithm.cpp src/parser.cpp $(HEADERS) Makefile | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -std=c++11 -fsanitize=undefined -fno-sanitize-recover=all -g -Isrc tests/test_algorithm.cpp src/algorithm.cpp src/parser.cpp -o $@

test: $(TARGET) $(BUILD_DIR)/test_algorithm
	./$(BUILD_DIR)/test_algorithm
	python3 tests/test_rule_groups.py
	python3 tests/test_rule_scope.py "$(ALGORITHM)"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run rule-groups test clean
