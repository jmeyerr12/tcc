CXX = g++
CLANG = clang

CXXFLAGS = -Wall -Wextra -pedantic
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include/$(shell uname -m)-linux-gnu

TARGET = alg
BPF_TARGET = af_xdp_kern.o

SOURCES = main.cpp parser.cpp algorithm.cpp pipeline.cpp
OBJECTS = $(SOURCES:.cpp=.o)

INPUT ?= suricata.rules
OUTPUT ?= suricata-adapted.rules

all: $(TARGET) $(BPF_TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET)

main.o: main.cpp pipeline.hpp

parser.o: parser.cpp parser.hpp types.hpp

algorithm.o: algorithm.cpp algorithm.hpp parser.hpp types.hpp

pipeline.o: pipeline.cpp pipeline.hpp algorithm.hpp types.hpp

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BPF_TARGET): af_xdp_kern.c xdp/parsing_helpers.h
	$(CLANG) $(BPF_CFLAGS) -c af_xdp_kern.c -o $(BPF_TARGET)

run: $(TARGET)
	./$(TARGET) $(INPUT) $(OUTPUT)

bpf: $(BPF_TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET) $(BPF_TARGET)

.PHONY: all run bpf clean