CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic

TARGET = alg
SOURCES = main.cpp parser.cpp algorithm.cpp pipeline.cpp
OBJECTS = $(SOURCES:.cpp=.o)

INPUT ?= suricata.rules
OUTPUT ?= suricata-adapted.rules

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET)

main.o: main.cpp pipeline.hpp
parser.o: parser.cpp parser.hpp types.hpp
algorithm.o: algorithm.cpp algorithm.hpp parser.hpp types.hpp
pipeline.o: pipeline.cpp pipeline.hpp algorithm.hpp types.hpp

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) $(INPUT) $(OUTPUT)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all run clean