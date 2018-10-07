CXX      ?= g++
CXXFLAGS ?= -std=c++11 -O3
LDFLAGS  ?= -lboost_system -lboost_program_options -pthread

.PHONY: .all

all: dns-selector

dns-selector: main.cpp utils.hpp
	$(CXX) -o dns-selector $(CXXFLAGS) main.cpp $(LDFLAGS)

clean: 
	rm dns-selector
