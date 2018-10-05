
CXX := g++

.PHONY: .all

all: dns-selector

dns-selector:
	$(CXX) -o dns-selector -std=c++11 -O3 main.cpp -s -lboost_system -lboost_program_options -pthread
