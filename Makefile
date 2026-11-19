CXX = clang++
CXXFLAGS = -std=c++20 -O3 -Wall -Wextra -Wpedantic -pthread

all: generate analyze

generate: generate.cpp common.h
	$(CXX) $(CXXFLAGS) generate.cpp -o generate

analyze: analyze.cpp common.h
	$(CXX) $(CXXFLAGS) analyze.cpp -o analyze

test: all
	python3 tests.py

demo: all
	python3 demo.py

clean:
	rm -f generate analyze

.PHONY: all test demo clean
