UNAME_S := $(shell uname -s)
CXX = g++-4.8

PROGS = ddosdetector
CLEANFILES = $(PROGS) *.o

LDFLAGS = -lboost_system -lboost_thread -llog4cpp -lboost_program_options -lpthread
CPPFLAGS = -std=c++11 -Wall -Wno-unused-variable
CPPFLAGS += -I ./sys

TESTS_LDFLAGS = -lgtest_main -lgtest $(LDFLAGS)
TESTS_CPPFILES = $(wildcard ./test/*.cpp)
TESTS_BIN = $(TESTS_CPPFILES:.cpp=)
TESTS_RUN = $(TESTS_CPPFILES:.cpp=.run)


ifeq ($(UNAME_S),Darwin)
	CPPFLAGS += -I/usr/local/Cellar/boost/1.60.0_1/include
endif

all: $(PROGS)

ddosdetector: functions.o collector.o parser.o rules.o controld.o ddosdetector.o
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

collector.o: collector.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

rules.o: rules.cpp 
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

parser.o: parser.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

controld.o: controld.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

functions.o: functions.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

# Testing
test: clean-test build-test run-test

check:
	@./test/cppcheck/cppcheck -q -j12 --platform=unix64 -itest --std=c++11 --enable=all --inconclusive --suppressions-list=./test/cppcheck_suppress.cfg ./

build-test: $(TESTS_BIN)
	@echo "====> Run tests <===="

%: %.cpp
	$(CXX) $(CPPFLAGS) $^ -o $@ $(TESTS_LDFLAGS)

run-test: $(TESTS_RUN)

%.run: %
	$^

clean-test:
	@echo "====> Clean all test <===="
	-@rm -rf $(TESTS_BIN)
	@echo "====> Build tests <===="
