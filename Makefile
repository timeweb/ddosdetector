UNAME_S := $(shell uname -s)
CXX = g++-4.8

PROGS = ddosdetector
CLEANFILES = $(PROGS) *.o

LDFLAGS = -lboost_system -lboost_thread -llog4cpp -lboost_program_options -lpthread
CPPFLAGS = -std=c++11 -Wall
CPPFLAGS += -I ./sys -I ./proto

TESTS_LDFLAGS = -lgtest_main -lgtest $(LDFLAGS)
TESTS_CPPFILES = $(wildcard ./test/*.cpp)
TESTS_BIN = $(TESTS_CPPFILES:.cpp=)
TESTS_RUN = $(TESTS_CPPFILES:.cpp=.run)


ifeq ($(UNAME_S),Darwin)
	CPPFLAGS += -I/usr/local/Cellar/boost/1.60.0_1/include
endif

all: $(PROGS)

ddosdetector: exceptions.o functions.o collector.o parser.o action.o controld.o baserule.o ip.o tcp.o udp.o icmp.o rules.o  ddosdetector.o
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

exceptions.o: exceptions.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

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

action.o: action.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

tcp.o: proto/tcp.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

udp.o: proto/udp.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

icmp.o: proto/icmp.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

ip.o: proto/ip.cpp
	$(CXX) $(CPPFLAGS) -c $^ -o $@ $(LDFLAGS)

baserule.o: proto/baserule.cpp
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
