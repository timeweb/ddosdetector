UNAME_S := $(shell uname -s)
CXX = g++-4.8

PROGS = controld ddosdetector
CLEANFILES = $(PROGS) *.o

LDFLAGS = -lboost_system
CPPFLAGS = -std=c++11 -Wall
ifeq ($(UNAME_S),Darwin)
CPPFLAGS += -I/usr/local/Cellar/boost/1.60.0_1/include
endif

all: $(PROGS)

controld: controld.o
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

ddosdetector: ddosdetector.o
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
