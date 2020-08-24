CXXFLAGS= -O2 -std=c++11
LDFLAGS= -L/usr/local/lib -ldyninstAPI -lparseAPI -linstructionAPI -lsymtabAPI -lglog -lgflags -lprotobuf -lboost_system -lpthread

.PHONY: all

all: dyninstBlocks 

dyninstBlocks: dyninstBB.cpp blocks.pb.cc
	c++ $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	
clean:
	rm dyninstBlocks
