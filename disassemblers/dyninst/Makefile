CXXFLAGS= -O2 -std=c++11
LDFLAGS= -L/usr/local/lib -ldyninstAPI -lparseAPI -linstructionAPI -lsymtabAPI -lglog -lgflags -lprotobuf -lboost_system -lpthread

.PHONY: all

all: dyninstBlocks 

blocks.pb.cc: ../../protobuf_def/blocks.proto
        protoc --cpp_out=. --proto_path=../../protobuf_def/ blocks.proto

dyninstBlocks: dyninstBB.cpp blocks.pb.cc
	c++ $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	
clean:
	rm dyninstBlocks blocks.pb.cc blocks.pb.h
