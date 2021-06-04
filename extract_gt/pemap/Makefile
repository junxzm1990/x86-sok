CXX=g++
CXXFLAGS= -O2
LDFLAGS=-lcapstone -liberty -lprotobuf -lpthread -L/usr/local/lib

PEMap: PEMap.o blocks.o refInf.o
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

PEMap.o: PEMap.cpp blocks.pb.cc refInf.pb.cc
	$(CXX) -c -o $@ PEMap.cpp $(CXXFLAGS)

blocks.o: blocks.pb.cc
	$(CXX) -c -o $@ $^ $(CXXFLAGS)

refInf.o: refInf.pb.cc
	$(CXX) -c -o $@ $^ $(CXXFLAGS)

blocks.pb.cc: ../../protobuf_def/blocks.proto
	protoc --cpp_out=. --proto_path=../../protobuf_def/ blocks.proto

refInf.pb.cc: ../../protobuf_def/refInf.proto
	protoc --cpp_out=. --proto_path=../../protobuf_def/ refInf.proto


clean:
	-rm -f PEMap *.o *.pb.cc *.pb.h
