CXX=g++
CXXFLAGS= -O2
LDFLAGS=-lcapstone -liberty -lprotobuf -lpthread -L/usr/local/lib

PEMap: PEMap.o blocks.o refInf.o
	$(CXX) -o $@ $^ $(LDFLAGS) $(CXXFLAGS)

PEMap.o: PEMap.cpp
	$(CXX) -c -o $@ $^ $(CXXFLAGS)

blocks.o: blocks.pb.cc
	$(CXX) -c -o $@ $^ $(CXXFLAGS)

refInf.o: refInf.pb.cc
	$(CXX) -c -o $@ $^ $(CXXFLAGS)

clean:
	-rm -f PEMap *.o
