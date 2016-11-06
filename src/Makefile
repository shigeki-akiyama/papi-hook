
CXX       := g++
LD        := g++
CXXFLAGS  := -std=c++11 -fPIE -Wall -Wextra $(CXXFLAGS)
LDFLAGS   := -pie -rdynamic $(LDFLAGS)
LDLIBS    := -lpapi -ldl

output  = papi-hook
objects = papi-hook.o

sample  = a.out

.PHONY: all clean

all : $(output)

clean :
	rm -f $(output) $(objects) $(sample)

$(output) : $(objects)
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(sample) : sample.cc
	$(CXX) -finstrument-functions -rdynamic -o $@ $^

