
CXX       := g++
LD        := g++
CXXFLAGS  := -g3 -std=c++11 -fPIE -Wall -Wextra $(CXXFLAGS)
LDFLAGS   := -pie -rdynamic $(LDFLAGS)
LDLIBS    := -lpapi -ldl

output  = papi-hook
objects = papi-hook.o

sample  = a.out

.PHONY: all clean

all : $(output) $(sample)

clean :
	rm -f $(output) $(objects) $(sample)

$(output) : $(objects)
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(sample) : sample.cc
	$(CXX) -g3 -finstrument-functions -rdynamic -o $@ $^

