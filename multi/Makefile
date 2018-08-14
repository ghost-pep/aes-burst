CC=clang
CXX=clang++
CFLAGS = -Wall -Wextra -O2
CXXFLAGS = $(CFLAGS) -std=c++11

SRCS=$(wildcard src/*.cpp)
OBJS=$(subst .cpp,.o,$(SRCS))

all: $(OBJS)
	@echo Compiling AES Burst

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS)
