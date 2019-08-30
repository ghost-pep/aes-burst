CC=clang
CXX=clang++
CFLAGS = -Wall -Wextra -O2
CXXFLAGS = $(CFLAGS) -std=c++0x -stdlib=libc++

CPP_COMMON= ./src/OpenCL/CppCommon/
INCLUDES += -I $(CPP_COMMON)

PLATFORM = $(shell uname -s)
LIBS = -lcryptopp -framework OpenCL 

all: simple multi

simple: simplebuild
	@echo Linking...;
	$(CXX) $(CXXFLAGS) -o aesburst-simple -lcryptopp ./simple/src/*.o
	 

simplebuild:
	@echo "====== Building simple implementation ======"
	cd simple/src && make && cd ../..;

multi: multibuild
	@echo Linking...;
	$(CXX) $(CXXFLAGS) -o aesburst-multi -lcryptopp ./multi/src/*.o

multibuild:
	@echo "====== Building multi implementation ======"
	cd multi && make && cd ../..;

clean:
	@echo "====== Cleaning ======"
	cd simple/src && make clean && cd ../..;
	rm -f aesburst-simple
	cd multi && make clean && cd ..;
	rm -f aesburst-multi



# "/Library/Developer/CommandLineTools/usr/bin/ld" -demangle -lto_library /Library/Developer/CommandLineTools/usr/lib/libLTO.dylib -no_deduplicate -dynamic -arch x86_64 -macosx_version_min 10.13.0 -o aesburst -lcryptopp -framework OpenCL ./src/host/AESBurst.o ./src/host/BruteForcer.o ./src/host/OpenCLRunner.o -lc++ -lSystem /Library/Developer/CommandLineTools/usr/lib/clang/9.1.0/lib/darwin/libclang_rt.osx.a
# $(CXX) $(CXXFLAGS) -v -o aesburst -lcryptopp $(OPENCL) ./src/host/*.o

