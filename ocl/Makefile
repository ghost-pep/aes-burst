
ifndef CPPC
	CPPC=g++
endif

CPP_COMMON = ./OpenCL/CppCommon

CCFLAGS=

INC = -I $(CPP_COMMON)

LIBS = -lOpenCL -lrt -lcryptopp


# Check our platform and make sure we define the APPLE variable
# and set up the right compiler flags and libraries
PLATFORM = $(shell uname -s)
ifeq ($(PLATFORM), Darwin)
	CPPC = clang++
	CCFLAGS += -stdlib=libc++
	LIBS = -framework OpenCL -lcryptopp
endif

aesburst-ocl: oclaesburst.cpp
	$(CPPC) $^ $(INC) $(CCFLAGS) $(LIBS) -o ../$@


clean:
	rm -f ../oclaesburst
