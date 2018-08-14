#ifndef __OPEN_CL_RUNNER__
#define __OPEN_CL_RUNNER__

#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "Types.h"

#define __CL_ENABLE_EXCEPTIONS
#ifndef DEVICE
#define DEVICE CL_DEVICE_TYPE_DEFAULT
#endif

#include "cl.hpp"
#include "util.hpp" // utility library
#include "err_code.h"

using namespace std;

void brute_open_cl_cbc(vector<raw_pair*>* vec_keys, vector<raw_pair*>* vec_samples);

#endif
