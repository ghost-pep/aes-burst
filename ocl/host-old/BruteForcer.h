#ifndef __BRUTE_FORCER_H__
#define __BRUTE_FORCER_H__

#include <string>
#include <vector>
#include <iostream>
#include <utility>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>

#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "OpenCLRunner.h"
#include "Types.h"

using namespace std;

enum Mode {
	ECB,
	CBC,
	CTR,
	ALL
};

struct BruteBuilder {
	string crib;
	bool is_b64;
	string iv;
	Mode mode;
};

void decode_hex(string encoded, raw_pair *output);
void decode_base64(string encoded, raw_pair *output);
void print_pair(raw_pair *print_me);

class BruteForcer {
	public:
		BruteForcer(BruteBuilder *config);
		~BruteForcer();
		void brute_force(vector<string> *keys, vector<string> *samples);
	private:
		string crib;
		int crib_len;
		bool decode_b64;
		raw_pair* iv;
		Mode mode;

		//member functions
		/* void brute_open_cl_cbc(vector<raw_pair*>* keys, vector<raw_pair*>* samples); */
};

#endif
