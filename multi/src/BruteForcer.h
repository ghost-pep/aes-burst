#ifndef __BRUTE_FORCER_H__
#define __BRUTE_FORCER_H__

#include <string>
#include <vector>
#include <iostream>
#include <utility>
#include <algorithm>
#include "ctpl_stl.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "kmp-cpp.h"

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
	int num_threads;
};

typedef pair<CryptoPP::byte*, unsigned int> raw_pair;

string decode_hex(string encoded);
string decode_base64(string encoded);
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
		string iv;
		Mode mode;
		int num_threads;
		ctpl::thread_pool *pool;
		vector<string> *ciphertexts;
		vector<string> *one_block_ciphertexts;
		vector<string> *multi_block_ciphertexts;


		//decryption booleans
		//NOTE these should be combined into a struct to give them a consistent UX
		//TODO: set these in order to get pretty printouts and to validate which keys to add
		//to the results
		bool ecb_bad_decrypt = false;

		void test_ecb(string key, vector<string> *ciphertexts);
		void test_cbc(string key,
				vector<string> *one_block_ciphertexts,
				vector<string> *multi_block_ciphertexts);
		bool decrypt_and_check(CryptoPP::SymmetricCipher *cipher, string ciphertext);
		bool check_crib(string plaintext);
};


#endif
