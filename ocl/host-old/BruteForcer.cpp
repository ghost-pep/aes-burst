#include "BruteForcer.h"

BruteForcer::BruteForcer(BruteBuilder *config) {
	//translate the config struct into private variables for the class
	crib_len = config->crib.size();
	/* cout << "crib_len is " << crib_len << endl; */
	crib = config->crib;
	decode_b64 = config->is_b64;
	//decode the IV and store as bytes rather than string
	if (!config->iv.empty()) {
		iv = new raw_pair();
		decode_hex(config->iv, iv);
	} else {
		iv = new raw_pair();
		iv->first = NULL;
		iv->second = 0;
	}
	mode = config->mode;
}

BruteForcer::~BruteForcer() {
	//dtor for cleanup of allocated variables
	if (iv->first) {
		delete iv->first;
	}
	delete iv;
}

void BruteForcer::brute_force(vector<string> *keys, vector<string> *samples) {

	//setup samples
	vector<raw_pair*> *ciphertexts
			= new vector<raw_pair*>();
	vector<raw_pair*> *one_block_ciphertexts
			= new vector<raw_pair*>();
	vector<raw_pair*> *multi_block_ciphertexts
			= new vector<raw_pair*>();

	for (auto sample_it = samples->begin(); sample_it != samples->end(); ++sample_it) {
		string sample = string(*sample_it);
		unsigned int sample_bytes_len;
		raw_pair* decoded_pair =
			new raw_pair();

		//decode sample
		if (decode_b64) {
			/* cout << "Decoding using base64." << endl; */
			decode_base64(sample, decoded_pair);
			sample_bytes_len = decoded_pair->second;
		} else {
			decode_hex(sample, decoded_pair);
			sample_bytes_len = decoded_pair->second;
		}

		//check for correct sample size
		/* cout << "Sample size: " << sample_bytes_len << endl; */
		if (sample_bytes_len % 16 != 0) {
			cout << "Incorrect sample sizes." << endl;
			exit(EXIT_FAILURE);
		}

		//populate CBC-mode structures
		if (sample_bytes_len == 16) {
			one_block_ciphertexts->push_back(decoded_pair);
			/* cout << "Identified as a single block ciphertext." << endl; */
		} else if (sample_bytes_len >16) {
			multi_block_ciphertexts->push_back(decoded_pair);
			/* cout << "Identified as a multi-block ciphertext." << endl; */
		}

		//populate the ciphertext vector
		/* cout << "Populating the ciphertexts vector with: " << decoded_pair->first << endl; */
		ciphertexts->push_back(decoded_pair);


	}

	//setup keys
	vector<raw_pair*> *keyset =
		new vector<raw_pair*>();
	for (auto key_it = keys->begin(); key_it != keys->end(); ++key_it) {
		//decode and push
		//note that the keys will be hex encoded ALWAYS
		/* cout << "Start key hex encoded: " << string(*key_it) << endl; */
		raw_pair* decoded_key = 
			new raw_pair();
		decode_hex(*key_it, decoded_key);
		/* cout << "Populating keyset with addr->first: " << decoded_key << endl; */
		/* cout << "\t" << (*decoded_key).first << endl; */
		keyset->push_back(decoded_key);
	}

	//brute force all keys now that samples and keys are setup
	//TODO: make this work with OpenCL
	/* for (auto key_it = keyset->begin(); key_it != keyset->end(); ++key_it) { */
	/* 	//All different modes */
	/* 	/1* bool cbc_result = true; *1/ */
	/* 	/1* bool ctr_result = true; *1/ */
	/* 	if (mode == ECB || mode == ALL) { */
	/* 		/1* cout << "Testing ECB Mode." << endl; *1/ */
	/* 		test_ecb(*key_it, ciphertexts); */
	/* 	} else if (mode == CBC || mode == ALL) { */
	/* 		/1* cout << "Testing CBC Mode." << endl; *1/ */
	/* 		test_cbc(*key_it, one_block_ciphertexts, multi_block_ciphertexts); */
	/* 	} else if (mode == CTR || mode == ALL) { */
	/* 		/1* cout << "Testing CTR Mode." << endl; *1/ */
	/* 	} */
	/* 	//cleanup the key after it has been used */
	/* 	delete (*key_it)->first; */
	/* 	delete *key_it; */
	/* } */

	brute_open_cl_cbc(keyset, ciphertexts);

	

	//cleanup
	delete keyset;
	for (auto cipher_it = ciphertexts->begin(); cipher_it != ciphertexts->end();
			++cipher_it) {
		delete (*cipher_it)->first;
		delete *cipher_it;
	}
	delete ciphertexts;
	delete one_block_ciphertexts;
	delete multi_block_ciphertexts;
}

/* void BruteForcer::test_ecb(raw_pair *key, vector<raw_pair*> *ciphertexts) { */
/* 	for (auto ciphertext_it = ciphertexts->begin(); ciphertext_it != ciphertexts->end(); ++ciphertext_it) { */
/* 		CryptoPP::ECB_Mode< CryptoPP::AES >::Decryption d; */
/* 		d.SetKey(key->first, key->second); */
/* 		CryptoPP::byte *ciphertext = (*ciphertext_it)->first; */
/* 		CryptoPP::byte *last_block = new CryptoPP::byte(CryptoPP::AES::BLOCKSIZE); */
/* 		unsigned int cipher_len = (*ciphertext_it)->second; */
/* 		if (crib_len == 0) { */
/* 			//if there is not a crib then we want to only use the last block of the */
/* 			//ciphertext */
/* 			for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) { */
/* 				last_block[i] = ciphertext[cipher_len - 16 + i]; */
/* 			} */
/* 			ciphertext = last_block; */
/* 			cipher_len = CryptoPP::AES::BLOCKSIZE; */
/* 		} */
/* 		bool decryption_ret = decrypt_and_check(&d, ciphertext, cipher_len); */
/* 		if (!decryption_ret) { */
/* 			ecb_bad_decrypt = true; */
/* 			delete last_block; */
/* 			break; */
/* 		} */
/* 		print_pair(key); */
/* 		delete last_block; */
/* 	} */
/* } */

void print_pair(raw_pair *print_me) {
	cout << "Printed bytes: ";
	for (int i = 0; i < print_me->second; i++) {
		cout << print_me->first[i];
	}
	cout << endl;
}

/* void BruteForcer::test_cbc(raw_pair *key, */
/* 		vector<raw_pair*> *one_block_ciphertexts, */
/* 		vector<raw_pair*> *multi_block_ciphertexts) { */
/* 	//last block with second to last as the "IV" to the decryption */
/* 	if (multi_block_ciphertexts->size() > 0) { */
/* 		for (auto pair_it = multi_block_ciphertexts->begin(); */
/* 				pair_it != multi_block_ciphertexts->end(); ++pair_it) { */
/* 			if (crib_len == 0) { */
/* 				CryptoPP::byte *ciphertext_full = (*pair_it)->first; */
/* 				unsigned int cipher_len = (*pair_it)->second; */
/* 				CryptoPP::byte *makeshift_iv = new CryptoPP::byte(CryptoPP::AES::BLOCKSIZE); */
/* 				//populate makeshift_iv as the previous block */
/* 				for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) { */
/* 					makeshift_iv[i] = ciphertext_full[cipher_len - 32 + i]; */
/* 				} */
/* 				CryptoPP::byte *ciphertext = new CryptoPP::byte(CryptoPP::AES::BLOCKSIZE); */
/* 				//populate ciphertext with the last block */
/* 				for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) { */
/* 					ciphertext[i] = ciphertext_full[cipher_len - CryptoPP::AES::BLOCKSIZE + i]; */
/* 				} */
/* 				try { */
/* 					CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption *d = */
/* 						new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(); */
/* 					d->SetKeyWithIV(key->first, key->second, makeshift_iv, CryptoPP::AES::BLOCKSIZE); */
/* 					if (!decrypt_and_check(d, ciphertext, CryptoPP::AES::BLOCKSIZE)) { */
/* 						delete makeshift_iv; */
/* 						delete d; */
/* 						delete ciphertext; */
/* 						//bad decryption */
/* 						//TODO: set bad decryption flag with final results interface */
/* 						break; */
/* 					} */
/* 					print_pair(key); */
/* 				} catch (const std::exception& e) { */
/* 					cout << "Error during decryption" << endl; */
/* 				} */
/* 				delete ciphertext; */
/* 				delete makeshift_iv; */

/* 			} else if (iv->second != 0) { */
/* 				try { */
/* 					CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption *d = */
/* 						new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(); */
/* 					d->SetKeyWithIV(key->first, key->second, iv->first, iv->second); */
/* 					if (!decrypt_and_check(d, (*pair_it)->first, (*pair_it)->second)) { */
/* 						delete d; */
/* 						//bad decryption for use of known IV */
/* 						//TODO: set flag */
/* 						break; */
/* 					} */
/* 					print_pair(key); */
/* 				} catch (const std::exception& e) { */
/* 					cout << "Error during decryption" << endl; */
/* 				} */

/* 			} else { */
/* 				//key is the IV here */
/* 				try { */
/* 					CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption *d = */
/* 						new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(); */
/* 					d->SetKeyWithIV(key->first, key->second, */
/* 							key->first, CryptoPP::AES::BLOCKSIZE); */
/* 					if (!decrypt_and_check(d, (*pair_it)->first, (*pair_it)->second)) { */
/* 						delete d; */
/* 						//bad decryption for use of key the IV */
/* 						//TODO: set flag */
/* 						break; */
/* 					} */
/* 					print_pair(key); */
/* 				} catch (const std::exception& e) { */
/* 					cout << "Error during decryption" << endl; */
/* 				} */

/* 			} */

/* 		} */

/* 	} else { */
/* 		//bad CBC decryption for multiblock structures */
/* 		//TODO: set flag */
/* 	} */


/* 	//one block samples for CBC mode */
/* 	if (one_block_ciphertexts->size() > 0) { */
/* 		if (iv->second != 0) { */
/* 			//TODO: set cbc_key_as_iv_bad_decrypt = True */
/* 			for (auto pair_it = one_block_ciphertexts->begin(); */
/* 					pair_it != one_block_ciphertexts->end(); ++pair_it) { */
/* 				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption *d = */
/* 					new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(); */
/* 				d->SetKeyWithIV(key->first, key->second, iv->first, iv->second); */
/* 				if (!decrypt_and_check(d, (*pair_it)->first, (*pair_it)->second)) { */
/* 					delete d; */
/* 					//bad decryption for use of key the IV */
/* 					//TODO: set flag */
/* 					break; */
/* 				} */
/* 				delete d; */

/* 			} */

/* 		} else { */
/* 			for (auto pair_it = one_block_ciphertexts->begin(); */
/* 					pair_it != one_block_ciphertexts->end(); ++pair_it) { */
/* 				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption *d = */
/* 					new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(); */
/* 				d->SetKeyWithIV(key->first, key->second, key->first, key->second); */
/* 				if (!decrypt_and_check(d, (*pair_it)->first, (*pair_it)->second)) { */
/* 					delete d; */
/* 					//bad decryption for use of key the IV */
/* 					//TODO: set flag */
/* 					break; */
/* 				} */
/* 				delete d; */

/* 			} */

/* 		} */

/* 	} else { */
/* 		//TODO: set flags cbc_known_iv_bad_decrypt = cbc_key_as_iv_bad_decrypt = True */
/* 	} */

/* } */

/* bool BruteForcer::decrypt_and_check(CryptoPP::SymmetricCipher *cipher, CryptoPP::byte *ciphertext, unsigned int cipher_len) { */
/* 	string plaintext; */
/* 	bool pkcs_fail = false; */
/* 	try { */
/* 		CryptoPP::StringSink *sink = new CryptoPP::StringSink(plaintext); */
/* 		CryptoPP::StreamTransformationFilter stfDecryptor(*cipher, sink); */
/* 		/1* cout << "CIPHERTEXT: "; *1/ */
/* 		/1* for (int i = 0; i < cipher_len; i++) { *1/ */
/* 		/1* 	cout << ciphertext[i]; *1/ */
/* 		/1* } *1/ */
/* 		/1* cout << endl; *1/ */
/* 		stfDecryptor.Put(ciphertext, cipher_len); */
/* 		stfDecryptor.MessageEnd(); */
/* 		delete sink; */
/* 	} catch (const CryptoPP::InvalidCiphertext &e){ */
/* 		pkcs_fail = true; */
/* 		cout << "PKCS7 Padding is invalid." << endl; */
/* 	} */
/* 	//check crib or pkcs7 padding */
/* 	/1* cout << "Decrypted text: " << plaintext << endl; *1/ */
/* 	bool result = !pkcs_fail; */
/* 	if (crib_len != 0) { */
/* 		/1* cout << "Checking crib" << endl; *1/ */
/* 		result = check_crib(plaintext); */
/* 		return result; */
/* 	} */
/* 	if (result) { */
/* 		cout << "POTENTIAL CANDIDATE" << endl; */
/* 	} */
/* 	return result; */
/* } */

/* bool BruteForcer::check_crib(string plaintext) { */
/* 	//use KMP string searching algorithm to find whether the crib is in the plaintext */
/* 	//https://github.com/santazhang/kmp-cpp */
/* 	kmp::pattern<string::const_iterator> kmp(crib.begin(), crib.end()); */
/* 	long crib_loc = kmp.match_first(plaintext.begin(), plaintext.end()); */
/* 	if (crib_loc >= 0) { */
/* 		cout << "POTENTIAL CANDIDATE" << endl; */
/* 		return true; */
/* 	} */
/* 	return false; */
/* } */

void decode_hex(string encoded, raw_pair* output) {

	string decoded;
	   
	CryptoPP::HexDecoder decoder;
	decoder.Put( (CryptoPP::byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();

	CryptoPP::word64 size = decoder.MaxRetrievable();
	if(size && size <= SIZE_MAX) {
		decoded.resize(size);		
		decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size());
	}
	output->first = new CryptoPP::byte(size);
	copy(decoded.data(), decoded.data() + decoded.size(), output->first);
	output->second = decoded.size();
	/* cout << "Decoded " << encoded << " to " << decoded << endl; */
	/* cout << "Size: " << decoded.size() << endl; */

}

void decode_base64(string encoded, raw_pair* output) {

	string decoded;
	   
	CryptoPP::Base64Decoder decoder;
	decoder.Put( (CryptoPP::byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();

	CryptoPP::word64 size = decoder.MaxRetrievable();
	if(size && size <= SIZE_MAX) {
		decoded.resize(size);		
		decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size());
	}
	output->first = new CryptoPP::byte(size);
	copy(decoded.data(), decoded.data() + decoded.size(), output->first);
	output->second = decoded.size();
	/* cout << "Decoded " << encoded << " to " << decoded << endl; */
	/* cout << "Size: " << decoded.size() << endl; */

}
