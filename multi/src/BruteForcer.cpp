#include "BruteForcer.h"

using namespace std;

BruteForcer::BruteForcer(BruteBuilder *config) {
  // translate the config struct into private variables for the class
  crib_len = config->crib.size();
  cout << "crib_len is " << crib_len << endl;
  crib = config->crib;
  decode_b64 = config->is_b64;
  // decode the IV and store as bytes rather than string
  if (!config->iv.empty()) {
    iv = decode_hex(config->iv);
  } else {
    iv = string();
  }
  mode = config->mode;
  num_threads = config->num_threads;
  // create the private threadpool
  pool = new ctpl::thread_pool(num_threads);
  // setup private memory
  ciphertexts = new vector<string>();
  one_block_ciphertexts = new vector<string>();
  multi_block_ciphertexts = new vector<string>();
}

BruteForcer::~BruteForcer() {
  // dtor for cleanup of allocated variables
  // TODO: make sure all threads are exited
  delete pool;
  // now we can delete the private memory
  delete ciphertexts;
  delete one_block_ciphertexts;
  delete multi_block_ciphertexts;
}

void BruteForcer::brute_force(vector<string> *keys, vector<string> *samples) {

  // setup samples

  for (auto sample_it = samples->begin(); sample_it != samples->end();
       ++sample_it) {
    string sample = string(*sample_it);
    string decoded;

    // decode sample
    if (decode_b64) {
      /* cout << "Decoding using base64." << endl; */
      decoded = decode_base64(sample);
    } else {
      decoded = decode_hex(sample);
    }

    // check for correct sample size
    /* cout << "Sample size: " << sample_bytes_len << endl; */
    if (decoded.size() % 16 != 0) {
      cout << "Incorrect sample sizes." << endl;
      exit(EXIT_FAILURE);
    }

    /* cout << "Decoded to: " << decoded << endl; */

    // populate CBC-mode structures
    if (decoded.size() == 16) {
      one_block_ciphertexts->push_back(decoded);
      /* cout << "Identified as a single block ciphertext." << endl; */
    } else if (decoded.size() > 16) {
      multi_block_ciphertexts->push_back(decoded);
      /* cout << "Identified as a multi-block ciphertext." << endl; */
    }

    // populate the ciphertext vector
    /* cout << "Populating the ciphertexts vector with: " << decoded_pair->first
     * << endl; */
    ciphertexts->push_back(decoded);
  }

  // setup keys and decrypt/check based on mode
  vector<string> *ciphertexts_cpy = ciphertexts;
  vector<string> *one_block_ciphertexts_cpy = one_block_ciphertexts;
  vector<string> *multi_block_ciphertexts_cpy = multi_block_ciphertexts;
  Mode mode_cpy = mode;
  for (auto key_it = keys->begin(); key_it != keys->end(); ++key_it) {
    // pass a lambda job to the thread pool
    string key = (*key_it);
    pool->push( // lambda below that captures the key and sample vectors
        [key, ciphertexts_cpy, one_block_ciphertexts_cpy,
         multi_block_ciphertexts_cpy, mode_cpy, this](int id) {
          // TODO: THIS SHIT BE BUSTED FOR ALL YO but im too lazy to fix
          string decoded_key = decode_hex(key);
          if (mode_cpy == ECB || mode_cpy == ALL) {
            /* cout << "Testing ECB Mode." << endl; */
            test_ecb(decoded_key, ciphertexts_cpy);
            /* cout << "Finished testing with ECB mode_cpy" << endl; */
          } else if (mode_cpy == CBC || mode_cpy == ALL) {
            /* cout << "Testing CBC Mode." << endl; */
            test_cbc(decoded_key, one_block_ciphertexts_cpy,
                     multi_block_ciphertexts_cpy);
          } else if (mode_cpy == CTR || mode_cpy == ALL) {
            /* cout << "Testing CTR Mode." << endl; */
          }
        });
    /* string decoded_key = decode_hex(*key_it); */
    /* if (mode == ECB || mode == ALL) { */
    /* 	/1* cout << "Testing ECB Mode." << endl; *1/ */
    /* 	test_ecb(decoded_key, ciphertexts); */
    /* 	/1* cout << "Finished testing with ECB mode" << endl; *1/ */
    /* } else if (mode == CBC || mode == ALL) { */
    /* 	/1* cout << "Testing CBC Mode." << endl; *1/ */
    /* 	test_cbc(decoded_key, one_block_ciphertexts, multi_block_ciphertexts);
     */
    /* } else if (mode == CTR || mode == ALL) { */
    /* 	/1* cout << "Testing CTR Mode." << endl; *1/ */
    /* } */
    /* /1* cout << "Finished with a key" << endl; *1/ */
  }

  // cleanup
  /* delete ciphertexts; */
  /* delete one_block_ciphertexts; */
  /* delete multi_block_ciphertexts; */

  // wait for the thread pool to finish synchronously
  pool->stop(true);
}

void BruteForcer::test_ecb(string key, vector<string> *ciphertexts) {
  for (auto ciphertext_it = ciphertexts->begin();
       ciphertext_it != ciphertexts->end(); ++ciphertext_it) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey((CryptoPP::byte *)key.data(), key.size());
    /* cout << "CIPHERTEXT FROM VECTOR: " << (*ciphertext_it) << endl; */
    CryptoPP::byte *ciphertext = (CryptoPP::byte *)(*ciphertext_it).data();
    CryptoPP::byte last_block[16];
    unsigned int cipher_len = (*ciphertext_it).size();
    string decryptme = (*ciphertext_it);
    if (crib_len == 0) {
      // if there is not a crib then we want to only use the last block of the
      // ciphertext
      for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
        last_block[i] = ciphertext[cipher_len - 16 + i];
      }
      ciphertext = last_block;
      cipher_len = CryptoPP::AES::BLOCKSIZE;
      string decryptmenew((char *)ciphertext, cipher_len);
      decryptme = decryptmenew;
    }
    bool decryption_ret = decrypt_and_check(&d, decryptme);
    /* cout << "Finished decrypt and check and got a bool " << endl; */
    if (!decryption_ret) {
      /* cout << "Bad decryption" << endl; */
      ecb_bad_decrypt = true;
      return;
    }
    cout << "POTENTIAL CANDIDATE: " << key << endl;
  }
}

void print_pair(raw_pair *print_me) {
  cout << "Printed bytes: ";
  for (unsigned int i = 0; i < print_me->second; i++) {
    cout << print_me->first[i];
  }
  cout << endl;
}

void BruteForcer::test_cbc(string key, vector<string> *one_block_ciphertexts,
                           vector<string> *multi_block_ciphertexts) {
  // last block with second to last as the "IV" to the decryption
  if (multi_block_ciphertexts->size() > 0) {
    for (auto str_it = multi_block_ciphertexts->begin();
         str_it != multi_block_ciphertexts->end(); ++str_it) {
      if (crib.empty()) {
        string whole_cipher = *str_it;
        // populate makeshift_iv as the previous block
        string makeshift_iv = whole_cipher.substr(whole_cipher.size() - 32,
                                                  CryptoPP::AES::BLOCKSIZE);

        // populate ciphertext with the last block
        string ciphertext = whole_cipher.substr(whole_cipher.size() - 16,
                                                CryptoPP::AES::BLOCKSIZE);

        try {
          CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
          d.SetKeyWithIV((CryptoPP::byte *)key.data(), key.size(),
                         (CryptoPP::byte *)makeshift_iv.data(),
                         makeshift_iv.size());
          if (!decrypt_and_check(&d, ciphertext)) {
            // bad decryption
            // TODO: set bad decryption flag with final results interface
            break;
          }
          cout << "POTENTIAL CANDIDATE: " << key << endl;
        } catch (const std::exception &e) {
          cout << "Error during decryption" << endl;
        }

      } else if (!iv.empty()) {
        try {
          CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
          d.SetKeyWithIV((CryptoPP::byte *)key.data(), key.size(),
                         (CryptoPP::byte *)iv.data(), iv.size());
          if (!decrypt_and_check(&d, *str_it)) {
            // bad decryption for use of known IV
            // TODO: set flag
            break;
          }
          cout << "POTENTIAL CANDIDATE: " << key << endl;
        } catch (const std::exception &e) {
          cout << "Error during decryption" << endl;
        }

      } else {
        // key is the IV here
        try {
          CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
          d.SetKeyWithIV((CryptoPP::byte *)key.data(), key.size(),
                         (CryptoPP::byte *)key.data(), key.size());
          if (!decrypt_and_check(&d, *str_it)) {
            // bad decryption for use of key the IV
            // TODO: set flag
            break;
          }
          cout << "POTENTIAL CANDIDATE: " << key << endl;
        } catch (const std::exception &e) {
          cout << "Error during decryption" << endl;
        }
      }
    }

  } else {
    // bad CBC decryption for multiblock structures
    // TODO: set flag
  }

  // one block samples for CBC mode
  if (one_block_ciphertexts->size() > 0) {
    if (!iv.empty()) {
      // TODO: set cbc_key_as_iv_bad_decrypt = True
      for (auto str_it = one_block_ciphertexts->begin();
           str_it != one_block_ciphertexts->end(); ++str_it) {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV((CryptoPP::byte *)key.data(), key.size(),
                       (CryptoPP::byte *)iv.data(), iv.size());
        if (!decrypt_and_check(&d, *str_it)) {
          // bad decryption for use of key the IV
          // TODO: set flag
          break;
        }
        cout << "POTENTIAL CANDIDATE: " << key << endl;
      }

    } else {
      for (auto str_it = one_block_ciphertexts->begin();
           str_it != one_block_ciphertexts->end(); ++str_it) {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        // set with key as IV
        d.SetKeyWithIV((CryptoPP::byte *)key.data(), key.size(),
                       (CryptoPP::byte *)key.data(), key.size());
        if (!decrypt_and_check(&d, *str_it)) {
          // bad decryption for use of key the IV
          // TODO: set flag
          break;
        }
        cout << "POTENTIAL CANDIDATE: " << key << endl;
      }
    }
  } else {
    // TODO: set flags cbc_known_iv_bad_decrypt = cbc_key_as_iv_bad_decrypt =
    // True
  }
}

bool BruteForcer::decrypt_and_check(CryptoPP::SymmetricCipher *cipher,
                                    string ciphertext) {
  /* cout << "Decrypting and checking" << endl; */
  string plaintext;
  /* vector<CryptoPP::byte> recovered; */
  /* recovered.resize(CryptoPP::AES::BLOCKSIZE); */
  bool retval = false;
  if (crib_len != 0) {
    try {

      // decrypt
      CryptoPP::StringSource cribsource(
          ciphertext, true,
          new CryptoPP::StreamTransformationFilter(
              *cipher, new CryptoPP::StringSink(plaintext),
              CryptoPP::StreamTransformationFilter::NO_PADDING));
      /* cout << "PLAINTEXT: " << plaintext << endl; */

      /* exit(EXIT_FAILURE); */

      /* CryptoPP::StreamTransformationFilter stfDecryptor_crib(*cipher,
       * &cribsink,
       * CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING); */
      /* cout << "CIPHERTEXT: "; */
      /* for (int i = 0; i < cipher_len; i++) { */
      /* cout << ciphertext[i]; */
      /* } */
      /* cout << endl; */
      /* stfDecryptor_crib.Put(ciphertext, cipher_len); */
      /* stfDecryptor_crib.MessageEnd(); */
      /* cout << "Decrypted text: " << plaintext << endl; */
      /* cout << "Checking crib" << endl; */
      bool result = check_crib(plaintext);
      /* cout << "Finished running kmp" << endl; */
      /* if (!result) { */
      /* cout << "Crib not found" << endl; */
      /* } */
      retval = result;
    } catch (const CryptoPP::Exception &e) {
      retval = false;
      cout << "Error while decrypting" << endl;
    }

  } else {
    /* cout << "Testing PKCS7 padding" << endl; */
    try {
      CryptoPP::StringSource cribsource(
          ciphertext, true,
          new CryptoPP::StreamTransformationFilter(
              *cipher, new CryptoPP::StringSink(plaintext)));
      /* cout << "PLAINTEXT: " << plaintext << endl; */
      // This means that we succeeded in passing the padding error
      retval = true;
    } catch (const CryptoPP::Exception &e) {
      retval = false;
      /* cout << "PKCS7 Padding is invalid." << endl; */
    }
    /* cout << "Decrypted text: " << plaintext << endl; */
    /* if (retval) { */
    /* 	cout << "POTENTIAL CANDIDATE" << endl; */
    /* } */
  }
  /* cout << "Returning with " << retval << endl; */
  return retval;
}

bool BruteForcer::check_crib(string plaintext) {
  // use KMP string searching algorithm to find whether the crib is in the
  // plaintext https://github.com/santazhang/kmp-cpp
  /* cout << "Running kmp" << endl; */
  kmp::pattern<string::const_iterator> kmp(crib.begin(), crib.end());
  long crib_loc = kmp.match_first(plaintext.begin(), plaintext.end());
  if (crib_loc >= 0) {
    /* cout << "POTENTIAL CANDIDATE" << endl; */
    return true;
  }
  return false;
}

string decode_hex(string encoded) {

  string decoded;
  /* cout << "Encoded string: " << encoded << endl; */

  CryptoPP::StringSource ss(
      encoded, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));

  /* CryptoPP::HexDecoder decoder; */
  /* decoder.Put( (CryptoPP::byte*)encoded.data(), encoded.size() ); */
  /* decoder.MessageEnd(); */

  /* CryptoPP::word64 size = decoder.MaxRetrievable(); */
  /* if(size && size <= SIZE_MAX) { */
  /* 	decoded.resize(size); */
  /* 	decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size()); */
  /* } */
  /* cout << "Decoded: " << decoded << endl; */
  return decoded;
}

string decode_base64(string encoded) {

  string decoded;

  CryptoPP::StringSource ss(
      encoded, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));

  /* CryptoPP::Base64Decoder decoder; */
  /* decoder.Put( (CryptoPP::byte*)encoded.data(), encoded.size() ); */
  /* decoder.MessageEnd(); */

  /* CryptoPP::word64 size = decoder.MaxRetrievable(); */
  /* if(size && size <= SIZE_MAX) { */
  /* 	decoded.resize(size); */
  /* 	decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size()); */
  /* } */
  /* output->first = new CryptoPP::byte(decoded.size()); */
  /* copy(decoded.data(), decoded.data() + decoded.size(), output->first); */
  /* output->second = decoded.size(); */
  /* cout << "Decoded " << encoded << " to " << decoded << endl; */
  /* cout << "Size: " << decoded.size() << endl; */
  return decoded;
}
