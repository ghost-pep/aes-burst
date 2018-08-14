// This will run through all of the keys in the list passed to it and brute force them

//define some hashcat consts to help inc_cipher_aes.cl
#ifndef __INC_AES_CIPHER_DEFS__
#define __INC_AES_CIPHER_DEFS__
#define u32a uint
#define u32 uint
#define SHM_TYPE __local
#define DECLSPEC inline
#endif

#ifndef KEYLEN
#define KEYLEN 4
#endif

#include "src/OpenCL/inc_cipher_aes.cl";

//define the metadata struct for use with indexing into samples
typedef struct tag_sample_metadata {
	uint index;
	uint size;
} sample_metadata;

//no crib needed because we can return all of the decrypted blocks
//also note that num_samples is fine because each sample will only test the last block for
//correct padding
__kernel void brute_aes_ecb(
		__global const uchar *keys,
		__global const uchar *samples,
		__global const sample_metadata *metadata,
		__global uchar *output,
		const int num_keys,
		const int num_samples) {
	//get ids -> may not be useful but this is how to abstract away loops
	int gid = get_global_id(0);
	int lid = get_local_id(0);
	//decrypt the key, sample pair based on which worker this is
	//first we need to get the key/sample pair by mod and casting division to an int
	/* const uint *key = keys + (gid * 4) % KEYLEN ; */
	/* const uint *sample = &samples[ (int) ( ((int) gid) / ((int) KEYLEN) ) ]; */
	
	//store the decrypted text back into the buffer

}
