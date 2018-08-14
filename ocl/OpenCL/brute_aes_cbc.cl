// This will run through all of the keys in the list passed to it and brute force them

//define some hashcat consts to help inc_cipher_aes.cl
#define SHM_TYPE __local
#define DECLSPEC inline

#include "src/OpenCL/inc_cipher_aes.cl";

//TODO: implement CBC mode rather than doing a vector copy
__kernel void brute_aes_cbc(
		__global const char *crib,
		__global const uint *init_vec,
		__global const uint *keys,
		__global uint *samples,
		const int count) {

	int i = get_global_id(0);
	if (i < count) {
		samples[i] = keys[i];
	}
}
