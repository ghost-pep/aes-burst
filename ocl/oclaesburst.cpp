#define __CL_ENABLE_EXCEPTIONS

#include "cl.hpp"
#include "util.hpp"


#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <iostream>
#include <fstream>

#include <getopt.h>

#include "err_code.h"
#include "device_picker.hpp"
#include "cryptopp/hex.h"

#define u32 unsigned int
#define bbyte unsigned char
#define KEYLENGTH 4

using namespace std;

typedef std::pair<CryptoPP::byte *, unsigned int> raw_pair;

typedef struct tag_sample_metadata {
	cl_uint index;
	cl_uint size;
} sample_metadata;

string decode_hex(string encode);
int bruteforce(vector<string> *keys,
		vector<string> *samples,
		vector<sample_metadata*> *metadata,
		int devid);
u32 createU32(bbyte a, bbyte b, bbyte c, bbyte d);

void usage(const char *name) {
	cout << "Usage: " << name << " [OPTIONS] <keylist> <sample_file>" << endl;
	cout << "\tOptions:" << endl;
	cout << "\t\t-c, --crib <crib text>" << endl;
	cout << "\t\t-e, --encoding <hex or b64>" << endl;
	cout << "\t\t-i, --initialization_vector <vector>" << endl;
	cout << "\t\t-m, --mode <ECB, CBC, CTR>" << endl;
	cout << "\t\t-l, --list\t\tshow a list of OpenCL devices" << endl;
	std::cout << "\t\t-d, --device     INDEX   Select device at INDEX\n";
}

int main(int argc, char *argv[])
{
	//handle arguments
	//TODO: fix getopt
	if (argc < 3) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	char *keylist_filename = argv[argc - 2];
	char *samples_filename = argv[argc - 1];

	const char *optstring = "c:e:i:m:l:d:";
	const struct option long_options[] = {
		{"initialization_vector", 	0, 	0, 	'i'},
		{"crib", 					0, 	0, 	'c'},
		{"encoding", 				0, 	0, 	'e'},
		{"mode", 					0, 	0, 	'm'},
		{"list", 					0, 	0, 	'l'},
		{"device", 					0, 	0, 	'd'},
		{0, 						0,	0, 	0}
	};

	char c;
	int option_index = 0;



	//init the configuration struct
	//this struct is passed to the library to specify how to brute force
	struct BruteBuilder {
		string crib;
		bool is_b64;
		string iv;
		string mode;
		int deviceid;
	} brutecfg;
	BruteBuilder *config = &brutecfg;
	config->crib = "";
	config->is_b64 = false;
	config->iv = "";
	config->mode = "ALL";
	config->deviceid = -1;
	while ((c = getopt_long(argc, argv, optstring, long_options, &option_index)) != EOF) {
		/* if (!optarg) { */
		/* 	cout << "Flag must be provided with an argument." << endl; */
		/* 	exit(EXIT_FAILURE); */
		/* } */
		string optargstr = string(optarg);
		switch (c) {
			case 'c':
				/* cout << "Setting crib to be " << optarg << endl; */
				config->crib = optargstr;
				break;

			case 'e':
				if (optargstr == "hex") {
					/* cout << "Choosing hex encoding." << endl; */
					config->is_b64 = false;
				} else if (optargstr == "b64") {
					/* cout << "Choosing base 64 encoding." << endl; */
					config->is_b64 = true;
				} else {
					/* cout << "Could not understand encoding. Please use 'hex' or 'b64'." */
						/* << endl << "Defaulting to 'hex' encoding." << endl; */
				}
				break;

			case 'i':
				/* cout << "Setting Initialization Vector to be " << optargstr << "." << endl; */
				config->iv = optargstr; //NOTE: this does not care about the null byte because IVs are always 16 bytes in AES
				break;

			case 'm':
				/* cout << "Setting mode to be " << optargstr << "." << endl; */
				if (optargstr == "ECB") {
					config->mode = optargstr;
				} else if (optargstr == "CBC") {
					config->mode = optargstr;
				} else if (optargstr == "CTR") {
					config->mode = optargstr;
				}
				break;

			case 'l': {
				// Get list of devices
				std::vector<cl::Device> devices;
				unsigned numDevices = getDeviceList(devices);

				// Print device names
				if (numDevices == 0)
			    {
				  std::cout << "No devices found.\n";
			    }
			    else
			    {
				  std::cout << "\nDevices:\n";
				  for (int i = 0; i < numDevices; i++)
				  {
				    std::string name;
				    getDeviceName(devices[i], name);
				    std::cout << i << ": " << name << "\n";
				  }
				  std::cout << "\n";
			    }
				break;
			}

			case 'd': 
			{
				config->deviceid = std::stoi(optargstr);
				cout << "set deviceid to " << config->deviceid << endl;
				break;
		    }
		}
	}
	
	//open files
	ifstream handle_keylist(keylist_filename);
	if (!handle_keylist.is_open()) {
		cout << "Could not open keylist." << endl;
		exit(EXIT_FAILURE);
	}

	ifstream handle_samples(samples_filename);
	if (!handle_samples.is_open()) {
		cout << "Could not open the samples file." << endl;
		exit(EXIT_FAILURE);
	}

	//initialize keys and samples on the heap
	vector<string> *keys = new vector<string>;
	vector<string> *samples = new vector<string>;
	vector<sample_metadata*> *metadata = new vector<sample_metadata*>;

	//populate keys and samples
	string line;
	cout << "Creating keys" << endl;
	while (getline(handle_keylist, line)) {

		//decode
		string decoded = decode_hex(line);
		keys->push_back(decoded);
	}
	handle_keylist.close();

	cout << "Creating samples and its metadata" << endl;
	cl_uint cur_index = 0;
	while (getline(handle_samples, line)) {

		//decode the line
		string decoded = decode_hex(line);

		//populate the metadata structure
		sample_metadata *line_meta = new sample_metadata;
		line_meta->index = cur_index;
		line_meta->size = decoded.size();

		//update the current index for the handling of the next line
		cur_index += (cl_int) line_meta->size;

		//push to the vectors
		metadata->push_back(line_meta);
		samples->push_back(decoded);
	}
	handle_samples.close();

	//actually try to brute force
	int err = bruteforce(keys, samples, metadata, config->deviceid);

	//cleanup
	delete keys;
	delete samples;
	delete metadata;
}

// ==================================================================================================== //
int bruteforce(vector<string> *keys,
		vector<string> *samples,
		vector<sample_metadata*> *metadata,
		int devid) {

	cl::Buffer d_keys;
	cl::Buffer d_ciphertexts;
	cl::Buffer d_metadata;
	cl::Buffer d_output;

	cl::Program program;

	cl::Device device;
	vector<cl::Device> devices;

	//calculate the size of all of the samples together so we can size the samples input buffer
	size_t num_sample_chars = 0;
	for (auto sample_it = samples->begin(); sample_it != samples->end(); ++sample_it) {
		string sample = *sample_it;
		num_sample_chars += sample.size();
	}
	//calculate the same for h_keys
	size_t num_key_chars = keys->size() * keys->begin()->size();

    try
    {
        cl_uint deviceIndex = (cl_uint) devid;
		//NOTE: above command uses the first one... in the future we can set this to be
		//the device index that they choose through the config

		cout << "Getting devices..." << endl;
        // Get list of devices
        unsigned numDevices = getDeviceList(devices);

        // Check device index in range
        if (deviceIndex >= numDevices)
        {
          std::cout << "Invalid device index (try '--list')\n";
          return EXIT_FAILURE;
        }

        device = devices[deviceIndex];

        std::string name;
        getDeviceName(device, name);
        std::cout << "\nUsing OpenCL device: " << name << "\n";

        std::vector<cl::Device> chosen_device;
        chosen_device.push_back(device);
        cl::Context context(chosen_device);
        cl::CommandQueue queue(context, device);

		cout << "Starting the loading of the kernel..." << endl;

        // Create the program object
        program = cl::Program(context, util::loadProgram("./ocl/OpenCL/brute_aes_ecb.cl"), true);

		/* string buildlog; */
		/* program.getBuildInfo<CL_PROGRAM_BUILD_LOG> (program, device, CL_PROGRAM_BUILD_LOG, buildlog); */ 
		/* cout << endl << "Build Log:" << endl << buildlog << endl << endl; */

		cout << "Loaded the program...now initializing the kernel object..." << endl;

        // Create the kernel object for quering information if needed
        cl::Kernel kernel(program, "brute_aes_ecb");

		cout << "Starting brute_aes.cl kernel build..." << endl;

        cl::make_kernel<const cl::Buffer, const cl::Buffer, cl::Buffer, cl_uint, cl_uint> brute_aes_ecb(
				program,
				"brute_aes_ecb"
				);

		//setup device memory
		d_keys = cl::Buffer(context, CL_MEM_READ_ONLY, num_key_chars);
		d_ciphertexts = cl::Buffer(context, CL_MEM_READ_ONLY, num_sample_chars);
		d_metadata = cl::Buffer(context, CL_MEM_READ_ONLY,
				metadata->size() * sizeof(sample_metadata));
		//this is for each key that is a potential candidate
		d_output = cl::Buffer(context, CL_MEM_WRITE_ONLY, num_key_chars);

		cout << "Finished setting up device memory and kernel creation...Starting kernel..."
			<< endl;

        util::Timer timer;

        // Execute the kernel over the entire range of our 1d input data set
        // using the maximum number of work group items for this device
        brute_aes_ecb(
            cl::EnqueueArgs(
                    queue,
                    cl::NDRange(num_sample_chars * num_key_chars)
				),
            d_keys,
			d_ciphertexts,
			d_output,
			num_key_chars,
			num_sample_chars
		);

        /* cl::copy(queue, d_output, h_keys->begin(), h_keys->end()); */

        //rtime = wtime() - rtime;
        double rtime = static_cast<double>(timer.getTimeMilliseconds()) / 1000.;
        printf("\nThe calculation ran in %lf seconds\n", rtime);

	} catch (cl::Error err) {
		std::cout << "Exception\n";
		std::cerr
		<< "ERROR: "
		<< err.what()
		<< "("
		<< err_code(err.err())
		<< ")"
		<< std::endl;
		if (err.err() == CL_BUILD_PROGRAM_FAILURE) {
			cout << "trying all devices" << endl;
			cl::Device dev = device;
			// Check the build status
			cl_build_status status = program.getBuildInfo<CL_PROGRAM_BUILD_STATUS>(dev);
			if (status != CL_BUILD_ERROR)
				cout << "was not a build error???" << endl;

			// Get the build log
			std::string name     = dev.getInfo<CL_DEVICE_NAME>();
			std::string buildlog = program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(dev);
			std::cerr << "Build log for " << name << ":" << std::endl
					<< buildlog << std::endl;
		}
	}
}

string decode_hex(string encoded) {

	string decoded;
	/* cout << "Encoded string: " << encoded << endl; */
	
	CryptoPP::StringSource ss(encoded, true,
			new CryptoPP::HexDecoder(
				new CryptoPP::StringSink(decoded)));
	   
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

u32 createU32(bbyte a, bbyte b, bbyte c, bbyte d) {

	u32 left1 = ((u32) a) << 24;
	u32 left2 = ((u32) b) << 16;
	u32 right1 = ((u32) c) << 8;
	u32 right2 = (u32) d;

	u32 retval = left1 ^ left2 ^ right1 ^ right2;

	return retval;
}
