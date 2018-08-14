#include<string>
#include<iostream>
#include<fstream>
#include<vector>
#include <getopt.h>
#include "BruteForcer.h"

using namespace std;

void usage(const char *name) {
	cout << "Usage: " << name << " [OPTIONS] <keylist> <sample_file>" << endl;
	cout << "\tOptions:" << endl;
	cout << "\t\t-c, --crib <crib text>" << endl;
	cout << "\t\t-e, --encoding <hex or b64>" << endl;
	cout << "\t\t-i, --initialization_vector <vector>" << endl;
	cout << "\t\t-m, --mode <ECB, CBC, CTR>" << endl;
	cout << "\t\t-t, --threads <number>" << endl;
}
	

int main(int argc, char **argv) {

	//handle arguments
	//TODO: fix getopt
	if (argc < 3) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	char *keylist_filename = argv[argc - 2];
	char *samples_filename = argv[argc - 1];

	const char *optstring = "c:e:i:m:t:";
	const struct option long_options[] = {
		{"initialization_vector", 	0, 	0, 	'i'},
		{"crib", 					0, 	0, 	'c'},
		{"encoding", 				0, 	0, 	'e'},
		{"mode", 					0, 	0, 	'm'},
		{"threads", 				0, 	0, 	't'},
		{0, 						0,	0, 	0}
	};

	int c;
	int option_index = 0;



	//init the configuration struct
	//this struct is passed to the library to specify how to brute force
	BruteBuilder *config = new BruteBuilder();
	config->crib = "";
	config->is_b64 = false;
	config->iv = "";
	config->mode = ALL;
	config->num_threads = 1;
	while ((c = getopt_long(argc, argv, optstring, long_options, &option_index)) != EOF) {
		/* if (!optarg) { */
		/* 	cout << "Flag must be provided with an argument." << endl; */
		/* 	exit(EXIT_FAILURE); */
		/* } */
		string optargstr = string(optarg);
		switch (c) {
			case 'c':
				cout << "Setting crib to be " << optarg << endl;
				config->crib = optargstr;
				break;

			case 'e':
				if (optargstr == "hex") {
					cout << "Choosing hex encoding." << endl;
					config->is_b64 = false;
				} else if (optargstr == "b64") {
					cout << "Choosing base 64 encoding." << endl;
					config->is_b64 = true;
				} else {
					cout << "Could not understand encoding. Please use 'hex' or 'b64'."
						<< endl << "Defaulting to 'hex' encoding." << endl;
				}
				break;

			case 'i':
				cout << "Setting Initialization Vector to be " << optargstr << "." << endl;
				config->iv = optargstr; //NOTE: this does not care about the null byte because IVs are always 16 bytes in AES
				break;

			case 'm': {
				cout << "Setting mode to be " << optargstr << "." << endl;
				Mode conf_mode = ALL;
				if (optargstr == "ECB") {
					conf_mode = ECB;
				} else if (optargstr == "CBC") {
					conf_mode = CBC;
				} else if (optargstr == "CTR") {
					conf_mode = CTR;
				}
				config->mode = conf_mode;
				break;
			}

			case 't':
				cout << "Setting num_threads to be " << optargstr << "." << endl;
				config->num_threads = stoi(optargstr);
				break;
		}
	}
	
	//open files
	ifstream h_keylist(keylist_filename);
	if (!h_keylist.is_open()) {
		cout << "Could not open keylist." << endl;
		exit(EXIT_FAILURE);
	}

	ifstream h_samples(samples_filename);
	if (!h_samples.is_open()) {
		cout << "Could not open the samples file." << endl;
		exit(EXIT_FAILURE);
	}

	//initialize keys and samples on the heap
	vector<string> *keys = new vector<string>;
	vector<string> *samples = new vector<string>;

	//populate keys and samples
	string line;
	while (getline(h_keylist, line)) {
		keys->push_back(line);
	}

	while (getline(h_samples, line)) {
		samples->push_back(line);
	}

	//actually try to brute force
	BruteForcer *bforcer = new BruteForcer(config);
	bforcer->brute_force(keys, samples);

	//cleanup
	delete keys;
	delete samples;
	delete config;
	h_keylist.close();
	h_samples.close();
}
