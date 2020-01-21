#include "aesburst.h"
#include <fstream>
#include <getopt.h>
#include <string>
#include <vector>

#include "aesburst.grpc.pb.h"
#include "aesburst.pb.h"
#include <grpcpp/grpcpp.h>

using aesburst::AESBurstManager;
using aesburst::BruteForceReply;
using aesburst::BruteForceRequest;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Server;
using grpc::ServerContext;
using grpc::Status;

class ManagerClient {
  public:
    ManagerClient(std::shared_ptr<Channel> channel)
        : stub_(AESBurstManager::NewStub(channel)) {}

    void BruteForce(BruteForceRequest::Mode mode, std::string crib,
                    std::string iv, std::vector<std::string> ciphertexts,
                    std::vector<std::string> keys) {
        BruteForceRequest request;
        request.set_crib(crib);
        request.set_iv(iv);
        request.set_mode(mode);
        {
            int i = 0;
            for (auto ciphertext : ciphertexts) {
                request.set_ciphertexts(i++, ciphertext);
            }
            i = 0;
            for (auto key : keys) {
                request.set_keys(i++, key);
            }
        }
        BruteForceReply reply;
        ClientContext context;
        // Make the call to the manager and parse any errors
        Status status = stub_->BruteForce(&context, request, &reply);
        if (status.ok()) {
        } else {
            std::cout << status.error_code() << ": " << status.error_message()
                      << "RPC failed." << std::endl;
            exit(-1);
        }
    }

  private:
    std::unique_ptr<AESBurstManager::Stub> stub_;
};

void usage() { std::cout << "USAGE" << std::endl; }

int main(int argc, char **argv) {
    if (argc < 3) {
        usage();
        exit(EXIT_FAILURE);
    }
    // parse out the params
    std::string crib;
    std::string iv;
    bool is_b64;
    int mode;
    std::string ciphertext_file(argv[argc - 2]);
    std::string key_file(argv[argc - 1]);

    const char *optstring = "c:e:i:m:";
    const struct option long_options[] = {{"initialization_vector", 0, 0, 'i'},
                                          {"crib", 0, 0, 'c'},
                                          {"encoding", 0, 0, 'e'},
                                          {"mode", 0, 0, 'm'},
                                          {0, 0, 0, 0}};

    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, optstring, long_options,
                            &option_index)) != EOF) {
        std::string optargstr = std::string(optarg);
        switch (c) {
        case 'c':
            std::cout << "Setting crib to be " << optarg << std::endl;
            crib = optargstr;
            break;

        case 'e':
            if (optargstr == "hex") {
                std::cout << "Choosing hex encoding." << std::endl;
                is_b64 = false;
            } else if (optargstr == "b64") {
                std::cout << "Choosing base 64 encoding." << std::endl;
                is_b64 = true;
            } else {
                std::cout << "Could not understand encoding. Please use 'hex' "
                             "or 'b64'."
                          << std::endl
                          << "Defaulting to 'hex' encoding." << std::endl;
            }
            break;

        case 'i':
            std::cout << "Setting Initialization Vector to be " << optargstr
                      << "." << std::endl;
            iv = optargstr; // NOTE: this does not care about the null byte
                            // because IVs are always 16 bytes in AES
            break;

        case 'm': {
            std::cout << "Setting mode to be " << optargstr << "." << std::endl;
            BruteForceRequest::Mode conf_mode = BruteForceRequest::ALL;
            if (optargstr == "ECB") {
                conf_mode = BruteForceRequest::ECB;
            } else if (optargstr == "CBC") {
                conf_mode = BruteForceRequest::CBC;
            } else if (optargstr == "CTR") {
                conf_mode = BruteForceRequest::CTR;
            }
            break;
        }
        }
    }

    // get the ciphertexts and keys
    // for now this is a simple load into a vector but it should possibly be
    // some sort of streaming abstraction
    std::vector<std::string> ciphertexts;
    std::vector<std::string> keys;
    std::ifstream cipherstream(ciphertext_file);
    std::ifstream keystream(key_file);
    if (!cipherstream.is_open()) {
        std::cerr << "Failed to open " << ciphertext_file << std::endl;
        exit(EXIT_FAILURE);
    } else {
        std::string line;
        while (std::getline(cipherstream, line)) {
            ciphertexts.push_back(line);
        }
    }
    if (!keystream.is_open()) {
        std::cerr << "Failed to open " << key_file << std::endl;
        exit(EXIT_FAILURE);
    } else {
        std::string line;
        while (std::getline(keystream, line)) {
            keys.push_back(line);
        }
    }
    cipherstream.close();
    keystream.close();

    // now we have:
    //	crib
    //	is_b64
    //	iv
    //	conf_mode
    //	ciphertexts
    //	keys

    // init the manager
    ManagerClient client(grpc::CreateChannel(
        MANAGERNODEPORT, grpc::InsecureChannelCredentials()));

    // make the request to the manager
    client.BruteForce(conf_mode, crib, iv, ciphertexts, keys);

    return 0;
}
