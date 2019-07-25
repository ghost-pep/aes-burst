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
  if (argc != 5) {
    usage();
    exit(EXIT_FAILURE);
  }
  return 0;
}
