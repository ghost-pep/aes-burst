#ifndef __AESBURSTMANAGER_H__
#define __AESBURSTMANAGER_H__

#include <mutex>
#include <string>

#include "aesburst.grpc.pb.h"
#include "aesburst.pb.h"
#include <grpcpp/grpcpp.h>

using aesburst::AESBurstWorker;
using aesburst::BruteForceReply;
using aesburst::BruteForceRequest;
using aesburst::PartialBruteReply;
using aesburst::PartialBruteRequest;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Server;
using grpc::ServerContext;
using grpc::Status;

namespace aesburst {

std::mutex request_lock;

typedef unsigned char BYTE;

typedef struct WorkerRequest {
  std::string crib;
  BYTE iv[16];
  char mode_flag;
  // ECB = 1;
  // CBC = 2;
  // CTR = 3;
  // ALL = 4;
  BYTE **ciphertexts;
  BYTE **keys;
} WorkerRequest_t;

class WorkerClient {
public:
  WorkerClient(std::shared_ptr<Channel> channel)
      : stub_(AESBurstWorker::NewStub(channel)) {}

  void BruteECB(WorkerRequest_t *req) {
    // Setup the request to the worker
    PartialBruteRequest request;
    // request.set_crib(req->crib);
    // request.set_keys(req->keys);
    // request.set_ciphertexts(req->ciphertexts);
    PartialBruteReply reply;
    ClientContext context;

    // Make the call to the worker and parse any errors
    Status status = stub_->BruteECB(&context, request, &reply);
    if (status.ok()) {
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << "RPC failed." << std::endl;
      exit(-1);
    }
  }
  void BruteCBC(WorkerRequest_t req) {
    // Setup the request to the worker
    PartialBruteRequest request;
    // request.set_crib(req->crib);
    // request.set_keys(req->keys);
    // request.set_ciphertexts(req->ciphertexts);
    PartialBruteReply reply;
    ClientContext context;

    // Make the call to the worker and parse any errors
    Status status = stub_->BruteCBC(&context, request, &reply);
    if (status.ok()) {
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << "RPC failed." << std::endl;
      exit(-1);
    }
  }
  void BruteCTR(WorkerRequest_t req) {
    // Setup the request to the worker
    PartialBruteRequest request;
    // request.set_crib(req->crib);
    // request.set_keys(req->keys);
    // request.set_ciphertexts(req->ciphertexts);
    PartialBruteReply reply;
    ClientContext context;

    // Make the call to the worker and parse any errors
    Status status = stub_->BruteCTR(&context, request, &reply);
    if (status.ok()) {
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << "RPC failed." << std::endl;
      exit(-1);
    }
  }

private:
  std::unique_ptr<AESBurstWorker::Stub> stub_;
};

// Implement the interface for the actual manager service code
class ManagerImpl final : public AESBurstManager::Service {
public:
  ManagerImpl() {}

  Status BruteForce(ServerContext *context, const BruteForceRequest *request,
                    BruteForceReply *reply) override {
    // pull the data out of the request
    std::string crib(request->crib());
    std::string iv(request->iv());
    BruteForceRequest::Mode mode = request->mode();

    // calculate the distribution of work

    // lock for the actual work
    request_lock.lock();

    // request work for each worker connected
    // distribute_work();

    // unlock to allow other requests to go through
    request_lock.unlock();

    return Status::OK;
  }

private:
};

} // namespace aesburst

int main() { return 0; }

#endif
