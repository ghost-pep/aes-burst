#ifndef __AESBURSTMANAGER_H__
#define __AESBURSTMANAGER_H__

#include <string>

#include "aesburst.grpc.pb.h"
#include "aesburst.pb.h"
#include <grpcpp/grpcpp.h>

using aesburst::AESBurstWorker;
using aesburst::BruteForceRequest;

namespace aesburst {

typedef unsigned char BYTE;

typedef struct WorkerRequest {
  std::string crib;
  BYTE[16] iv;
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

  void BruteECB(WorkerRequest_t req);
  void BruteCBC(WorkerRequest_t req);
  void BruteCTR(WorkerRequest_t req);

private:
  std::unique_ptr<AESBurstWorker::Stub> stub_;
}

// TODO: Implement the interface for the actual manager service code

} // namespace aesburst

#endif
