// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: aesburst.proto

#include "aesburst.pb.h"
#include "aesburst.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/method_handler_impl.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace aesburst {

static const char* AESBurstManager_method_names[] = {
  "/aesburst.AESBurstManager/BruteForce",
};

std::unique_ptr< AESBurstManager::Stub> AESBurstManager::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< AESBurstManager::Stub> stub(new AESBurstManager::Stub(channel));
  return stub;
}

AESBurstManager::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_BruteForce_(AESBurstManager_method_names[0], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status AESBurstManager::Stub::BruteForce(::grpc::ClientContext* context, const ::aesburst::BruteForceRequest& request, ::aesburst::BruteForceReply* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_BruteForce_, context, request, response);
}

void AESBurstManager::Stub::experimental_async::BruteForce(::grpc::ClientContext* context, const ::aesburst::BruteForceRequest* request, ::aesburst::BruteForceReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteForce_, context, request, response, std::move(f));
}

void AESBurstManager::Stub::experimental_async::BruteForce(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::BruteForceReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteForce_, context, request, response, std::move(f));
}

void AESBurstManager::Stub::experimental_async::BruteForce(::grpc::ClientContext* context, const ::aesburst::BruteForceRequest* request, ::aesburst::BruteForceReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteForce_, context, request, response, reactor);
}

void AESBurstManager::Stub::experimental_async::BruteForce(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::BruteForceReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteForce_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::aesburst::BruteForceReply>* AESBurstManager::Stub::AsyncBruteForceRaw(::grpc::ClientContext* context, const ::aesburst::BruteForceRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::BruteForceReply>::Create(channel_.get(), cq, rpcmethod_BruteForce_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::aesburst::BruteForceReply>* AESBurstManager::Stub::PrepareAsyncBruteForceRaw(::grpc::ClientContext* context, const ::aesburst::BruteForceRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::BruteForceReply>::Create(channel_.get(), cq, rpcmethod_BruteForce_, context, request, false);
}

AESBurstManager::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      AESBurstManager_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< AESBurstManager::Service, ::aesburst::BruteForceRequest, ::aesburst::BruteForceReply>(
          std::mem_fn(&AESBurstManager::Service::BruteForce), this)));
}

AESBurstManager::Service::~Service() {
}

::grpc::Status AESBurstManager::Service::BruteForce(::grpc::ServerContext* context, const ::aesburst::BruteForceRequest* request, ::aesburst::BruteForceReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


static const char* AESBurstWorker_method_names[] = {
  "/aesburst.AESBurstWorker/BruteECB",
  "/aesburst.AESBurstWorker/BruteCBC",
  "/aesburst.AESBurstWorker/BruteCTR",
};

std::unique_ptr< AESBurstWorker::Stub> AESBurstWorker::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< AESBurstWorker::Stub> stub(new AESBurstWorker::Stub(channel));
  return stub;
}

AESBurstWorker::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_BruteECB_(AESBurstWorker_method_names[0], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_BruteCBC_(AESBurstWorker_method_names[1], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_BruteCTR_(AESBurstWorker_method_names[2], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status AESBurstWorker::Stub::BruteECB(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::aesburst::PartialBruteReply* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_BruteECB_, context, request, response);
}

void AESBurstWorker::Stub::experimental_async::BruteECB(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteECB_, context, request, response, std::move(f));
}

void AESBurstWorker::Stub::experimental_async::BruteECB(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::PartialBruteReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteECB_, context, request, response, std::move(f));
}

void AESBurstWorker::Stub::experimental_async::BruteECB(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteECB_, context, request, response, reactor);
}

void AESBurstWorker::Stub::experimental_async::BruteECB(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::PartialBruteReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteECB_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::aesburst::PartialBruteReply>* AESBurstWorker::Stub::AsyncBruteECBRaw(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::PartialBruteReply>::Create(channel_.get(), cq, rpcmethod_BruteECB_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::aesburst::PartialBruteReply>* AESBurstWorker::Stub::PrepareAsyncBruteECBRaw(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::PartialBruteReply>::Create(channel_.get(), cq, rpcmethod_BruteECB_, context, request, false);
}

::grpc::Status AESBurstWorker::Stub::BruteCBC(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::aesburst::PartialBruteReply* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_BruteCBC_, context, request, response);
}

void AESBurstWorker::Stub::experimental_async::BruteCBC(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteCBC_, context, request, response, std::move(f));
}

void AESBurstWorker::Stub::experimental_async::BruteCBC(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::PartialBruteReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteCBC_, context, request, response, std::move(f));
}

void AESBurstWorker::Stub::experimental_async::BruteCBC(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteCBC_, context, request, response, reactor);
}

void AESBurstWorker::Stub::experimental_async::BruteCBC(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::PartialBruteReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteCBC_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::aesburst::PartialBruteReply>* AESBurstWorker::Stub::AsyncBruteCBCRaw(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::PartialBruteReply>::Create(channel_.get(), cq, rpcmethod_BruteCBC_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::aesburst::PartialBruteReply>* AESBurstWorker::Stub::PrepareAsyncBruteCBCRaw(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::PartialBruteReply>::Create(channel_.get(), cq, rpcmethod_BruteCBC_, context, request, false);
}

::grpc::Status AESBurstWorker::Stub::BruteCTR(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::aesburst::PartialBruteReply* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_BruteCTR_, context, request, response);
}

void AESBurstWorker::Stub::experimental_async::BruteCTR(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteCTR_, context, request, response, std::move(f));
}

void AESBurstWorker::Stub::experimental_async::BruteCTR(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::PartialBruteReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_BruteCTR_, context, request, response, std::move(f));
}

void AESBurstWorker::Stub::experimental_async::BruteCTR(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteCTR_, context, request, response, reactor);
}

void AESBurstWorker::Stub::experimental_async::BruteCTR(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::aesburst::PartialBruteReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create(stub_->channel_.get(), stub_->rpcmethod_BruteCTR_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::aesburst::PartialBruteReply>* AESBurstWorker::Stub::AsyncBruteCTRRaw(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::PartialBruteReply>::Create(channel_.get(), cq, rpcmethod_BruteCTR_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::aesburst::PartialBruteReply>* AESBurstWorker::Stub::PrepareAsyncBruteCTRRaw(::grpc::ClientContext* context, const ::aesburst::PartialBruteRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::aesburst::PartialBruteReply>::Create(channel_.get(), cq, rpcmethod_BruteCTR_, context, request, false);
}

AESBurstWorker::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      AESBurstWorker_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< AESBurstWorker::Service, ::aesburst::PartialBruteRequest, ::aesburst::PartialBruteReply>(
          std::mem_fn(&AESBurstWorker::Service::BruteECB), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      AESBurstWorker_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< AESBurstWorker::Service, ::aesburst::PartialBruteRequest, ::aesburst::PartialBruteReply>(
          std::mem_fn(&AESBurstWorker::Service::BruteCBC), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      AESBurstWorker_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< AESBurstWorker::Service, ::aesburst::PartialBruteRequest, ::aesburst::PartialBruteReply>(
          std::mem_fn(&AESBurstWorker::Service::BruteCTR), this)));
}

AESBurstWorker::Service::~Service() {
}

::grpc::Status AESBurstWorker::Service::BruteECB(::grpc::ServerContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status AESBurstWorker::Service::BruteCBC(::grpc::ServerContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status AESBurstWorker::Service::BruteCTR(::grpc::ServerContext* context, const ::aesburst::PartialBruteRequest* request, ::aesburst::PartialBruteReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace aesburst

