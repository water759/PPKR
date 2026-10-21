#include "protocol/core.hpp"
#include <iostream>
#include <stdexcept>
int main() {
  using namespace ppkr;
  using namespace ppkr::protocol;
  try {
    oprf::initialize(); Device device; Hsm hsm; Server server;
    const std::string id="demo-user",password="demo-password";
    auto [init,request]=device.begin_init(id,password);
    auto response=server.relay(hsm.begin_init(server.relay(request)));
    auto upload=device.finish_init_crypto(init,response);
    auto initial=device.accept_init(init,server.relay(hsm.accept_init(id,server.relay(upload),0)),0);
    if(!initial) throw std::runtime_error("initialization failed");
    auto start=device.begin_recovery(id,password,1);
    if(!start) throw std::runtime_error("device stopped recovery");
    auto [recovery,rec_request]=std::move(*start);
    auto rec_response=hsm.begin_recovery(server.relay(rec_request),1);
    if(!rec_response) throw std::runtime_error("HSM stopped recovery");
    auto auth=device.authenticate(recovery,server.relay(*rec_response));
    if(!auth) throw std::runtime_error("device authentication step stopped");
    auto recovered=device.recover(recovery,server.relay(hsm.authenticate(id,server.relay(*auth))));
    if(!recovered) throw std::runtime_error("key recovery failed");
    Client client;
    auto delivered=client.receive(deliver_key(*recovered,client.qr_public_key()));
    if(delivered!=initial) throw std::runtime_error("client key mismatch");
    std::cout<<"Initialization: PASS\nKey recovery: PASS\nClient delivery matches original key: PASS\n";
    return 0;
  } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
