#include "evaluation/lev3.hpp"
#include <algorithm>
#include <stdexcept>
namespace ppkr::evaluation {
using crypto::Bytes;using crypto::view;
namespace {
void require(bool b){if(!b)throw std::runtime_error("Level-3 workload validation failed");}
// The same length-prefix profile as the existing implementation.
std::vector<Bytes> decode(const Bytes& input){
  std::vector<Bytes> fields;std::size_t pos=0;
  while(pos<input.size()){
    require(input.size()-pos>=8);std::uint64_t n=0;
    for(int i=0;i<8;++i)n=(n<<8)|input[pos++];
    require(n<=input.size()-pos);
    fields.emplace_back(input.begin()+pos,input.begin()+pos+n);pos+=n;
  }
  return fields;
}
void relay(Traffic* t,const Bytes& bytes){if(t){++t->relayed_messages;t->relayed_bytes+=bytes.size();}}
void result(Traffic* t,std::string_view phase,const crypto::Key& session){if(t){++t->server_messages;t->server_bytes+=crypto::encode({phase,view(session),std::string_view("\1",1)}).size();}}
}
void Lev3Workload::initialize(Traffic* t){
  const auto key=crypto::random_key();
  const auto x=oprf::encode_input(config.password,config.id);
  const auto blind=oprf::random_scalar();const auto a=oprf::hsm_blind(x,blind);
  if(t)relay(t,crypto::encode({"Init",view(session),view(a),config.id}));
  const auto enc=crypto::encryption_keygen();const auto k=oprf::random_scalar();
  const auto b=oprf::hsm_evaluate(a,k);
  if(t)relay(t,crypto::encode({view(session),view(b),config.id,view(enc.pk)}));
  const auto rho=oprf::hsm_finalize(x,b,blind);
  const auto signing=crypto::signing_from_seed(crypto::random_key());
  const auto c=crypto::ae_encrypt(crypto::encode({view(key),view(signing.sk)}),rho);
  const auto upload=crypto::pke_encrypt(crypto::encode({view(session),view(signing.pk),view(c)}),enc.pk);
  if(t)relay(t,crypto::encode({view(session),view(upload)}));
  const auto plaintext=crypto::pke_decrypt(upload,enc);require(plaintext.has_value());
  const auto fields=decode(*plaintext);
  require(fields.size()==3&&fields[0]==crypto::bytes(session));
  record=Record{crypto::key_from_bytes(fields[1]),fields[2],k,10};
  result(t,"InitRes",session); // Figure 4: final HSM status goes only to S, not C.
  original=key;recovered.reset();
}
bool Lev3Workload::recover(std::string_view password,Traffic* t){
  recovered.reset();
  const auto x=oprf::encode_input(password,config.id);
  const auto blind=oprf::random_scalar();const auto a=oprf::hsm_blind(x,blind);
  if(t)relay(t,crypto::encode({"Rec",view(session),view(a),config.id}));
  if(!record)return false;
  if(record->counter==0){record.reset();return false;}
  --record->counter;
  const auto b=oprf::hsm_evaluate(a,record->oprf_key);
  if(t)relay(t,crypto::encode({view(session),view(b),view(record->ciphertext),config.id}));
  const auto rho=oprf::hsm_finalize(x,b,blind);
  const auto plaintext=crypto::ae_decrypt(record->ciphertext,rho);
  if(!plaintext)return false;
  const auto fields=decode(*plaintext);
  require(fields.size()==2&&fields[1].size()==64);
  const auto key=crypto::key_from_bytes(fields[0]);
  crypto::SigningKeys signing{};std::copy(fields[1].begin(),fields[1].end(),signing.sk.begin());
  const auto transcript=crypto::encode({view(a),config.id,view(session),view(b),view(record->ciphertext)});
  const auto signature=crypto::sign(transcript,signing);
  if(t)relay(t,crypto::encode({view(session),view(signature)}));
  // Independently construct the HSM's transcript from its state.
  const auto expected=crypto::encode({view(a),config.id,view(session),view(b),view(record->ciphertext)});
  if(!crypto::verify(expected,signature,record->pk))return false;
  record->counter=10;result(t,"RecRes",session);recovered=key;return true;
}
void Lev3Workload::setup(Stage s){
  if(s==Stage::KeyRecovery){initialize();session=crypto::random_key();}
  else if(s!=Stage::Initialization)throw std::invalid_argument("Level-3 has only Init/Rec");
}
void Lev3Workload::run(Stage s,Traffic* t){
  if(s==Stage::Initialization)initialize(t);
  else if(s==Stage::KeyRecovery)require(recover(config.password,t));
  else throw std::invalid_argument("Level-3 has only Init/Rec");
}
void Lev3Workload::validate(Stage s)const{
  require(original.has_value()&&record.has_value()&&record->counter==10);
  if(s==Stage::KeyRecovery)require(original==recovered);
}
Storage Lev3Workload::storage(Stage)const{
  require(record.has_value());std::string counter(8,'\0');
  for(int i=0;i<8;++i)counter[7-i]=(record->counter>>(8*i))&255;
  Storage s;s.hsm=crypto::encode({"HSMRecord",config.id,view(record->pk),view(record->ciphertext),view(record->oprf_key),counter}).size();
  s.client_output=original?32:0;return s;
}
}
