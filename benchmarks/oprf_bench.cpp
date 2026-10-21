#include "crypto/oprf.hpp"
#include <benchmark/benchmark.h>
using namespace ppkr::oprf;
namespace {
void operation(benchmark::State& state, int op) {
  const auto x=encode_input(std::string(state.range(0),'p'),"alice@example.org");
  const auto k=random_scalar(), r=random_scalar();
  const auto a=hsm_blind(x,r), b=hsm_evaluate(a,k);
  for(auto _:state) {
    switch(op) {
      case 0: { auto v=random_scalar(); benchmark::DoNotOptimize(v); break; }
      case 1: { auto v=hash_to_group(Domain::Device,x); benchmark::DoNotOptimize(v); break; }
      case 2: { auto v=device_evaluate(x,k); benchmark::DoNotOptimize(v); break; }
      case 3: { auto v=hsm_blind(x,r); benchmark::DoNotOptimize(v); break; }
      case 4: { auto v=hsm_evaluate(a,k); benchmark::DoNotOptimize(v); break; }
      case 5: { auto v=hsm_unblind(b,r); benchmark::DoNotOptimize(v); break; }
      case 6: { auto v=hsm_finalize(x,b,r); benchmark::DoNotOptimize(v); break; }
      case 7: { auto fresh=random_scalar(); auto req=hsm_blind(x,fresh);
        auto res=hsm_evaluate(req,k); auto v=hsm_finalize(x,res,fresh); benchmark::DoNotOptimize(v); break; }
      case 8: { auto v=finalize(Domain::Device,x,a); benchmark::DoNotOptimize(v); break; }
    }
  }
  state.SetItemsProcessed(state.iterations());
}
#define OPRF_BENCH(name,n) void name(benchmark::State& s){operation(s,n);} BENCHMARK(name)->Arg(16)->Arg(64)->Unit(benchmark::kMicrosecond)
OPRF_BENCH(ScalarRandom,0);
OPRF_BENCH(DeviceHashToGroup,1);
OPRF_BENCH(DeviceEvaluate,2);
OPRF_BENCH(HsmBlind,3);
OPRF_BENCH(HsmEvaluate,4);
OPRF_BENCH(HsmUnblind,5);
OPRF_BENCH(HsmFinalize,6);
OPRF_BENCH(HsmRoundTrip,7);
OPRF_BENCH(DeviceOutputHash,8);
}
int main(int argc,char** argv) {
  initialize(); benchmark::Initialize(&argc,argv);
  if(benchmark::ReportUnrecognizedArguments(argc,argv)) return 1;
  benchmark::AddCustomContext("google_benchmark_version",PPKR_BENCHMARK_VERSION);
  benchmark::RunSpecifiedBenchmarks(); benchmark::Shutdown();
}
