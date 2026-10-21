#include "evaluation/recovery_breakdown.hpp"
#include <benchmark/benchmark.h>
#include <memory>
using namespace ppkr::evaluation;
namespace {
void operation(benchmark::State& state,RecoveryPart part) {
  bool paused=false;
  try {
    RecoveryBreakdown prepared;prepared.setup(part);
    for(auto _:state) {
      state.PauseTiming();paused=true;
      auto fixture=std::make_unique<RecoveryBreakdown>(prepared);
      state.ResumeTiming();paused=false;
      fixture->run(part);benchmark::DoNotOptimize(fixture.get());
      state.PauseTiming();paused=true;
      fixture->validate(part);fixture.reset();
      state.ResumeTiming();paused=false;
    }
  } catch(const std::exception& e) {
    if(paused)state.ResumeTiming();state.SkipWithError(e.what());
  }
  state.SetItemsProcessed(state.iterations());
}
}
int main(int argc,char** argv) {
  ppkr::oprf::initialize();
  for(int i=0;i<=static_cast<int>(RecoveryPart::SigningKeygenDiagnostic);++i) {
    const auto p=static_cast<RecoveryPart>(i);
    benchmark::RegisterBenchmark(name(p),[p](benchmark::State& s){operation(s,p);})->Unit(benchmark::kMicrosecond);
  }
  benchmark::Initialize(&argc,argv);
  if(benchmark::ReportUnrecognizedArguments(argc,argv))return 1;
  benchmark::AddCustomContext("ppkr_build_revision",build_revision());
  benchmark::AddCustomContext("google_benchmark_version",PPKR_BENCHMARK_VERSION);
  benchmark::AddCustomContext("scope","recovery software components; prerequisite prefix and completion validation excluded; diagnostics overlap components; do not sum diagnostics");
  benchmark::RunSpecifiedBenchmarks();benchmark::Shutdown();
}
