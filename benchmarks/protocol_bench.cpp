#include "evaluation/workload.hpp"
#include "evaluation/lev3.hpp"
#include <benchmark/benchmark.h>
#include <memory>
using namespace ppkr::evaluation;
namespace {
template<class Fixture=Workload>
void operation(benchmark::State& state,Stage stage){
  Config config;
  if(stage==Stage::DeviceBackup||stage==Stage::DeviceRestoration){config.n=state.range(0);config.t=state.range(1);}
  bool paused=false;
  try{
    for(auto _:state){
      state.PauseTiming();paused=true;
      auto workload=std::make_unique<Fixture>(config);workload->setup(stage);
      state.ResumeTiming();paused=false;
      workload->run(stage);benchmark::DoNotOptimize(workload.get());
      state.PauseTiming();paused=true;
      workload->validate(stage);workload.reset();
      state.ResumeTiming();paused=false;
    }
  }catch(const std::exception& e){if(paused)state.ResumeTiming();state.SkipWithError(e.what());}
  state.SetItemsProcessed(state.iterations());
}
void InitializationCpu(benchmark::State& s){operation(s,Stage::Initialization);}
void KeyRecoveryCpu(benchmark::State& s){operation(s,Stage::KeyRecovery);}
void DeviceBackupCpu(benchmark::State& s){operation(s,Stage::DeviceBackup);}
void DeviceRestorationCpu(benchmark::State& s){operation(s,Stage::DeviceRestoration);}
void Lev3InitializationCpu(benchmark::State& s){operation<Lev3Workload>(s,Stage::Initialization);}
void Lev3KeyRecoveryCpu(benchmark::State& s){operation<Lev3Workload>(s,Stage::KeyRecovery);}
void matrix(benchmark::internal::Benchmark* b){for(auto [n,t]:scenarios())b->Args({static_cast<std::int64_t>(n),static_cast<std::int64_t>(t)});b->ArgNames({"n","t"});}
BENCHMARK(Lev3InitializationCpu)->Unit(benchmark::kMicrosecond);
BENCHMARK(Lev3KeyRecoveryCpu)->Unit(benchmark::kMicrosecond);
BENCHMARK(InitializationCpu)->Unit(benchmark::kMicrosecond);
BENCHMARK(KeyRecoveryCpu)->Unit(benchmark::kMicrosecond);
BENCHMARK(DeviceBackupCpu)->Apply(matrix)->Unit(benchmark::kMicrosecond);
BENCHMARK(DeviceRestorationCpu)->Apply(matrix)->Unit(benchmark::kMicrosecond);
}
int main(int argc,char** argv){
  ppkr::oprf::initialize();benchmark::Initialize(&argc,argv);
  if(benchmark::ReportUnrecognizedArguments(argc,argv))return 1;
  benchmark::AddCustomContext("ppkr_build_revision",build_revision());
  benchmark::AddCustomContext("google_benchmark_version",PPKR_BENCHMARK_VERSION);
  benchmark::AddCustomContext("scope","single-process sequential software work; setup/validation excluded; human and network delay excluded");
  benchmark::AddCustomContext("baseline", "Faller et al. 2024 Figure 4 Level-3; software reimplementation; channels idealized; see docs/LEV3_BASELINE.md");
  benchmark::RunSpecifiedBenchmarks();benchmark::Shutdown();
}
