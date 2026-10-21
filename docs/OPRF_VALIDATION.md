# Executed validation, 2026-10-21

Environment: Ubuntu 24.04.3 container, GCC 13.3.0, CMake 4.4.4,
OpenSSL 3.0.13, libsodium 1.0.18, Google Benchmark 1.8.3.
Dependencies were built outside the repository because development packages
were missing and apt source connections were unsuccessful. Sodium upstream
1.0.18-RELEASE commit 940ef42797baa0278df6b7fd9e67c7590f87744b;
Benchmark v1.8.3 commit 344117638c8ff7e239044fd0fa7085839fc03021.
The project itself does not download dependencies.

Executed:

```sh
cmake -S PPKR -B PPKR/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/tmp/ppkr-deps
cmake --build PPKR/build -j4
ctest --test-dir PPKR/build --output-on-failure
PPKR/build/oprf_tests
PPKR/build/oprf_bench --benchmark_min_time=0.01s
```

Release correctness: 1/1 CTest passed; direct executable reports
`PASS: 3959 checks; 280 randomized/boundary cases`.
Additional checks include fixed hash/OPRF regression vectors (k=1), q-1
key/blind boundary, 0/q/noncanonical scalar rejection, and invalid domain.
All 18 benchmark entries (9 operations x 2 input sizes) executed successfully.
These very short container runs validate executability, not performance claims.
No measurements were taken on the user's i9-14900HX or a physical HSM/device.

Debug ASan+UBSan build also passed 1/1 CTest with
`ASAN_OPTIONS=detect_leaks=0`. The first default sanitizer run failed in
LeakSanitizer because it could not read /proc/<pid>/task in this environment;
leak detection remains unverified. External libsodium/OpenSSL were not rebuilt
with sanitizers. No independent cryptographic audit, formal proof compatibility
check, network/HSM integration, or full protocol test was performed.

For repeatable local performance commands and remaining instantiation reviews,
see OPRF_INSTANTIATION.md. The 280 cases include deterministic boundary inputs
and random keys/blinds, so not all test executions are bit-for-bit deterministic.

## Follow-up correctness review

After the initial 3959-check run, tests were extended with an OpenSSL BN
reference for modular inversion, applied to all 280 cases and the q-1 boundary.
Added 256-byte input-length encoding checks and valid-but-altered response /
mismatched blind checks. Production OPRF formulas and messages were unchanged.

The updated Release executable reports:
`PASS: 4808 checks; 280 randomized/boundary cases`.
Release CTest passed 1/1. No performance run was requested or performed for
this follow-up. The user's earlier local 3959-check success applies to the
previous revision; the updated tests have so far run in the container only.
The follow-up Debug ASan+UBSan run passed 1/1 with leak detection disabled
for the previously documented container limitation. A fresh Release build with
PPKR_BUILD_BENCHMARKS=OFF also passed 1/1 CTest, confirming correctness checks
can run without Google Benchmark. No production protocol change was introduced.
