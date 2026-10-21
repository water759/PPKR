# Evaluation infrastructure validation

Executed in Ubuntu 24.04.3 container, GCC 13.3.0, libsodium 1.0.18,
OpenSSL 3.0.13, Google Benchmark 1.8.3, CMake 4.4.4.

* Release CTest: 5/5 passed, including the unchanged four cryptographic test
  groups and 80 evaluation workload/accounting checks.
* Debug ASan/UBSan CTest: 5/5 passed with leak detection disabled for the
  previously documented container restriction. External libraries are not
  sanitizer-instrumented.
* Protocol benchmark smoke run executed all 28 cases; OPRF smoke run executed
  all 18 cases. Two very short repetitions per case were used solely to check
  executability and output handling. These are not formal measurements.
* Validated protocol_sizes.csv has 28 data rows and the stated hop-byte identity
  for every row. Repeated fresh crypto execution produces identical sizes.
* Checked raw repetition rows and aggregate rows exist in protocol JSON.
* The runner successfully saved JSON/log/CSV/environment artifacts to unique
  ignored results directories. The metadata correctly indicated a dirty
  development build during the smoke run; no formal-run claim is made.

Representative validation commands (custom prefix for container dependencies):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/tmp/ppkr-deps
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/evaluation_tests
python3 scripts/run_evaluation.py --build-dir build --suite all --repetitions 2 --min-time 0.001s
```

No target i9-14900HX data, real HSM data, network capture, human timings,
thermal stability claim or proof compatibility result was obtained. The byte
profile is explicitly specified in EVALUATION.md and should not be relabeled
as measured network traffic or database footprint. Protocol code/formulas
were not changed by this evaluation stage.
