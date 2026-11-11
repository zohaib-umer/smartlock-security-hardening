# SmartLock — Lab and Reproduction Guide

**Course:** CS3002 — Information Security
**Author:** Zohaib Umer
**Student ID:** 23i-0528
**Section:** F

> Commands in this guide run from the combined project root. The original course scaffold (`smartlock/`, `v2_skeleton/`, and `instance.txt`) is required separately and is not included in this repository.

## Overview

This submission covers the analysis of SmartLock v1 vulnerabilities, implementation of the v2 security module, security verification, and performance comparison of both versions.

## Submission Contents

| File or Folder | Description |
|---|---|
| `23i-0528-F-REPORT (1).pdf` | Report covering Parts A–D, supporting evidence, and the design diagram, within the 20-page limit. |
| `answers.txt` | Values recovered from captured network evidence and dictionary verification results. |
| `securelink2.cpp` | Source code for the compiled and tested v2 security module. |
| `exploits/` | A1 standard-tool instructions and C++17 source files for A2–A5. |
| `performance/` | Benchmark source, raw measurements, summary, chart, and measurement environment details. |
| `evidence/` | PCAPs, screenshots, console logs, TSV exports, source self-test results, and mitmproxy addons. |

## Requirements

- Original SmartLock source project containing `smartlock/` and `v2_skeleton/`.
- A C++17-compatible compiler (`g++`).
- OpenSSL 3.x development headers and `libcrypto`.
- `make` for building v2.
- `mitmdump` for the relevant relay tests.
- Packet capture tools for collecting and inspecting network evidence.
- The original `instance.txt` for running the legitimate applications and benchmarks.

## Build Instructions

Run the following commands from the project root containing `smartlock/`, `v2_skeleton/`, `exploits/`, and `performance/`.

### Build A2–A5

```bash
g++ -std=c++17 -O2 -Wall -Wextra -I smartlock \
  exploits/23i-0528-F-TASKA2-V1.cpp \
  -o a2_mitm -lcrypto

g++ -std=c++17 -O2 -Wall -Wextra -I smartlock \
  exploits/23i-0528-F-TASKA3-V1.cpp \
  -o a3_recover -lcrypto

g++ -std=c++17 -O2 -Wall -Wextra -I smartlock \
  exploits/23i-0528-F-TASKA4-V1.cpp \
  -o a4_nonce -lcrypto

g++ -std=c++17 -O2 -Wall -Wextra -I smartlock \
  exploits/23i-0528-F-TASKA5-V1.cpp \
  -o a5_replay -lcrypto
```

### Build SmartLock v2

Copy the submitted `securelink2.cpp` into `v2_skeleton/`, then build:

```bash
cp securelink2.cpp v2_skeleton/securelink2.cpp
make -C v2_skeleton
```

### Build the Benchmark

```bash
g++ -std=c++17 -O2 -Wall -Wextra \
  -I smartlock -I v2_skeleton \
  performance/23i-0528-F-TASKD-V1.cpp \
  v2_skeleton/securelink2.cpp \
  -o benchmark -lcrypto
```

## Part A — Reproduction Instructions

The commands below use:

| Setting | Value |
|---|---|
| Server IP address | `10.10.10.11` |
| Server port | `9283` |
| Relay port | `8000` |

Adjust the server address if your lab configuration differs.

### A1 — Standard-Tool Sequence

Follow the exact relay commands provided in:

```text
exploits/23i-0528-F-TASKA1-V1.txt
```

### A2 — MITM Test

Keep the legitimate v1 server running. Start the relay from the project root:

```bash
./a2_mitm 10.10.10.11 9283 8000
```

In a separate terminal, run the legitimate client from the directory containing `hub_client` and the original `instance.txt`:

```bash
./hub_client instance.txt 127.0.0.1 8000
```

### A3 — Capture-Based Recovery

Run from the project root:

```bash
./a3_recover evidence/A3_tcp.tsv 9283
```

### A4 — Nonce Test

```bash
./a4_nonce evidence/A4_tcp.tsv 9283
```

### A5 — Replay Test

Keep the legitimate v1 server running, then execute:

```bash
./a5_replay evidence/A5_tcp.tsv 9283 10.10.10.11 2
```

For A2–A5, use the original `instance.txt` only for the legitimate server and client. The capture-based secret-recovery tools must use captured evidence rather than `instance.txt`.

## Parts B and C — v2 Implementation and Verification

The submitted `securelink2.cpp` contains the v2 security implementation. The report explains the design, security changes, verification results, and remaining limitations.

Use the following mitmproxy addons for the v2 re-tests:

| Test | Addon |
|---|---|
| A1 | `evidence/tool_addons/23i-0528-F-C-A1-V1.py` |
| A2 | `evidence/tool_addons/23i-0528-F-C-A2-V1.py` |
| A5 | `evidence/tool_addons/23i-0528-F-C-A5-V1.py` |

For each test:

1. Start the v2 server at `10.10.10.11:9283`.
2. Run `mitmdump` in reverse TCP mode, listening on port `8000` and forwarding to the server.
3. Load the corresponding addon.
4. Connect `hub_client2` through `127.0.0.1:8000`.
5. Capture the relevant traffic on `eth0` and/or `lo`.
6. Inspect the client/server logs and packet captures to verify the behavior described in the report.

**Known limitation:** The PIN-digest weakness remains in the provided v2 scaffolding by assignment design. This limitation is explicitly discussed in Part B.

## Part D — Performance Testing

The archived benchmark was executed on 2026-11-10 in a **Linux container on an AMD EPYC 9V74 host with five exposed vCPUs**, using GCC 14.2.0 and OpenSSL 3.5.5. These measurements were not taken on the original Kali/VirtualBox lab machines; see `performance/benchmark_environment.txt`. Both SmartLock v1 and v2 used C++17 implementations with OpenSSL (`libcrypto`), compiled with `-std=c++17 -O2`.

### Methodology

- **Handshake:** 30 sessions per version.
- **Record processing:** Five runs of 10,000 records per version.
- **Plaintext record size:** 1 KiB (1,024 bytes).
- **Protect and open operations:** Measured separately.
- **Results:** Mean ± standard deviation (SD).

### Results

| Measurement | v1 (AES256-GCM) | v2 (AES256-GCM) |
|---|---:|---:|
| Handshake latency, ms (n = 30) | 1.102 ± 1.016 | 2.558 ± 0.829 |
| Protect time, µs/record (n = 5) | 1.47 ± 0.11 | 1.08 ± 0.05 |
| Open time, µs/record (n = 5) | 1.33 ± 0.05 | 1.20 ± 0.01 |
| Protect throughput, MB/s (n = 5) | 698.7 ± 48.9 | 948.6 ± 43.0 |
| Open throughput, MB/s (n = 5) | 769.1 ± 29.4 | 850.5 ± 7.1 |
| Complete wire MSG line for 1 KiB plaintext | 2,124 bytes | 2,110 bytes |
| Wire bytes added over plaintext | 1,100 bytes | 1,086 bytes |

### Interpretation

The v2 mean handshake latency was approximately **2.32 times** that of v1, consistent with the additional authentication and verification work.

In these measurements, v2 provided lower record protection and opening times and higher record throughput. Its complete wire message was also **14 bytes smaller** for a 1 KiB plaintext record.

Performance can vary with the host machine, VM resources, and system load.

### Reproduce the Measurements

Use the same machine, compiler, and compilation settings for both versions. Run the benchmark commands below from the project root.

#### v1 Handshake

Start the v1 server from its executable directory using the original instance file:

```bash
./lock_server instance.txt
```

In another terminal, run:

```bash
./benchmark handshake v1 smartlock/instance.txt 127.0.0.1 30 \
  > performance/v1_handshakes.csv
```

#### v2 Handshake

Stop the v1 server. Start the v2 server using the same original instance file, adjusting its path for the server's working directory:

```bash
./lock_server2 /path/to/original/instance.txt
```

In another terminal, run:

```bash
./benchmark handshake v2 smartlock/instance.txt 127.0.0.1 30 \
  > performance/v2_handshakes.csv
```

#### Record Processing

These tests do not require an active server:

```bash
./benchmark records v1 smartlock/instance.txt 10000 5 \
  > performance/v1_records.csv

./benchmark records v2 smartlock/instance.txt 10000 5 \
  > performance/v2_records.csv
```

The commands overwrite the corresponding CSV files. If measurements change, update the summary, chart, report table, and `performance/benchmark_environment.txt` to match the new run.

## Additional Audit Evidence

| File | Description |
|---|---|
| `evidence/23i-0528-F-TASKC-AI-AUDIT.txt` | Explicitly illustrative AI audit example and the applied fix. |
| `evidence/A1_null_plaintext_verified.txt` | Bytes decoded from the actual `A1_after.pcap` capture. |
| `evidence/C_A5_packet_replay_check.txt` | Duplicate record fingerprints from a captured v2 session. |
