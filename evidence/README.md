# Reading the lab evidence

The archive contains original coursework filenames so results can be cross-referenced with the report. Start with the [evidence index](23i-0528-F-evidence_index.txt) and [lab guide](../docs/LAB_GUIDE.md).

## Suggested review order

| Question | Starting evidence |
| --- | --- |
| Was plaintext exposed after the v1 downgrade? | [Decoded capture bytes](A1_null_plaintext_verified.txt) |
| What happened during the v1 relay? | [Relay output](A2_relay_output.txt) and [hub output](A2_hub_output.txt) |
| What did the weak-DH recovery produce? | [Recovery output](A3_recovery_output.txt) |
| What did the nonce-reuse analysis show? | [Analysis](A4_analysis.txt) |
| How did the v1 replay affect the lab? | [Before](A5_before_hub.txt), [replay output](A5_replay_output.txt), and [after](A5_after_hub.txt) |
| Does the v2 record module pass its core checks? | [Test source](23i-0528-F-TASKC-V1.cpp) and [archived results](C_A4_aead_test.txt) |
| Was a v2 duplicate record rejected? | [Packet comparison](C_A5_packet_replay_check.txt), [rejection result](C_A5_replay_result.txt), [before](C_A5_before.txt), and [after](C_A5_after.txt) |

## What each artifact establishes

- **PCAP files** preserve captured traffic. Valid packet structure alone does not establish exploit success.
- **TSV exports** provide capture data consumed by recovery/analysis programs.
- **Console logs** record program observations and errors; interpret them alongside the matching traffic and state changes.
- **Screenshots** provide visual context for the lab sessions.
- **Self-check results** cover the cryptographic module, not every handshake or application behavior.

Repeated bytes in packets may reflect retransmissions or capture effects. The v2 replay check explicitly requires comparison with rejection and before/after logs; duplicate payloads alone do not demonstrate application acceptance.

## Provenance

These are archived artifacts, not fresh test runs performed during GitHub publication. The [AI audit](23i-0528-F-TASKC-AI-AUDIT.txt) is explicitly an illustrative review exercise, not historical commit evidence. The index also identifies PIN analysis generated during report assembly.

The values in [answers.txt](../answers.txt) belong to this dummy lab. Use new disposable instance values for your own experiments, and inspect new captures before publishing them.
