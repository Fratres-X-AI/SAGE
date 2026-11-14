# Recording performance

These are measurements, not a service-level promise. Run the benchmark on your own hardware before
you size anything.

## How to measure

```bash
python scripts/measure_overhead.py --mode journal --durability all --payload-bytes 64,512,4096,32768 --out journal.json
python scripts/measure_overhead.py --mode workflow --durability all --runs 100 --out workflow.json
```

`--mode journal` times `end_span` for tool spans with one unique payload each, for every durability
mode and payload size. Payloads above 1 KiB are offloaded and write one blob per span.
`--mode workflow` times the consultancy demo workflow end to end. CI runs both on Linux in the
`journal-benchmark` job and uploads the JSON as an artifact. That job fails if the median cost of a
span under the default mode exceeds 2 ms at any payload size. The limit catches a regression to
synchronous fsync; it is not a performance target.

## Reference runs

### Linux CI runner

GitHub-hosted `ubuntu-latest`, Python 3.12, 2000 spans per mode (500 for `"span"`). Median and p95
in milliseconds per span at `end_span`.

| Mode | 64 B | 512 B | 4 KiB median / p95 | 32 KiB median / p95 |
| --- | --- | --- | --- | --- |
| in memory (no journal) | 0.054 | 0.056 | 0.31 / 0.40 | 0.60 / 0.68 |
| `"span"` | 1.90 | 1.89 | 2.38 / 3.53 | 2.68 / 3.37 |
| `"batch"` (default) | 0.12 | 0.12 | 0.38 / 0.80 | 0.88 / 1.30 |
| `"close"` | 0.11 | 0.11 | 0.38 / 0.70 | 0.67 / 0.79 |

### Windows laptop

One Windows 11 laptop (HP OMEN, NVMe SSD), Python 3.12, SAGE 2.3.0rc1, 500 spans per mode (200 for
`"span"`). Times are milliseconds per span measured at `end_span`. "End to end" divides the whole
run, including the seal, by the span count.

| Mode | Payload | Median | p95 | End to end | Seal |
| --- | --- | --- | --- | --- | --- |
| in memory (no journal) | 512 B | 0.043 | 0.062 | 0.10 | 26 |
| `"span"` | 512 B | 5.74 | 6.66 | 6.15 | 43 |
| `"batch"` (default) | 512 B | 0.081 | 0.12 | 0.32 | 108 |
| `"close"` | 512 B | 0.075 | 0.099 | 0.28 | 96 |
| in memory (no journal) | 4 KiB | 0.76 | 1.08 | 2.76 | 120 |
| `"span"` | 4 KiB | 16.8 | 19.4 | 15.6 | 26 |
| `"batch"` (default) | 4 KiB | 0.82 | 1.24 | 2.86 | 274 |
| `"close"` | 4 KiB | 0.83 | 1.52 | 2.80 | 221 |

What the numbers show:

- `"span"` pays four fsyncs inside every `end_span`, so it costs milliseconds per span. That is the
  price of losing no closed span in a crash.
- `"batch"` and `"close"` move the disk work to a background thread. `end_span` then costs about the
  same as recording with no journal at all. Their seal is slower because the seal waits for the last
  group commit and its fsyncs.
- Above 1 KiB, cost is dominated by hashing and offloading the payload, not by the journal.

## Choosing a mode

The loss window for each mode is in the README section "Live journal durability" and in the
residual risks of `THREAT_MODEL.md`. In short: use `"span"` when every closed span must survive a
crash, keep the default `"batch"` for agent workloads, and use `"close"` for short batch jobs where
only the sealed pack matters.
