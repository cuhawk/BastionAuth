# Wave 6 verification results

Measured in Codex Cloud using the loopback HTTP token exchange benchmark.

| Metric | CI-sized run | 16-worker run |
| --- | ---: | ---: |
| Requests | 500 | 4,000 |
| Workers | 8 | 16 |
| Request failures | 0 | 0 |
| Requests per second | 4982.49 | 4365.89 |
| p50 latency | 1.314296ms | 3.041158ms |
| p95 latency | 3.084039ms | 7.327932ms |
| p99 latency | 4.027375ms | 9.386723ms |
| Allocations per operation | 802 | 802 |

The race suite passed 19 tests and 99 subtests against PostgreSQL 16.16, with 0 test skips and no data race reports. The migration linter checked four migrations.
