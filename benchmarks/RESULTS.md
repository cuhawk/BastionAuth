# Wave 4 verification results

| Loopback HTTP token exchange | CI-sized run | 16-worker run |
| --- | ---: | ---: |
| Requests | 500 | 4,000 |
| Workers | 8 | 16 |
| Request failures | 0 | 0 |
| Requests per second | 5,401.23 | 5,177.61 |
| p50 latency | 1.255791 ms | 2.515217 ms |
| p95 latency | 2.711483 ms | 5.797908 ms |
| p99 latency | 3.125615 ms | 10.137766 ms |
| Allocations per operation | 791 | 791 |

The race-enabled suite against PostgreSQL 16.16 passed 17 tests and 98 subtests, with zero skips and zero data race reports. The migration linter checked three migrations.
