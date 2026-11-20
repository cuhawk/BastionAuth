# Wave 3 verification results

The loopback HTTP token exchange benchmark completed 4,000 requests with 16 workers and zero request failures.

| Metric | Observed |
| --- | ---: |
| Requests per second | 3,861.18 |
| p50 latency | 3.446477 ms |
| p95 latency | 8.190801 ms |
| p99 latency | 10.952736 ms |
| Allocations per operation | 766 |

The race-enabled suite against PostgreSQL 16 passed 15 tests and 87 subtests, with zero skips and zero data race reports.
