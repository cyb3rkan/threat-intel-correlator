# TIC Load Tests

## Quick start

```bash
pip install locust
locust -f tests/load/locustfile.py --host http://127.0.0.1:8000
# Open http://localhost:8089 → set 10 users, 2 spawn rate → Start
```

## CI headless run

```bash
mkdir -p tests/load/results
locust -f tests/load/locustfile.py \
  --host http://127.0.0.1:8000 \
  --headless \
  --users 10 \
  --spawn-rate 2 \
  --run-time 60s \
  --csv tests/load/results/run \
  --exit-code-on-error 1
```

## SLO targets

| Endpoint | P95 target | Error budget |
|----------|-----------|--------------|
| `GET /api/health` | < 50 ms | 0% errors |
| `GET /api/ready` | < 200 ms | 0% errors |
| `GET /api/metrics` | < 100 ms | 0% errors |
| `POST /api/sweep` (stub, no providers) | < 5 000 ms | < 1% errors |

## User classes

| Class | Weight | Behavior |
|-------|--------|----------|
| `TicReadUser` | 3 | health + ready + metrics polls |
| `TicSweepUser` | 1 | CSV and NDJSON sweep submissions |
| `TicMixedUser` | 2 | 80% read, 20% sweep |

## Rate limiting validation

`SweepTasks.sweep_rate_limit_probe` deliberately bursts 3 rapid sweep
requests to validate that HTTP 429 is returned correctly and Retry-After
header is present.
