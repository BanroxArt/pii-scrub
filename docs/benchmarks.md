# Benchmarks

Run them yourself:

```
make bench
```

or `PYTHONPATH=src python bench/run.py`. The script uses `timeit` from the
standard library and reports the best of five repeats, so the numbers are a
floor for one CPU core, not a throughput promise. Compare runs on the same
machine only.

Last recorded run, Nov 14, 2026, on a shared cloud VM (Intel Xeon, 1 core in use):

Python 3.13.5 on x86_64 (linux)

| case | µs/op | ops/s |
|---|---:|---:|
| mask, clean line (168 chars) | 35.29 | 28,336 |
| mask, line with 5 findings (126 chars) | 62.39 | 16,028 |
| pseudonym (HMAC), line with 5 findings | 95.54 | 10,466 |
| scrub_obj, nested record (12 strings) | 605.61 | 1,651 |
| mask, 1,000-line blob (147,999 chars) | 158,467.90 | 6 |
