# Fuzzing harnesses

Run one harness locally as a smoke check:

```bash
python fuzz/fuzz_aes.py -runs=100
```

Run all harnesses locally:

```bash
for h in aes rsa ecies pipeline; do python "fuzz/fuzz_${h}.py" -runs=100; done
```
