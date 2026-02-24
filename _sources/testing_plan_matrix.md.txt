# Test Plan Matrix

| Module | Primary risks | Unit | Integration | Contract | Negative/edge | Property-based |
| --- | --- | --- | --- | --- | --- | --- |
| `cryptography_suite/core/settings.py` | Invalid env parsing, wrong defaults, cache behavior drift, concurrent access | ✅ normalization/parsing | ✅ `config` facade reload | ✅ subprocess env boundary | ✅ invalid env/strict key values | ✅ Hypothesis for accepted values |
| `cryptography_suite/core/errors.py` | Typed error semantics regressions | ✅ `SuiteError.__str__`, `format_with_code` | ✅ used by settings failures | N/A | ✅ error code assertions | N/A |
| `cryptography_suite/audit.py` | Timestamp format drift, encrypted log format breakage, logger wiring | ✅ in-memory and file logger behavior | ✅ decorator with configured logger | ✅ encrypted file line format (`timestamp|operation|status`) | ✅ failure-path logging | N/A |
| `cryptography_suite/cli.py` | CLI UX regressions, argument parsing contract breaks | ✅ command option paths | ✅ end-to-end `script_runner` tests | ✅ subprocess return code/output | ✅ invalid args and file errors | N/A |
| `cryptography_suite/keystores/local.py` | key persistence corruption, insecure key handling | ✅ serialization routines | ✅ migrate/import flows | ✅ filesystem paths and metadata files | ✅ malformed input / missing key IDs | N/A |

**Notes**
- Timeout/retry scenarios are validated in modules that implement retries; they are not applicable to pure parsing/config primitives.
- Concurrency coverage is explicitly included for settings cache access.
