# Pipeline API

The `Pipeline` class allows sequential composition of cryptographic modules. Each
module implements a simple `run` method. Pipelines can be built using the `>>`
operator and inspected as JSON.

Example:

```python
from cryptography_suite.pipeline import Pipeline

class UpperCase:
    def run(self, data: bytes) -> bytes:
        return data.upper()

p = Pipeline() >> UpperCase()
print(p.run(b"abc"))  # b'ABC'
```
