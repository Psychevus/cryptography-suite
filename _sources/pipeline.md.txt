# Pipeline API

The `Pipeline` class allows sequential composition of cryptographic modules. Each
module implements a simple `run` method. Pipelines can be built using the `>>`
operator and inspected as JSON.

## Pipeline DSL

The package ships with a small DSL for common cryptographic operations such as
AES-GCM encryption. Modules are importable from
`cryptography_suite.pipeline` and can be composed declaratively:

```python
from cryptography_suite.pipeline import (
    Pipeline,
    AESGCMEncrypt,
    AESGCMDecrypt,
    list_modules,
)

p = Pipeline() >> AESGCMEncrypt(password="pw") >> AESGCMDecrypt(password="pw")
print(p.run("hi"))        # 'hi'
print(list_modules())      # ['AESGCMDecrypt', 'AESGCMEncrypt']
```

## Extending the Pipeline DSL

Backends or applications can expose custom modules using the
`@register_module` decorator. Registered classes automatically appear in
`list_modules` and are importable from the pipeline namespace:

```python
from dataclasses import dataclass
from cryptography_suite.pipeline import CryptoModule, register_module

@register_module
@dataclass
class ROT13(CryptoModule[str, str]):
    def run(self, data: str) -> str:
        import codecs
        return codecs.encode(data, "rot13")

Pipeline() >> ROT13()
```

Use :func:`cryptography_suite.crypto_backends.use_backend` to switch the
backend providing primitive implementations.
