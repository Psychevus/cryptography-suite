# Misuse-Resistant Checking

The project ships with a custom **mypy** plugin that performs static
analysis to detect insecure cryptographic API usage. The plugin runs as
part of the type checking stage and will fail the build if dangerous
patterns are found.

Detected issues include:

- Use of weak hash functions like `md5` or `sha1`.
- Creating AES ciphers in `ECB` mode.

To enable the plugin manually add `tools.mypy_crypto_checker` to the
`plugins` option in your `mypy` configuration. The repository has this
enabled by default via ``setup.cfg``.

Code snippets that trigger the plugin can be found in
`examples/vulnerable.py`.

You can run the check locally with:

```bash
mypy examples/vulnerable.py
```

IDE integration works out of the box in PyCharm and VSCode when using the
project's `setup.cfg`.
