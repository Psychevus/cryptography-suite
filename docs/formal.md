# Formal Verification Support

Pipelines can be exported to simple ProVerif or Tamarin models using the
`export` CLI command. The exported files are intentionally lightweight and only
capture the order of pipeline steps and any secrets you choose to track.
They are suitable for quick syntax checking but **do not** automatically encode
complex protocol semantics.

Example:
```
cryptography-suite export examples/formal/pipeline.yaml --format proverif
```

Known limitations:

- Only the names of pipeline modules are exported. No cryptographic operations
  are modeled beyond the provided stubs.
- Claims such as secrecy or authentication are not generated automatically.
- For anything more than syntax checking, you will need to edit the model
  manually.

Typical queries you may want to add by hand include:

- confidentiality of generated keys or plaintexts
- authentication of communicating parties
- replay resistance

