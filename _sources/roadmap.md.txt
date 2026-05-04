# Experimental Feature Roadmap

The following checklists outline review and hardening work required before any
optional component could be considered for high-assurance use.

## Signal Protocol

- [ ] Multi-session support and message counters
- [ ] Persistent session/key storage
- [ ] Robust error handling and interoperability tests
- [ ] Consider extraction into a separate plugin repository

## Homomorphic Encryption

- [ ] Backend abstraction for alternative HE libraries
- [ ] Context serialization and parameter management
- [ ] Key and context lifecycle APIs
- [ ] Performance and security review

## Zero-Knowledge Proofs

- [ ] Unified context/key management layer
- [ ] Graceful error handling with conditional imports
- [ ] Broader proof system support and additional tests

