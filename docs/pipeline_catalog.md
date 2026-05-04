# Pipeline Module Catalog

Quick reference of built-in modules for the `Pipeline` DSL.

| Module | Description |
| --- | --- |
| AESGCMEncrypt | Encrypt data using AES-GCM. |
| AESGCMDecrypt | Decrypt AES-GCM data. |
| RSAEncrypt | Encrypt data using RSA-OAEP. |
| RSADecrypt | Decrypt RSA-OAEP ciphertext. |
| ECIESX25519Encrypt | Encrypt data using ECIES with X25519. |
| ECIESX25519Decrypt | Decrypt ECIES X25519 ciphertext. |
| HybridEncrypt | Encrypt using hybrid RSA/ECIES + AES-GCM. |
| HybridDecrypt | Decrypt data produced by HybridEncrypt. |
| MLKEMEncrypt | Encrypt data as a sealed ML-KEM/AES-GCM envelope. |
| MLKEMDecrypt | Decrypt data produced by MLKEMEncrypt. |
| KyberEncrypt | Deprecated compatibility wrapper for MLKEMEncrypt. |
| KyberDecrypt | Deprecated compatibility wrapper for MLKEMDecrypt. |
