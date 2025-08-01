# Protocol Notes

The suite provides a light-weight X3DH implementation used for Signal-like
sessions. This code now lives under
``cryptography_suite.experimental.signal`` and **is strictly experimental**.
Use it only for demos or research. During session setup the receiver verifies
that the sender's ``signed_prekey`` is signed with the sender's identity key
using the helper ``verify_signed_prekey``. A failed verification raises
``SignatureVerificationError``.

One-time prekeys are optional. When present they are mixed into the Diffie–Hellman
chain as `dh4 = DH(IK_B, OPK_A)`. Each step of the chain (`dh1`, `dh2`, `dh3`, `dh4`)
is logged with `verbose_print` when `VERBOSE_MODE` is enabled.
