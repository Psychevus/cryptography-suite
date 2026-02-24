import warnings

from cryptography_suite.protocols import generate_hotp, generate_totp, verify_hotp


# RFC 4226 (HOTP) shared secret (ASCII): b"12345678901234567890"
RFC4226_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc4226_hotp_vectors_counter_0_to_9():
    expected = [
        "755224",
        "287082",
        "359152",
        "969429",
        "338314",
        "254676",
        "287922",
        "162583",
        "399871",
        "520489",
    ]

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        actual = [
            generate_hotp(RFC4226_SECRET_BASE32, counter=i, digits=6, algorithm="sha1")
            for i in range(10)
        ]

    assert actual == expected


def test_rfc6238_totp_vectors_sha1_sha256_sha512():
    timestamps = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]

    vectors = {
        "sha1": {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "expected": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
        },
        "sha256": {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            "expected": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
        },
        "sha512": {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
            "expected": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
        },
    }

    for algorithm, vector in vectors.items():
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            actual = [
                generate_totp(
                    vector["secret"],
                    interval=30,
                    digits=8,
                    algorithm=algorithm,
                    timestamp=ts,
                )
                for ts in timestamps
            ]
        assert actual == vector["expected"]


def test_verify_hotp_window_skips_negative_counters_without_crashing():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        code = generate_hotp(RFC4226_SECRET_BASE32, counter=0, digits=6, algorithm="sha1")

    # Regression: this verification window checks counter -1, which must be skipped.
    assert verify_hotp(code, RFC4226_SECRET_BASE32, counter=0, digits=6, window=1, algorithm="sha1")
