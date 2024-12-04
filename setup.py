from setuptools import setup, find_packages

setup(
    name="cryptography-suite",
    version="1.0.0",
    description="A comprehensive and secure cryptographic toolkit.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Mojtaba Zaferanloo",
    author_email="psychevus@gmail.com",
    url="https://github.com/Psychevus/cryptography-suite",
    packages=find_packages(),
    include_package_data=True,
    license="MIT",
    keywords=[
        "cryptography",
        "encryption",
        "security",
        "AES",
        "RSA",
        "ChaCha20",
        "Ed25519",
        "ECDSA",
        "hashing",
        "PAKE",
        "OTP",
        "secret sharing",
    ],
    classifiers=[
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.3",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "coverage",
            "coveralls",
        ],
    },
    project_urls={
        "Documentation": "https://github.com/Psychevus/cryptography-suite#readme",
        "Source": "https://github.com/Psychevus/cryptography-suite",
        "Tracker": "https://github.com/Psychevus/cryptography-suite/issues",
    },
)
