# setup.py
from setuptools import setup, find_packages

setup(
    name="cryptography-suite",
    version="0.1.0",
    description="A secure and easy-to-use cryptographic toolkit.",
    long_description=open("README.md", encoding="utf-8").read(),  # Specify utf-8 encoding here
    long_description_content_type="text/markdown",
    author="Mojtaba Zaferanloo",
    author_email="psychevus@gmail.com",
    url="https://github.com/Psychevus/cryptography-suite",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=3.4.7",
    ],
    entry_points={
        "console_scripts": [
            "cryptography-suite=cryptography_suite.__main__:main",
        ]
    },
)
