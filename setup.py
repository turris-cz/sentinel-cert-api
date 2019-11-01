#!/usr/bin/env python

from setuptools import setup


VERSION = "0.7"


setup(
    name="certapi",
    author="CZ.NIC, z.s.p.o.",
    author_email="packaging@turris.cz",
    version=VERSION,
    zip_safe=False,
    include_package_data=True,
    packages=["certapi"],
    install_requires=[
        "flask",
        "python-dotenv",
        "cryptography",
        "redis",
    ],
    extras_require={
        "tests": [
            "pytest",
            "coverage",
            "pytest-cov",
        ],
    }
)
