#!/usr/bin/env python

from setuptools import setup, find_packages


VERSION = "0.9.3"


setup(
    name="certapi",
    version=VERSION,
    description="Flask application providing HTTP API for Turris:Sentinel authentication backend",
    author="CZ.NIC, z.s.p.o.",
    author_email="packaging@turris.cz",
    url="https://gitlab.nic.cz/turris/sentinel/cert-api",
    packages=find_packages(exclude=("tests*",)),
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
    },
)
