from setuptools import setup


setup(
    name="certapi",
    author="CZ.NIC, z.s.p.o.",
    author_email="packaging@turris.cz",
    zip_safe=False,
    include_package_data=True,
    packages=["certapi"],
    install_requires=[
        "flask",
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
