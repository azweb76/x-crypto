from setuptools import setup

setup(
    name="xcrypto",
    version="1.0.4",
    install_requires=[
        'PyCrypto',
    ],
    author = "Dan Clayton",
    author_email = "dan@azwebmaster.com",
    description = "Used to encrypt or decrypt based on an SSH RSA key pair.",
    license = "MIT",
    keywords = "encrypt decrypt",
    url = "https://github.com/azweb76/x-crypto",
    packages=['xcrypto'],
    entry_points={
        'console_scripts': [
            'xcrypto=xcrypto.xcrypto:main',
        ],
    },
)
