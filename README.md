# X-Crypto
Python-based tool used to encrypt/decrypt via the command-line or API using symmetric and asymmetric cryptography.

## Install
```bash
pip install git+https://github.com/azweb76/x-crypto [--upgrade]
```
 
## Usage (encrypt)
To encrypt text.

```bash
# xcrypto encrypt [text | -]

xcrypto encrypt "my text"
# returns pFU2+m740G1pXzlZacgPPQ==

# from stdin
echo "this is a test" | xcrypto encrypt -
# returns pFU2+m740G1pXzlZacgPPQ==
```

## Usage (decrypt)
To decrypt text.

```bash
# xcrypto decrypt [encrypted_text | -]

xcrypto decrypt "pFU2+m740G1pXzlZacgPPQ=="
# returns "my text" 

# from stdin
echo "pFU2+m740G1pXzlZacgPPQ==" | xcrypto encrypt -
# returns "my text"
```
