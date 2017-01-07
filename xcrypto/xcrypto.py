#!/usr/bin/env python
# coding: utf-8

import argparse
import base64
import glob
import os
import platform
import readline
import sys

import requests


if platform.system() != 'Windows':
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from Crypto import Random
    from Crypto.Cipher import AES


def complete(text, state):
    if str(text).startswith('~/'):
        home = os.path.expanduser('~/')
        p = os.path.join(home, text[2:])
    else:
        p = text
        home = None

    items = glob.glob(p+'*')
    if items is not None and home is not None:
        items = ['~/' + x[len(home):] for x in items]
    return (items+[None])[state]


readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)


def main():
    try:
        parser = argparse.ArgumentParser(description='Encrypt or decrypt text based on RSA.')

        subparsers = parser.add_subparsers(help='actions')
        parser_a = subparsers.add_parser('encrypt', help='encrypt text')
        parser_a.add_argument('text', help='text to encrypt')
        parser_a.add_argument('-k', '--key', help='path to public key or use XCRYPTO_KEY env')
        parser_a.add_argument('-w', '--width', default=60, type=int, help='encrypt text delimited by newlines')
        parser_a.set_defaults(func=encrypt_cli)

        parser_a = subparsers.add_parser('decrypt', help='decrypt text')
        parser_a.add_argument('text', help='text to decrypt')
        parser_a.add_argument('-k', '--key', help='path to private key or use XCRYPTO_KEY')
        parser_a.set_defaults(func=decrypt_cli)

        args = parser.parse_args()
        args.func(args)
    except KeyboardInterrupt:
        exit(0)


BLOCK_SIZE = 16
DEFAULT_KEY_PATH = '~/.ssh/id_rsa'

_keys = {}


def get_key(key_path):
    global _keys
    if 'XCRYPTO_KEY' in os.environ:
        key_path = os.environ['XCRYPTO_KEY']
    if key_path not in _keys:
        if key_path.startswith('http'):
            resp = requests.get(key_path, verify=False)
            key = _keys[key_path] = RSA.importKey(resp.text)
        else:
            with open(os.path.expanduser(key_path), 'r') as f:
                key = _keys[key_path] = RSA.importKey(f.read())
    else:
        key = _keys[key_path]
    return key


def split2len(s, n):
    def _f(s, n):
        while s:
            yield s[:n]
            s = s[n:]
    return list(_f(s, n))


def rsa_encrypt(decrypted, key_path):
    key = get_key(key_path)

    public_key = key.publickey()
    encrypted = public_key.encrypt(decrypted, 32)

    return encrypted[0]


def rsa_decrypt(encrypted, key_path):
    key = get_key(key_path)

    decrypted = key.decrypt(encrypted)

    return decrypted


def encrypt(message, public_key=None, width=60):
    """
    Encrypt a string using Asymmetric and Symmetric encryption.

    :param message: message to encrypt
    :param public_key: public key to use in encryption
    :return: encrypted string
    """
    random = Random.new()
    key = random.read(AES.key_size[0])
    passphrase = base64.b64encode(key)
    iv = Random.new().read(AES.block_size)

    def pad(s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    if message == '-':
        message = sys.stdin.read()
    data = aes.encrypt(pad(message))

    token = rsa_encrypt(key+iv, public_key)

    enc_str = base64.b64encode(data + token)

    if width > 0:
        print '\n'.join(split2len(enc_str, width))
    else:
        print enc_str


def decrypt(encrypted, private_key=None):
    """
    Decrypt a string using Asymmetric and Symmetric encryption.

    :param encrypted: message to decrypt
    :param private_key: private key to use in decryption
    :return: decrypted string
    """
    encrypted = ''.join(encrypted.split('\n'))

    data = base64.b64decode(encrypted)

    payload = data[:-256]
    token = rsa_decrypt(data[-256:], private_key)

    passphrase = base64.b64encode(token[:AES.key_size[0]])
    iv = token[AES.key_size[0]:]

    aes = AES.new(passphrase, AES.MODE_CBC, iv)

    return aes.decrypt(payload).rstrip(b"\0")


def encrypt_cli(args):
    if args.text is None or args.text == '-':
        args.text = sys.stdin.read()
    print encrypt(args.text, args.key or DEFAULT_KEY_PATH)


def decrypt_cli(args):
    if args.text is None or args.text == '-':
        args.text = sys.stdin.read()
    print decrypt(args.text, args.key or DEFAULT_KEY_PATH)


if __name__ == '__main__':
    main()
