#!/usr/bin/env python
# coding: utf-8

import argparse
import base64
import glob
import os
import platform
import sys
import tempfile
import json
import time
import logging
from pymongo import MongoClient

import requests

log = logging.getLogger(name=__name__)


if platform.system() != 'Windows':
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from Crypto import Random
    from Crypto.Cipher import AES


def main():
    try:
        parser = argparse.ArgumentParser(
            description='Encrypt or decrypt text based on RSA.')

        parser.add_argument(
            '-m', '--mongo-url', default=os.environ.get('XCRYPTO_MONGO_URL', None),
            help='mongo endpoint for key storage')

        subparsers = parser.add_subparsers(help='actions')
        parser_a = subparsers.add_parser('encrypt', help='encrypt text')
        parser_a.add_argument('-n', '--name', default=None, help='name of secret')
        parser_a.add_argument('text', help='text to encrypt')
        parser_a.add_argument(
            '-k', '--key', help='path to public key or use XCRYPTO_KEY env')
        parser_a.add_argument('-w', '--width', default=60,
                              type=int, help='encrypt text delimited by newlines')
        parser_a.set_defaults(func=encrypt_cli)

        parser_a = subparsers.add_parser('decrypt', help='decrypt text')
        parser_a.add_argument('text', help='text to decrypt')
        parser_a.add_argument(
            '-k', '--key', help='path to private key or use XCRYPTO_KEY')
        parser_a.set_defaults(func=decrypt_cli)

        parser_a = subparsers.add_parser('get', help='get a remote secret')
        parser_a.add_argument('name', help='name of secret')
        parser_a.add_argument('-w', '--width', default=60,
                              type=int, help='encrypt text delimited by newlines')
        parser_a.add_argument(
            '-k', '--key', help='path to private key or use XCRYPTO_KEY')
        parser_a.set_defaults(func=get_cli)

        parser_a = subparsers.add_parser('save', help='save a remote secret')
        parser_a.add_argument('text', default='-', help='text to encrypt')
        parser_a.add_argument('-n', '--name', help='name of secret')
        parser_a.add_argument(
            '-k', '--key', help='path to private key or use XCRYPTO_KEY')
        parser_a.set_defaults(func=save_cli)

        parser_a = subparsers.add_parser('delete', help='save a remote secret')
        parser_a.add_argument('name', help='name of secret')
        parser_a.set_defaults(func=delete_cli)

        parser_a = subparsers.add_parser('edit', help='edit encrypted file')
        parser_a.add_argument('file', help='file to edit')
        parser_a.add_argument('-v', '--validate',
                              help='validate contents before saving')
        parser_a.add_argument(
            '-k', '--key', help='path to private key or use XCRYPTO_KEY')
        parser_a.set_defaults(func=edit_cli)

        args = parser.parse_args()
        args.func(args)
    except KeyboardInterrupt:
        exit(0)


BLOCK_SIZE = 16
DEFAULT_KEY_PATH = '~/.ssh/id_rsa'

_keys = {}


def get_key(key_path):
    global _keys
    if key_path is None or len(key_path) == 0:
        key_path = os.environ.get('XCRYPTO_KEY', DEFAULT_KEY_PATH)
    cache_key = key_path
    if cache_key not in _keys:
        if key_path.startswith('http'):
            resp = requests.get(key_path, verify=False)
            key = _keys[cache_key] = RSA.importKey(resp.text)
        else:
            with open(os.path.expanduser(key_path), 'r') as f:
                key = _keys[cache_key] = RSA.importKey(f.read())
    else:
        key = _keys[cache_key]
    return key


def new_thread():
    Random.atfork()


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


def read_value(message, opts):
    if message == '-':
        message = sys.stdin.read()
    return message


def delete_secret(secret_name, **kwargs):
    if 'mongo_url' in kwargs:
        client = MongoClient(kwargs['mongo_url'])
        x = client.xcrypto
        secrets = x.secrets

        resp = secrets.delete_one({"name": secret_name})
        return resp.deleted_count

    else:
        raise RuntimeError('not currently supported')


def get_secret(secret_name, private_key, **kwargs):
    if 'mongo_url' in kwargs:
        client = MongoClient(kwargs['mongo_url'])
        x = client.xcrypto
        secrets = x.secrets

        secret = secrets.find_one({"name": secret_name})
        if secret is None:
            raise RuntimeError('secret %s was not found' % secret_name)
        enc_str = secret['content']

        return decrypt(enc_str, private_key=private_key)

    raise RuntimeError('not currently supported')


def save_secret(secret_name, message, public_key=None, width=0, **kwargs):
    enc_str = encrypt(message, public_key=public_key, width=width)

    if 'mongo_url' in kwargs:
        client = MongoClient(kwargs['mongo_url'])
        x = client.xcrypto
        secrets = x.secrets

        secret = secrets.find_one({"name": secret_name})
        if secret:
            secrets.update_one({"name": secret_name}, {
                '$set': {
                    'content': enc_str
                }
            })
            sys.stdout.write('secret %s updated' % secret_name)
        else:
            secrets.insert_one(
                {
                    "name": secret_name,
                    "content": enc_str
                })
            sys.stdout.write('secret %s added' % secret_name)
        
        return True
    return False


def encrypt(message, public_key=None, width=60, **kwargs):
    """
    Encrypt a string using Asymmetric and Symmetric encryption.

    :param width:
    :param message: message to encrypt
    :param public_key: public key to use in encryption
    :return: encrypted string
    """
    random = Random.new()
    key = random.read(AES.key_size[0])
    passphrase = base64.b64encode(key)
    iv = Random.new().read(AES.block_size)

    def pad(s):
        return s + '\0' * (AES.block_size - len(s) % AES.block_size)

    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    message = read_value(message, kwargs)
    data = aes.encrypt(pad(message))

    token = rsa_encrypt(key + iv, public_key)

    enc_str = base64.b64encode(data + token).decode()

    if width > 0:
        x = split2len(enc_str, width)
        return '\n'.join(x)
    else:
        return enc_str


def decrypt(encrypted, private_key=None, **kwargs):
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

    return aes.decrypt(payload).rstrip(b'\0').decode()


def encrypt_cli(args):
    if args.text is None or args.text == '-':
        args.text = sys.stdin.read()
    sys.stdout.write(encrypt(args.text, args.key, args.width, mongo_url=args.mongo_url))


def save_cli(args):
    if args.text is None or args.text == '-':
        args.text = sys.stdin.read()
    save_secret(args.name, args.text, args.key, mongo_url=args.mongo_url)


def delete_cli(args):
    sys.stdout.write(delete_secret(args.name, mongo_url=args.mongo_url))


def get_cli(args):
    sys.stdout.write(get_secret(args.name, args.key, mongo_url=args.mongo_url))


def decrypt_cli(args):
    if args.text is None or args.text == '-':
        args.text = sys.stdin.read()
    sys.stdout.write(decrypt(args.text, args.key))


def edit_cli(args):
    try:
        decrypted = None
        tmp_file = tempfile.mkstemp()[1]
        if os.path.exists(args.file):
            with open(args.file, 'r') as fhd:
                decrypted = decrypt(fhd.read(), args.key)

            with open(tmp_file, 'w') as fhd:
                fhd.write(decrypted)

        tries = 0
        while True:
            os.system('vi %s' % tmp_file)

            try:
                decrypted_new = None
                if os.path.exists(tmp_file):
                    with open(tmp_file, 'r') as fhd:
                        decrypted_new = fhd.read()

                if decrypted_new == '':
                    exit()

                if args.validate == 'json':
                    json.loads(decrypted_new)
                break
            except KeyboardInterrupt:
                exit()

            except Exception as ex:
                tries += 1
                if tries >= 5:
                    exit('failed validation')
                sys.stdout.write(
                    'validation failed: %s, retrying...' % ex.message)
                time.sleep(3)

        if decrypted_new != decrypted:
            with open(args.file, 'w') as fhd:
                fhd.write(encrypt(decrypted_new, args.key))
            sys.stdout.write('Updated %s' % args.file)
        else:
            sys.stdout.write('No changes')
    finally:
        os.unlink(tmp_file)


if __name__ == '__main__':
    main()
