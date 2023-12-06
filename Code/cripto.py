from Crypto import Random
import hashlib
from hashlib import sha1, md5
import hmac
import base64
from Crypto.Cipher import AES
from base64 import b64decode
from base64 import b64encode

from tokens import *


def encrypt(key, value):
    return hmac.new(key.encode("utf-8"), value.encode("utf-8"), sha1).hexdigest()

# authenticated encrypted


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


# def encrypt_aes(key, value):
#     cipher = AES.new(
#         md5(key).hexdigest().encode('utf8'), AES.MODE_CTR)
#     return cipher.encrypt(pickle.dumps(value))
#     # return b64encode(cipher.encrypt(value))


# def decrypt_aes(key, value):
#     cipher = AES.new(
#         md5(key).hexdigest().encode('utf8'), AES.MODE_CTR)
#     # value = cipher.decrypt(value)
#     print(cipher.decrypt(value))
#     return pickle.loads(cipher.decrypt(value))
######################################
#########Jorge Martins fc51033########
######################################


def encrypt(key, value):
    return hmac.new(key.encode("utf-8"), value.encode("utf-8"), sha1).hexdigest()

# authenticated encrypted


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


# def encrypt_aes(key, value):
#     cipher = AES.new(
#         md5(key).hexdigest().encode('utf8'), AES.MODE_CTR)
#     return cipher.encrypt(pickle.dumps(value))
#     # return b64encode(cipher.encrypt(value))


# def decrypt_aes(key, value):
#     cipher = AES.new(
#         md5(key).hexdigest().encode('utf8'), AES.MODE_CTR)
#     # value = cipher.decrypt(value)
#     print(cipher.decrypt(value))
#     return pickle.loads(cipher.decrypt(value))
