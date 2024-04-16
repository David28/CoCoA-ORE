from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import hashlib
from hashlib import sha1, md5
import hmac
import base64
from Crypto.Cipher import AES
from base64 import b64decode
from base64 import b64encode

from tokens import *

# DET encryption

def encrypt(key, value):
    return hmac.new(key.encode("utf-8"), value.encode("utf-8"), sha1).hexdigest()
#    return AES.new(key, AES.MODE_CBC, "0000000000000000".encode(),use_aesni=True).encrypt(pad(value.encode("utf-8"),16))

# RND encryption

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
#        self.key = key

    def encrypt(self, raw):
#        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv, use_aesni=True)
#        return base64.b64encode(iv + cipher.encrypt(raw.encode()))
        return base64.b64encode(iv + cipher.encrypt(pad(raw.encode(),16)))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv, use_aesni=True)
#        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
        return unpad(cipher.decrypt(enc[AES.block_size:]),16).decode('utf-8')

    # def _pad(self, s):
    #     return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    # @staticmethod
    # def _unpad(s):
    #     return s[:-ord(s[len(s)-1:])]



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
