from User import User
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import os
import base64
import communicate as com


tester = User("tester", "test", True)
tester2 = User("Pablo", "test", True)
plaintext = "I can see this too".encode("utf-8")