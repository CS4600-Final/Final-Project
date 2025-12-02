from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import os

class User:
  publicKey = ''
  privateKey = ''
  def encryptMessage(self, plaintext, receiverPublic):
    ciphertextAES = self._AESEncryption(plaintext)
    ciphertext = self._RSAEncryption(ciphertextAES, receiverPublic)
    return ciphertext

  def decryptMessage(self, ciphertext, privateKey):
    ciphertextAES = self._RSADecryption(ciphertext, privateKey)
    plaintext = self._AESDecryption(ciphertextAES[:-32], ciphertextAES[-32:-16], ciphertextAES[-16:] )
    return plaintext

  def signMessage(self, plaintext):
    return signature

  def validateMessage(self, signature, pubKey):
    return isValid
  
  def _AESEncryption(self, plaintext):
    #generate AES key and cipher
    AESKey = os.urandom(16)
    cipher = AES.new(AESKey, AES.MODE_EAX)
    AESNonce = cipher.nonce

    #encrypts and appends needs data for decryption
    ciphertext = bytearray(cipher.encrypt(plaintext))
    ciphertext += AESNonce
    ciphertext += AESKey
    byteciphertext = bytes(ciphertext)

    return byteciphertext
  
  def _AESDecryption(self, ciphertext, encryptedNonce, AESKey):
    decipher = AES.new(AESKey, AES.MODE_EAX, nonce = encryptedNonce)
    plaintext = decipher.decrypt(ciphertext)

    return plaintext
  
  def _RSAEncryption(self, plaintext, RSAKey):    #
    cipher = PKCS1_OAEP.new(RSAKey)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext
  
  def _RSADecryption(self, ciphertext, RSAKey):
    cipher = PKCS1_OAEP.new(RSAKey)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext

#used for testing with no official way of key generation
test = User()
key = RSA.generate(3072)
with open("private.txt", "wb") as privateKeyFile:
  privateKeyFile.write(key.exportKey('PEM'))
with open("public.txt", "wb") as publicKeyFile:
  publicKeyFile.write(key.public_key().exportKey('PEM'))

with open("public.txt", "rb") as public_key_file:
  publicKey = RSA.importKey(public_key_file.read())
with open("private.txt", "rb") as private_key_file:
  privateKey = RSA.importKey(private_key_file.read())

#test._RSAEncryption(b'testing',key)
#print(test._RSADecryption(test._RSAEncryption(b'testing', publicKey ), privateKey  ) )
#importantInfo = test._AESEncryption(b"testing")
#print("\n",importantInfo[:-32],importantInfo[-32:-16], importantInfo[-16:] )
#print(test._AESDecryption(importantInfo[:-32],importantInfo[-32:-16], importantInfo[-16:]))
