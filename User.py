from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import os

class User:
  # Initialize the user with username and password, and create a key pair.
  def __init__(self, username, password):
    self.username = username
    self.password = password.encode("utf-8")
    print("Generating the key pair...")
    self.keypair = RSA.generate(3072)
    print("Key pair for user " + self.username + " generated")

  # Store the private key in a secure, password protected pem file
  def storePrivateKey(self):
    print("Storing the private key...")
    with open(self.username + "privatekey.pem", "wb") as fp:
      data = self.keypair.export_key(passphrase=self.password,
                                     pkcs=8,
                                     protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                     prot_params={'iteration_count':131072})
      fp.write(data)
    print("Private key stored to: " + self.username + "privatekey.pem")

  # Store the public key in an unsecure pem file so anyone can use it
  def storePublicKey(self):
    print("Storing the public key...")
    with open(self.username + "publickey.pem", "wb") as fp:
      data = self.keypair.public_key().export_key()
      fp.write(data)
    print("Public key stored to: " + self.username + "publickey.pem")
  
  def encryptMessage(self, plaintext, receiverPublic):
    ciphertextAES = self._AESEncryption(plaintext)
    ciphertext = self._RSAEncryption(ciphertextAES, receiverPublic)
    return ciphertext

  def decryptMessage(self, ciphertext):
    with open(self.username+"privatekey.pem", "rb") as privateFile:
      data = privateFile.read()
      privateKey = RSA.import_key(data, self.password)
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
