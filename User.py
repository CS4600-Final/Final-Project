from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import os
from hmac import generateSecret, genHash, verifyHash

class User:
  # Initialize the user with name and password, and create a key pair.
  def __init__(self, name, password):
    self.name = name
    self.password = password.encode("utf-8")
    print("Generating the key pair...")
    self.keypair = RSA.generate(3072)
    print("Key pair for user " + self.name + " generated")

  # Store the private key in a secure, password protected pem file
  def storePrivateKey(self):
    print("Storing the private key...")
    with open(self.name + "privatekey.pem", "wb") as fp:
      data = self.keypair.export_key(passphrase=self.password,
                                     pkcs=8,
                                     protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                     prot_params={'iteration_count':131072})
      fp.write(data)
    print("Private key stored to: " + self.name + "privatekey.pem")

  # Store the public key in an unsecure pem file so anyone can use it
  def storePublicKey(self):
    print("Storing the public key...")
    with open(self.name + "publickey.pem", "wb") as fp:
      data = self.keypair.public_key().export_key()
      fp.write(data)
    print("Public key stored to: " + self.name + "publickey.pem")

  def destroyKeys(self):
    print("Destroying the private key...")
    os.remove(self.name+"privatekey.pem")
    print("Done.")
    print("Destroying the public key...")
    os.remove(self.name+"publickey.pem")
    print("Done.")

  # Encrypt the message using a unique AES key, then further encrypt the ciphertext with the receiver's public key.
  def encryptMessage(self, plaintext, RSAKey):
    ciphertextAES = self._AESEncryption(plaintext)
    ciphertext = self._RSAEncryption(ciphertextAES, RSAKey)
    return ciphertext

  def decryptMessage(self, ciphertext):
    with open(self.name+"privatekey.pem", "rb") as privateFile:
      data = privateFile.read()
      privateKey = RSA.import_key(data, self.password)
      ciphertextAES = self._RSADecryption(ciphertext, privateKey)
      plaintext = self._AESDecryption(ciphertextAES[:-32], ciphertextAES[-32:-16], ciphertextAES[-16:] )
      return plaintext

  # Encrypt message with a random 16-byte key, then return the resulting ciphertext with the AES nonce and AES key appended to it.
  def _AESEncryption(self, plaintext):
    #generate AES key and cipher
    AESKey = os.urandom(16)
    cipher = AES.new(AESKey, AES.MODE_EAX)
    AESNonce = cipher.nonce

    #encrypts and appends needs data for decryption
    ciphertext = bytearray(cipher.encrypt(plaintext.encode("utf-8")))
    ciphertext += AESNonce
    ciphertext += AESKey
    byteciphertext = bytes(ciphertext)

    return byteciphertext

  # Decrypt a message that is encrypted using AES
  def _AESDecryption(self, ciphertext, encryptedNonce, AESKey):
    decipher = AES.new(AESKey, AES.MODE_EAX, nonce = encryptedNonce)
    plaintext = decipher.decrypt(ciphertext)

    return plaintext

  # Encrypt using the given RSA key (use the receiver's public key)
  def _RSAEncryption(self, plaintext, RSAKey):
    cipher = PKCS1_OAEP.new(RSAKey)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

  # Decrypt using the the given RSA key (use the receiver's private key)
  def _RSADecryption(self, ciphertext, RSAKey):
    cipher = PKCS1_OAEP.new(RSAKey)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext
  

