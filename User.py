from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import os
import base64
from hmac import generateSecret, genHash, verifyHash

class User:
  # Initialize the user with name, password, and working keypair
  def __init__(self, name, password, makeAccount = True):
    
    #if returning user, verifies account
    if(makeAccount):
      if(not self.verifyUser(name, password)):
        raise BadLoginExist("",1)
      else:
        self.name = name
        self.password = password.encode("utf-8")
    # if new user, creates new user
    elif(os.path.isfile("keys/"+name+"publickey.pem")):\
        raise BadLoginNew("",2)
    else:
      self.name = name
      self.password = password.encode("utf-8")
      self.generateKeys()

  #verifies that the user exists and that the correct password was used
  def verifyUser(self, name, password):
    if (not os.path.isfile("keys/"+name+"privatekey.pem") ):
      validPassword = False
    try:
      with open("keys/"+name+"privatekey.pem", "rb") as privateFile:
        data = privateFile.read()
        privateKey = RSA.import_key(data, password)
        validPassword = True
    except:
      validPassword = False
    finally:
      return validPassword

  #generates key pair for user
  def generateKeys(self):
    print("\nGenerating the key pair...")
    keypair = RSA.generate(3072)
    self.storePrivateKey(keypair)
    self.storePublicKey(keypair)
    print("Key pair for user " + self.name + " generated")

  # Store the private key in a secure, password protected pem file
  def storePrivateKey(self, keypair):
    print("Storing the private key...")
    with open("keys/"+self.name + "privatekey.pem", "wb") as fp:
      data = keypair.export_key(passphrase=self.password,
                                     pkcs=8,
                                     protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                     prot_params={'iteration_count':131072})
      fp.write(data)
    print("Private key stored to: " + self.name + "privatekey.pem")

  # Store the public key in an unsecure pem file so anyone can use it
  def storePublicKey(self, keypair):
    print("Storing the public key...")
    with open("keys/"+self.name + "publickey.pem", "wb") as fp:
      data = keypair.public_key().export_key()
      fp.write(data)
    print("Public key stored to: " + self.name + "publickey.pem")

  #destroys all User data from keys folder
  def destroyUserData(self):
    
    print("Destroying all shared secrets")
    #finds all keys containing username in proper format for file name
    #then delete them
    print("Destroying the private key...")
    os.remove("keys/"+self.name+"privatekey.pem")
    print("Done.")
    print("Destroying the public key...")
    os.remove("keys/"+self.name+"publickey.pem")
    print("Done.")


  # Encrypt the message using a unique AES key, then further encrypt the ciphertext with the receiver's public key.
  def encryptMessage(self, plaintext, RSAKey):
    dataAES = self.AESEncryption(plaintext)
    encryptedAESKeyAndNonce = self.RSAEncryption(dataAES[1], RSAKey)    
    ciphertext = base64.b64encode(dataAES[0] + encryptedAESKeyAndNonce).decode('ascii')

    return f"{ciphertext}"

  def decryptMessage(self, ciphertext):
    with open("keys/"+self.name+"privatekey.pem", "rb") as privateFile:
      data = privateFile.read()
      privateKey = RSA.import_key(data, self.password)
      AESKeyAndNonce = self.RSADecryption(ciphertext[-384:], privateKey)
      plaintext = self.AESDecryption(ciphertext[:-384],  AESKeyAndNonce)
      return plaintext

  # Encrypt message with a random 16-byte key,
  # then return the resulting ciphertext with the AES nonce and AES key appended to it.
  def AESEncryption(self, plaintext):
    #generate AES key and cipher
    AESKey = os.urandom(16)
    cipher = AES.new(AESKey, AES.MODE_EAX)
    AESNonce = cipher.nonce

    #encrypts and appends needs data for decryption
    ciphertext = bytearray(cipher.encrypt(plaintext))
    AESdata = AESKey + AESNonce

    return ciphertext, AESdata

  # Decrypt a message that is encrypted using AES
  def AESDecryption(self, ciphertext, AESKeyAndNonce):
    decipher = AES.new(AESKeyAndNonce[:-16], AES.MODE_EAX, nonce = AESKeyAndNonce[-16:])
    plaintext = decipher.decrypt(ciphertext)

    return plaintext

  # Encrypt using the given RSA key (use the receiver's public key)
  def RSAEncryption(self, plaintext, RSAKey):
    cipher = PKCS1_OAEP.new(RSAKey)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

  # Decrypt using the the given RSA key (use the receiver's private key)
  def RSADecryption(self, ciphertext, RSAKey):
    cipher = PKCS1_OAEP.new(RSAKey)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext
  
class BadLoginExist(Exception):
  def __init__(self, message, error_code):
    super().__init__(message)
    self.error_code = error_code

  def __str__(self):
    return f"{self.message}   Error Code: {self.error_code}"
  
class BadLoginNew(Exception):
  def __init__(self, message, error_code):
    super().__init__(message)
    self.error_code = error_code

  def __str__(self):
    return f"{self.message}   Error Code: {self.error_code}"