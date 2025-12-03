from Crypto.PublicKey import RSA

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
  
  def encryptMessage(plaintext):
    return ciphertext

  def decryptMessage(ciphertext):
    return plaintext

  def signMessage(plaintext):
    return signature

  def validateMessage(signature, pubKey):
    return isValid

# Use cases:
# Run the program as "Alice"
# Run the program as "Bob"