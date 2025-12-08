from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from User import User
import os
import base64
from hmac import genHash, verifyHash, generateSecret

#sends message from host to receiver
def sendMsg(sender, receiverName, message):
  # obtain the ciphertext using the receiver's public key
  receiverPubKey = getPublicKey(receiverName)
  ciphertext = sender.encryptMessage(message, receiverPubKey)
  signedMsg = messageSignature(sender, receiverName, ciphertext )
  file = open("Transmitted_Data.txt", "a")
  file.write(receiverName + " " + sender.name + " " + ciphertext + " " + signedMsg + "\n")
  file.close()

#checks for messages meant for the user, and prints them out if they meet the security requirements
def receiveMessages(receiver: User):
  file = open("Transmitted_Data.txt", "r")

  #gets all messages possibly sent to user
  receivedMessages = []
  for line in file:
    input = line.strip().split()  #cleans input
    if(input[0] == receiver.name):
      receivedMessages.append(input) #gets encrypted data, which might contain whitespace

  #checks is receiver got any mesages
  if len(receivedMessages) != 0:
    print("You have", len(receivedMessages), "messages.")

    #verifies each message found then prints it if valid
    for message in receivedMessages:
      try:
        sender, message, hmac = message[1:]
        decodeHMAC = base64.b64decode(hmac.encode("utf-8"))
        decodeMsg = base64.b64decode(message.encode("ascii"))
        secret = retrieveMacKey(receiver, sender)
        is_Valid = verifyHash(decodeMsg, decodeHMAC, secret)
        if(is_Valid):
          print(receiver.decryptMessage(decodeMsg))
        else:
          print("Message integrity compromised")
      except ValueError:
        print("Sent message has invalid format")
      except NoSharedSecret:
        print("No shared secret with", sender)
  else:
    print("There are no messages for you to read.")

#gets public key of user that is not the host
def getPublicKey(userName):
  publicKey = RSA.import_key(open("keys/"+userName+"publickey.pem").read())
  return publicKey

# Store a shared key between users in a secure, password protected file
def storeMacKey(host, target, secret):
  #stores shared secret for host to use with target user in key file
  print("Storing the shared key...")
  with open("keys/"+host.name + "_" + target + ".key", "wb") as fp:
    rsaKey = getPublicKey(host.name)
    data = host.RSAEncryption(secret, rsaKey)
    fp.write(data)

  #stores shared secret for target to use with host user in key file
  with open("keys/"+target + "_" + host.name + ".key", "wb") as fp:
    rsaKey = getPublicKey(target)
    data = host.RSAEncryption(secret, rsaKey)
    fp.write(data)

  print("Shared secret with",target, "has been made.")
  

#Retrieve a shared key between users from a secure file.
def retrieveMacKey(host, target):
  #If shared secret not found
  if(os.path.isfile("keys/"+host.name + "_" + target + ".key")):
    macKey = "keys/"+host.name + "_" + target + ".key"
    with open(macKey, "rb") as fp:
      with open("keys/"+host.name+"privatekey.pem", "rb") as privateFile:
        rawPrivate = privateFile.read()
        privateKey = RSA.import_key(rawPrivate, host.password)
        keyEncrypt = fp.read()
        data = host.RSADecryption(keyEncrypt, privateKey) 
        return data
  else:
    raise NoSharedSecret("Mac File not found", 6767)

    
def messageSignature(host, target, ciphertext):
  try:
    secret = retrieveMacKey(host, target)
  except NoSharedSecret:
    print("No key found, creating new key...")
    key = generateSecret()
    storeMacKey(host, target, key)
    secret = key

  ciphertextSign = base64.b64decode(ciphertext.encode("ascii"))
  hmac = genHash(ciphertextSign, secret)

  print(hmac)
  # host_name_b64 = base64.b64encode(host.name.encode('utf-8')).decode('ascii')
  signature = base64.b64encode(hmac).decode('ascii')
  # ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')

  # 4. Construct the final signed message string using the Base64 components
  # signedMsg = f"{host_name_b64}.{hmac_b64}.{ciphertext_b64}"

  return f"{signature}"

def validateMessage(target, hmac, message):
  secret = retrieveMacKey(target)
  isValid = verifyHash(message, hmac, secret)
  return isValid

class NoSharedSecret(Exception):
  def __init__(self, message, error_code):
    super().__init__(message)
    self.error_code = error_code

  def __str__(self):
    return f"{self.message}   Error Code: {self.error_code}"
  
