from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from User import User
import os
from hmac import genHash, verifyHash, generateSecret


def sendMsg(sender, receiverName, message):
  # obtain the ciphertext using the receiver's public key
  receiverPubKey = getPublicKey(receiverName)
  ciphertext = sender.encryptMessage(message, receiverPubKey)
  signedMsg = signMessage(sender, receiverName, ciphertext)
  file = open("Transmitted_Data.txt", "ba")
  file.write(signedMsg)
  file.close()

def receiveMessages(receiver):
  # assume Transmit file is formatted as Receiver Sender Message or 
  # if public key is written as PK User PublicKey
  file = open("Transmitted_Data.txt", "r")

  receivedMessages = []
  for line in file:
    input = line.readLine().strip().split()  #cleans input
    if (input[0] == receiver):
      receivedMessages.append(input[1:]) #gets encrypted data, which might contain whitespace

  print("You have received", len(receivedMessages), "messages.")
  for message in receivedMessages:
    input("press enter to read nest message")
    target, hmac, rawMsg = message.split(".")
    #print("Target: " + target + "\t hmac: " + hmac + "\t rawMsg: " + rawMsg)
    print(validateMessage(target, hmac, message))
    print(decryptMessage(rawMsg[0], rawMsg[1:]))

  return 0

def decryptMessage(receiverName, encMessage, password):
  host = User(receiverName, password)
  host.decryptMessage(encMessage)

def getPublicKey(userName):
  publicKey = RSA.import_key(open(userName+"publickey.pem").read())
  return publicKey

# Store a shared key between users in a secure, password protected file
def storeMacKey(host, target, secret):
  print("Storing the shared key...")
  with open(host.name + "_" + target + ".key", "wb") as fp:
    rsaKey = getPublicKey(host.name)
    data = host._RSAEncryption(secret.encode("utf-8"), rsaKey)
    fp.write(data)
  print("Secret stored to " + host.name + "_" + target + ".key")

#Retrieve a shared key between users from a secure file.
def retrieveMacKey(host, target):
  #Need to search for keys
  #Both user.name+target.name AND target.name+user.name key files
  #If not found, should create and store a new key
  print("Retrieving shared key...")
  if(os.path.isfile(host.name + "_" + target + ".key")):
    macKey = host.name + "_" + target + ".key"
  elif(os.path.isfile(target + "_" + host.name + ".key")):
    macKey = target + "_" + host.name + ".key"
  else:
    print("No key found, creating new key...")
    key = generateSecret()
    storeMacKey(host, target, key)
    print(key)
    return key


  with open(macKey, "rb") as fp:
    rawPrivate = open(host.name + "privatekey.pem", "rb")
    privateKey = RSA.import_key(rawPrivate.read(), host.password)
    #publicKey = getPublicKey(host.name)
    keyEncrypt = fp.read()
    data = host._RSADecryption(keyEncrypt, privateKey) 
    return data
    
def signMessage(host, target, plaintext):
  secret = retrieveMacKey(host, target)
  hmac = genHash(plaintext, secret)
  signedMsg = f"{host.name}.{hmac}.{plaintext}"

  return signedMsg

def validateMessage(target, hmac, message):
  secret = retrieveMacKey(target)
  isValid = verifyHash(message, hmac, secret)
  return isValid
