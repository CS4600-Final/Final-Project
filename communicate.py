from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from User import User
import os
import base64
from hmac import genHash, verifyHash, generateSecret


def sendMsg(sender, receiverName, message):
  # obtain the ciphertext using the receiver's public key
  receiverPubKey = getPublicKey(receiverName)
  ciphertext = sender.encryptMessage(message, receiverPubKey)
  signedMsg = messageSignature(sender, receiverName, ciphertext )
  file = open("Transmitted_Data.txt", "a")
  file.write(receiverName + " " + sender.name + " " + ciphertext + " " + signedMsg + "\n")
  file.close()

def receiveMessages(receiver: User):
  # assume Transmit file is formatted as Receiver Sender Message or 
  # if public key is written as PK User PublicKey
  file = open("Transmitted_Data.txt", "r")

  receivedMessages = []
  for line in file:
    input = line.strip().split()  #cleans input
    if(input[0] == receiver.name):
      receivedMessages.append(input) #gets encrypted data, which might contain whitespace

  print("You have", len(receivedMessages), "messages.")
  for message in receivedMessages:
    sender, message, hmac = message[1:]
    decodeHMAC = base64.b64decode(hmac.encode("utf-8"))
    decodeMsg = base64.b64decode(message.encode("ascii"))


    try:
      secret = retrieveMacKey(receiver, sender)
      is_Valid = verifyHash(decodeMsg, decodeHMAC, secret)
      if(is_Valid):
        print(receiver.decryptMessage(decodeMsg))
      else:
        print("Error with MAC verification.")
    except Exception: 
      print("Not for current user.")


    # input("press enter to read nest message")
    # target, hmac, rawMsg = message.split(".")
    # #print("Target: " + target + "\t hmac: " + hmac + "\t rawMsg: " + rawMsg)
    # print(validateMessage(target, hmac, message))
    # print(decryptMessage(rawMsg[0], rawMsg[1:]))

  return 0

def decryptMessage(receiverName, encMessage, password):
  host = User(receiverName, password)
  host.decryptMessage(encMessage)

def getPublicKey(userName):
  publicKey = RSA.import_key(open("keys/"+userName+"publickey.pem").read())
  return publicKey

# Store a shared key between users in a secure, password protected file
def storeMacKey(host, target, secret):
  print("Storing the shared key...")
  with open("keys/"+host.name + "_" + target + ".key", "wb") as fp:
    rsaKey = getPublicKey(host.name)
    data = host.RSAEncryption(secret, rsaKey)
    fp.write(data)
    print("Secret stored to " + host.name + "_" + target + ".key")

  with open("keys/"+target + "_" + host.name + ".key", "wb") as fp:
    rsaKey = getPublicKey(target)
    data = host.RSAEncryption(secret, rsaKey)
    fp.write(data)
    print("Secret stored to " + target + "_" + host.name + ".key")

#Retrieve a shared key between users from a secure file.
def retrieveMacKey(host, target):
  #Need to search for keys
  #Both user.name+target.name AND target.name+user.name key files
  #If not found, should create and store a new key
  print("Retrieving shared key...")
  if(os.path.isfile("keys/"+host.name + "_" + target + ".key")):
    macKey = "keys/"+host.name + "_" + target + ".key"
    with open(macKey, "rb") as fp:
      with open("keys/"+host.name+"privatekey.pem", "rb") as privateFile:
        rawPrivate = privateFile.read()
        privateKey = RSA.import_key(rawPrivate, host.password)
        #publicKey = getPublicKey(host.name)
        keyEncrypt = fp.read()
        data = host.RSADecryption(keyEncrypt, privateKey) 
        return data
  else:
    raise Exception("MAC Key file not found.")

    
def messageSignature(host, target, ciphertext):
  try:
    secret = retrieveMacKey(host, target)
  except Exception:
    print("No key found, creating new key...")
    key = generateSecret()
    storeMacKey(host, target, key)
    print(key)
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
