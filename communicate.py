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
  signedMsg = signMessage(sender, receiverName, ciphertext)
  file = open("Transmitted_Data.txt", "a")
  file.write(receiverName + " " + ciphertext + " " + signedMsg + "\n")
  file.close()

def receiveMessages(receiver):
  # assume Transmit file is formatted as Receiver Sender Message or 
  # if public key is written as PK User PublicKey
  file = open("Transmitted_Data.txt", "r")

  receivedMessages = []
  for line in file:
    input = line.strip().split()  #cleans input

    receivedMessages.append(input[0]) #gets encrypted data, which might contain whitespace

  print("There are ", len(receivedMessages), "messages.")
  for message in receivedMessages:
    sender, hmac, message = message.split(".")
    decodeSend = base64.b64decode(sender.encode("ascii")).decode("utf-8")
    decodeHMAC = base64.b64decode(hmac.encode("ascii"))
    decodeMsg = base64.b64decode(message.encode("ascii"))

    try:
      secret = retrieveMacKey(receiver, decodeSend)
      is_Valid = verifyHash(decodeMsg, decodeHMAC, secret)
      if(is_Valid):
        print("This is a valid string! Please implement a decryption :)")
        #print(decryptMessage(receiver.name, decodeMsg, receiver.password))
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
  publicKey = RSA.import_key(open(userName+"publickey.pem").read())
  return publicKey

# Store a shared key between users in a secure, password protected file
def storeMacKey(host, target, secret):
  print("Storing the shared key...")
  with open(host.name + "_" + target + ".key", "wb") as fp:
    rsaKey = getPublicKey(host.name)
    data = host._RSAEncryption(secret, rsaKey)
    fp.write(data)
    print("Secret stored to " + host.name + "_" + target + ".key")

  with open(target + "_" + host.name + ".key", "wb") as fp:
    rsaKey = getPublicKey(target)
    data = host._RSAEncryption(secret, rsaKey)
    fp.write(data)
    print("Secret stored to " + target + "_" + host.name + ".key")

#Retrieve a shared key between users from a secure file.
def retrieveMacKey(host, target):
  #Need to search for keys
  #Both user.name+target.name AND target.name+user.name key files
  #If not found, should create and store a new key
  print("Retrieving shared key...")
  if(os.path.isfile(host.name + "_" + target + ".key")):
    macKey = host.name + "_" + target + ".key"
    with open(macKey, "rb") as fp:
      with open(host.name+"privatekey.pem", "rb") as privateFile:
        rawPrivate = privateFile.read()
        privateKey = RSA.import_key(rawPrivate, host.password)
        #publicKey = getPublicKey(host.name)
        keyEncrypt = fp.read()
        data = host._RSADecryption(keyEncrypt, privateKey) 
        return data
  else:
    raise Exception("MAC Key file not found.")

  
    
def signMessage(host, target, ciphertext):
  try:
    secret = retrieveMacKey(host, target)
  except Exception:
    print("No key found, creating new key...")
    key = generateSecret()
    storeMacKey(host, target, key)
    print(key)
    secret = key

  hmac = genHash(ciphertext, secret)

  host_name_b64 = base64.b64encode(host.name.encode('utf-8')).decode('ascii')
  hmac_b64 = base64.b64encode(hmac).decode('ascii')
  ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')

  # 4. Construct the final signed message string using the Base64 components
  signedMsg = f"{host_name_b64}.{hmac_b64}.{ciphertext_b64}"

  return signedMsg

def validateMessage(target, hmac, message):
  secret = retrieveMacKey(target)
  isValid = verifyHash(message, hmac, secret)
  return isValid
