from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from User import User
import os

def sendMsg(sender, receiverName, message):
  # obtain the ciphertext using the receiver's public key
  receiverPubKey = getPublicKey(receiverName)
  ciphertext = sender.encryptMessage(message, receiverPubKey)
  file = open("Transmitted_Data.txt", "ba")
  file.write(ciphertext)
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
    print(decryptMessage(message[0], message[1:]))

  return 0

def decryptMessage(receiverName, encMessage, password):
  host = User(receiverName, password)
  host.decryptMessage(encMessage)

def getPublicKey(userName):
  publicKey = RSA.import_key(open(userName+"publickey.pem").read())
  return publicKey