def sendMsg(sender, receiver):
  file = open("Transmitted_Data.txt", "a")
  
  publicKey = file.readline().strip().split()
  while(publicKey != receiver):
    publicKey = file.readline().strip().split()

  return 

def decryptReceived(receiver):
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

#decrypts message. if not properly encrypted or in unable to decrypt returns "unable to decrypt"
def decryptMessage(encryptedMessage):
  #use private key on encrypted message

  #get AES key, if not compatible (sent message is too short) return unable to decrypt

  #AES decryption then return

  return 0
