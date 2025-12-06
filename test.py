import os
import sys
from communicate import sendMsg
#from communicate import decryptReceived
from communicate import getPublicKey

from User import User

print(os.path.realpath(sys.executable))

def menuPrompt():
    print("--------------MENU--------------")
    print("(1) Receive new messages")
    print("(2) Send a message")
    print("(3) Quit")
    response = input()
    return response

def main():
    hostName = input("Please enter your name: ")
    hostPass = input("Please enter your password: ")
    host = User(hostName, hostPass)
    host.storePrivateKey()
    host.storePublicKey()
    action = ""
    while action != "3":
        action = menuPrompt()
        if action == "1":
            print("flag")
            if os.path.isfile("Transmitted_Data.txt"):
                fp = open("Transmitted_Data.txt", "r")
                data = fp.read().split(" ",2)
                recipient = data[0]
                print(recipient)
                if recipient == hostName:
                    print("You have received a messsage!")
                    print("Decrypting the message using your private key...")
                    encMsg = data[1]
                    msg = host.decryptMessage(encMsg)
                    print("The message said: '" + msg + "'")
                    # decrypt
                    os.remove("Transmitted_Data.txt")
            else:
                    print("No new messages to read.")
        elif action == "2":
            receiverName = input("Who would you like to send a message to?")
            receiver_key_path = receiverName + "publickey.pem"
            # The user entered a valid user. Ask them for the message
            if os.path.isfile(receiver_key_path):
                messageContent = input("Please type your message for " + receiverName + " below, then press [ENTER]")
                sendMsg(host, receiverName, messageContent)
                print("Your message has been sent.")
            # The host entered a nonexistent user or made a typo. Prompt them again.
            else:
                print("The user " + receiverName + " does not exist.")
                continue

        
    host.destroyKeys()

main()