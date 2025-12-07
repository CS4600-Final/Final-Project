import os
import sys
from communicate import sendMsg
from communicate import receiveMessages
from communicate import getPublicKey

from User import User

print(os.path.realpath(sys.executable))

def menuPrompt():
    print("--------------MENU--------------")
    print("(1) Receive new messages")
    print("(2) Send a message")
    print("(3) Generate new keys")
    print("(4) Delete account")
    print("(5) Quit")
    response = input()
    return response

def deleteKeys():
    print("To delete your key, enter")
    response = input()

def main():
    newHost = input("Enter 'NEW' if brand new user")
    hostName = input("Please enter your name: ")
    hostPass = input("Please enter your password: ")
    if (newHost == "NEW"):
        host = User(hostName, hostPass, False)
    else:
        host = User(hostName, hostPass, True)
    action = ""
    while action != "5":
        action = menuPrompt()
        
        if action == "1":
            if os.path.isfile("Transmitted_Data.txt"):
                fp = open("Transmitted_Data.txt", "r")
                data = fp.read().split(" ",2)
                recipient = data[0]
                print(recipient)
                if recipient == hostName:
                    receiveMessages(host)
                    # print("You have received a messsage!")
                    # print("Decrypting the message using your private key...")
                    # encMsg = data[1]
                    # msg = host.decryptMessage(encMsg)
                    # print("The message said: '" + msg + "'")
                    # # decrypt
                    # os.remove("Transmitted_Data.txt")
            else:
                    print("No new messages to read.")
        elif action == "2":
            receiverName = input("Who would you like to send a message to?")
            receiver_key_path = "keys/" + receiverName + "publickey.pem"
            # The user entered a valid user. Ask them for the message
            if os.path.isfile(receiver_key_path):
                messageContent = input("Please type your message for " + receiverName + " below, then press [ENTER]").encode("utf-8")
                sendMsg(host, receiverName, messageContent)
                print("Your message has been sent.")
            # The host entered a nonexistent user or made a typo. Prompt them again.
            else:
                print("The user " + receiverName + " does not exist.")
                continue
        elif action == "3":
            print("Generation of new keys will make it so you are unable to decipher current messages")
            confirmation = input("Enter 'NEW' if you would like to continue")
            if confirmation == "NEW":
                host.generateKeys()
        elif action == "4":
            print("Deletion of account will make all message to you unreadable, and make it so other users can't sent you any more messages.")
            print("You will also be immediately logged out of your account")
            confirmation = input("Enter 'DELETE' if you would like to continue")
            if confirmation == "DELETE":
                host.destroyKeys()
                action = "5"
        else:
            print("Invalid choice, Enter another choice")

main()