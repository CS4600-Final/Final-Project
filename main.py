import os
import sys
from communicate import sendMsg
from communicate import receiveMessages
from communicate import getPublicKey
from User import User
from User import BadLoginExist
from User import BadLoginNew

print(os.path.realpath(sys.executable))

#menu prompt display used by menu
def menuPrompt():
    print("--------------MENU--------------")
    print("(1) Receive new messages")
    print("(2) Send a message")
    print("(3) Generate new keys")
    print("(4) Delete account")
    print("(5) Quit")
    response = input()
    return response

def systemLogin():
    
    hostName = input("Please enter your name or 'STOP' to stop: ")
    if hostName != "STOP":
        hostPass = input("Please enter your password: ")
        newHost = input("Enter 'NEW' if brand new user: ")
        try:
            if (newHost == "NEW"):
                host = User(hostName, hostPass, False)
            else:
                host = User(hostName, hostPass, True)
            main(host)
        except BadLoginExist:
            print("\nIf you dont have an account, please enter NEW when prompted")
        except BadLoginNew:
            print("\nIf you do have an account, please do not enter NEW when prompted")
    print("Have a good day!")    
    
def main(host):
    action = ""
    while action != "5":
        action = menuPrompt()
        
        #read received messages if there are any
        if action == "1":               
            if os.path.isfile("Transmitted_Data.txt"):
                receiveMessages(host)
            else:
                print("No messages to read.")

        #sends message to another registered user
        elif action == "2":             
            receiverName = input("Who would you like to send a message to? Enter 'STOP' to quit to menu ")
            receiver_key_path = "keys/" + receiverName + "publickey.pem"
            
            # The host entered a nonexistent user or made a typo. Prompt them again.
            while (not os.path.isfile(receiver_key_path)) and receiverName != "STOP":
                print("The user " + receiverName + " does not exist. Enter 'STOP' to quit to menu ")
                receiverName = input("Who would you like to send a message to?")
                receiver_key_path = "keys/" + receiverName + "publickey.pem"

            # The user entered a valid user. Ask them for the message
            if os.path.isfile(receiver_key_path):
                messageContent = input("Please type your message for " + receiverName + " below, then press [ENTER]").encode("utf-8")
                sendMsg(host, receiverName, messageContent)
                print("Your message has been sent.")
            
        #generates new key
        elif action == "3":
            print("Generation of new keys will make it so you are unable to decipher current messages")
            confirmation = input("Enter 'NEW' if you would like to continue ")
            if confirmation == "NEW":
                #get all shared secrets
                host.generateKeys()
                #encrypt all shared secrets with new keys

        #deletes account
        elif action == "4":
            print("Deletion of account will make all message to you unreadable, and make it so other users can't sent you any more messages.")
            print("Any shared secrets you have will also be deleted")
            print("You will also be immediately logged out of your account")
            confirmation = input("Enter 'DELETE' if you would like to continue")
            if confirmation == "DELETE":
                #deletes all shared secrets
                host.destroyUserData()
                action = "5"

        #invalid choice selected
        else:
            print("Invalid choice, Enter another choice")


systemLogin()