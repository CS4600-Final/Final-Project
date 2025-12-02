from communicate import sendMsg
from communicate import decryptReceived
from User import User

def signInPrompt(primaryUser, otherUser):
  print("Signed in as " + primaryUser)
  print("S) Send a message")
  print("R) Decrypt most recently received message")
  userAction = input()

  if userAction == 'S':
    sendMsg(primaryUser, otherUser)
  elif userAction == 'R':
    decryptReceived(primaryUser) # this program needs to check if there is a message to read in the first place
  
def main():
  #Alice = User()
  #Bob = User()
  #fp = open("Transmitted_Data.txt")
  #fp.write(Alice.getPublicKey())
  #fp.write(Bob.getPublicKey())

  nameInput = input("Enter username: ")
  passwordInput = input("Enter password: ")
  host = User(nameInput, passwordInput)
  host.storePrivateKey()
  host.storePublicKey()

  #if userSelection == 'A':
  #  signInPrompt(Alice, Bob)
  #elif userSelection == 'B':
  #  signInPrompt(Bob, Alice)

main()