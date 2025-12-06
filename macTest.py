from User import User
from communicate import sendMsg, receiveMessages, getPublicKey
from Crypto.PublicKey import RSA


#Testing functions

tarHost = User("end", "1")
tarHost.storePrivateKey()
tarHost.storePublicKey()
host = User("test", "1234")
host.storePrivateKey()
host.storePublicKey()
receiverName = "end"

# #Need to send MAC

sendMsg(host, receiverName, "Test Success")
print("Message sent")

receiveMessages(receiverName)



#Functioning decrypting, what the **** man

# publicKey = getPublicKey("end")
# cipher = host._RSAEncryption(b"Yo", publicKey)

# with open(tarHost.name+"privatekey.pem", "rb") as privateFile:
#       data = privateFile.read()
#       privateKey = RSA.import_key(data, tarHost.password)
#       plain = host._RSADecryption(cipher, privateKey)
#       print(plain)

