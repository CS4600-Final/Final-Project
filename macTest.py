from User import User
from communicate import sendMsg, receiveMessages, getPublicKey, retrieveMacKey
from Crypto.PublicKey import RSA
import os

#Testing functions

tarHost = User("end", "1")
host = User("test", "1234")
if(not os.path.isfile(host.name + "privatekey.pem")):
    host.storePrivateKey()
    host.storePublicKey()
if(not os.path.isfile(tarHost.name + "privatekey.pem")):
    tarHost.storePrivateKey()
    tarHost.storePublicKey()
receiverName = "end"



# #Need to send MAC

sendMsg(host, receiverName, "Test Success")
print("Message sent")

receiveMessages(tarHost)



#Functioning decrypting, what the **** man

# publicKey = getPublicKey("end")
# cipher = host._RSAEncryption(b"Yo", publicKey)

# with open(tarHost.name+"privatekey.pem", "rb") as privateFile:
#       data = privateFile.read()
#       privateKey = RSA.import_key(data, tarHost.password)
#       plain = host._RSADecryption(cipher, privateKey)
#       print(plain)

# with open("test_end.key", "rb") as fp:
#     with open("testprivatekey.pem", "rb") as priv:
#         data = priv.read()
#         cipher = fp.read()
#         privKey = RSA.import_key(data, host.password)
#         print(host._RSADecryption(cipher, privKey))