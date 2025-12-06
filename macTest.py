from User import User
from communicate import sendMsg, receiveMessages


#Testing functions

tarHost = User("end", "1")
tarHost.storePrivateKey()
tarHost.storePublicKey()
host = User("test", "1234")
host.storePrivateKey()
host.storePublicKey()
receiverName = "end"

#Need to send MAC

sendMsg(host, receiverName, "Test Success")
print("Message sent")

receiveMessages(receiverName)

