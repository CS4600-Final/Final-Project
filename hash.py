from Crypto.Hash import SHA3_256

def genHash(msg):
    hashObj = SHA3_256.new()

    for data in msg:
        hashObj.update(msg)

    return hashObj.hexdigest()



print("Testing Hash Output")
msg1 = b"very long string"
msg2 = b"very long stringg"

hashedMsg1 = genHash(msg1)
hashedMsg2 = genHash(msg2)

print("Hash of previous message1: " + hashedMsg1)
print("Hash of previous message2: " + hashedMsg2)

print("Hashes equal? " + (str)(hashedMsg1==hashedMsg2))

