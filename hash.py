from Crypto.Hash import SHA256, HMAC


def genHash(msg, secret):
    hashObj = HMAC.new(secret, digestmod=SHA256)

    hashObj.update(msg)
    
    return hashObj.hexdigest()

def verifyHash(msg, hash, secret):
    hashObj = HMAC.new(secret, digestmod=SHA256)

    hashObj.update(msg)
    try:
        hashObj.hexverify(hash)
        return True
    except ValueError:
        return False

secret = 'i_am_secret'
encodedSecret = secret.encode('utf-8')

print("Testing Hash Output")
print("Secret: " + secret)
msg = b"bobMessage"

hashedMsg1 = genHash(msg, encodedSecret)
editedHash = genHash(msg, encodedSecret)

edit = list(editedHash)
edit[5] = '0'
editedHash = "".join(edit)

print("Hash of previous message1: " + hashedMsg1)
print("Edited hash: " + editedHash)

print("Verifying original hash with secret: " + str(verifyHash(msg, hashedMsg1, encodedSecret)))
print("Verifying edited hash: " + str(verifyHash(msg, editedHash, encodedSecret)))
