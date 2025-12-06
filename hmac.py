from Crypto.Hash import SHA256, HMAC
import os

'''
    Anticipated flow for validating messages

    1) Handshake - Both users are decided, the sender and transmitter
    2) Key generation - Sender should generate a key and send it to the transmitter
        with RSA Encryption. 
    3) Key saving - Both users should be able to save the key. Store in a file?
    4) Message HMAC Generation - A message is signed with the key, to be sent with the encrypted message
    5) Message HMAC Validation - A message is compared with the HMAC using the key to validate
'''


#Methods to be exported

#Generate a random 32-bit secret for MAC purposes
#Returns a string
def generateSecret():
    key_bytes = os.urandom(32)

    key_hex = key_bytes.hex()

    return key_hex    

#Create a hash from a message and a secret
#Returns: The hash generated with SHA256

def genHash(msg, secret):
    hashObj = HMAC.new(secret, digestmod=SHA256)

    hashObj.update(msg)
    
    return hashObj.hexdigest()

#Verify a given hash using a given message and secret
#Returns: Boolean - True if verified, False if not

def verifyHash(msg, hash, secret):
    hashObj = HMAC.new(secret, digestmod=SHA256)

    hashObj.update(msg)
    try:
        hashObj.hexverify(hash)
        return True
    except ValueError:
        return False


#Testing functions of methods

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
