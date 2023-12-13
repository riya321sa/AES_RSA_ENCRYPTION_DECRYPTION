import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

message = input("Enter the string: ")

def hash_message(message):
    hash_object = hashlib.sha256()
    hash_object.update(message.encode('utf-8'))
    return hash_object.hexdigest()

def rsa_encrypt(plain_text, public_keyA):
    recipient_key = RSA.import_key(public_keyA)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher_rsa.encrypt(plain_text)
    return ciphertext

def rsa_decrypt(ciphertext, private_keyA):
    rsa_key = RSA.import_key(private_keyA)
    rsa_private_key = PKCS1_OAEP.new(rsa_key)
    decrypted_text = rsa_private_key.decrypt(ciphertext)
    return decrypted_text

def aes_encrypt(plain_text, key):
    cipher_aes = AES.new(key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    ciphertext, tag = cipher_aes.encrypt_and_digest(plain_text)
    return nonce + ciphertext + tag

def aes_decrypt(ciphertext, key):
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext

hashed_messageA = hash_message(message)

'''GENERATING KEYS'''
keyA = RSA.generate(2048)
private_keyA = keyA.export_key('PEM')
public_keyA = keyA.publickey().export_key('PEM')

'''encrypted message'''
encrypted_message = rsa_encrypt(hashed_messageA.encode('utf-8'), public_keyA)
aes_key = hashlib.sha256(b'secret_key').digest()
aes_encrypted_message = aes_encrypt(encrypted_message, aes_key)

keyB = RSA.generate(2048)
private_keyB = keyB.export_key()
public_keyB = keyB.publickey().export_key()

encrypted_SharedKeyB = rsa_encrypt(aes_key, public_keyB)

''' decryption '''
decrypted_sharedKey = rsa_decrypt(encrypted_SharedKeyB, private_keyB)
decrypt_msg = aes_decrypt(aes_encrypted_message, decrypted_sharedKey)
decrypt_hash_msg = rsa_decrypt(decrypt_msg, private_keyA)

hashed_messageA = hashed_messageA.encode('ASCII')

if hashed_messageA == decrypt_hash_msg:
    print("SECURED CONNECTION! MESSAGE ACCEPTED")
else:
    print("INSECURE CONNECTION! MESSAGE REJECTED")

print("----------------------------------------AT SENDER------------------------------------------------------")
print("ORIGINAL MESSAGE:", message)
print("HASHED MESSAGE OF SENDER:", hashed_messageA)
print("PRIVATE KEY OF SENDER:", private_keyA)
print("PUBLIC KEY OF SENDER:", public_keyA)
print("AES ENCRYPTED MESSAGE OF SENDER:", aes_encrypted_message)
print("PRIVATE KEY OF RECEIVER:", private_keyB)
print("PUBLIC KEY OF RECEIVER:", public_keyB)
print("SHARED SECRET KEY:", aes_key)
print("ENCRYPTED SHARED KEY:", encrypted_SharedKeyB)
print("----------------------------------------AT RECEIVER------------------------------------------------------")
print("SHARED DECRYPT KEY:", decrypted_sharedKey)
print("DECRYPTED MESSAGE OF AES:", decrypt_msg)
print("DECRYPTED MESSAGE OF RSA:", decrypt_hash_msg)
print("HASHED MESSAGE:", hashed_messageA)
