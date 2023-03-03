from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# Generate Alice's key pair
def generate_keys(size):
    key_pair = RSA.generate(size)
    public_key = key_pair.publickey().exportKey()
    private_key = key_pair.exportKey()

    return key_pair, private_key, public_key

# Generate Alice's key pair
alice_key, alice_private_key, alice_public_key = generate_keys(1024)


# Generate Bob's key pair
bob_key, bob_private_key, bob_public_key = generate_keys(1024)

# Alice creates a cipher object using Bob's public key
cipher = PKCS1_OAEP.new(RSA.import_key(bob_public_key))


message = 'A message to secure'
print("message=" + message)

# Alice encrypts a message to Bob using Bob's public key
ciphertext = cipher.encrypt(message.encode())
print("ciphertext=" + str(ciphertext))

# Alice signs the encrypted message using her private key
message_hash = SHA256.new(ciphertext)
signature = pkcs1_15.new(RSA.import_key(alice_private_key)).sign(message_hash)
print("signature=" + str(signature))


# Bob's work starts
bob_message_hash = SHA256.new(ciphertext)
try:
    pkcs1_15.new(RSA.import_key(alice_public_key)).verify(bob_message_hash, signature)
    # Bob decrypts the message using his private key
    cipher = PKCS1_OAEP.new(RSA.import_key(bob_private_key))
    decrypted_message = cipher.decrypt(ciphertext)
    print(decrypted_message.decode())
except (ValueError, TypeError):
    print('Error: Message has been tampered with or signature is invalid!')
