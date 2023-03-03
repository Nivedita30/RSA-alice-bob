import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Connect to Bob's socket
server_address = ('localhost', 8000)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)

# Generate Alice's key pair
def generate_keys(size):
    key_pair = RSA.generate(size)
    public_key = key_pair.publickey().exportKey()
    private_key = key_pair.exportKey()

    return key_pair, private_key, public_key

# Generate Alice's key pair
alice_key, alice_private_key, alice_public_key = generate_keys(1024)

# print("Hi, this is Alice",alice_public_key)
print()

#Alice receives Bob's public key
bob_public_key=client_socket.recv(1024)
# print("Bob PK",bob_public_key)

#After the exchange of public keys between Alice & Bob, Alice creates a cipher object using Bob's public key
cipher = PKCS1_OAEP.new(RSA.import_key(bob_public_key))


message = 'A message to secure'
print("message=" + message)

# Alice encrypts a message to Bob using Bob's public key
ciphertext = cipher.encrypt(message = message.encode())
print("ciphertext=" + str(ciphertext))

# Alice signs the encrypted message using her private key
message_hash = SHA256.new(ciphertext)
signature = pkcs1_15.new(RSA.import_key(alice_private_key)).sign(message_hash)
print("signature=" + str(signature))

# Send the ciphertext and signature to Bob
client_socket.send(ciphertext)
client_socket.send(signature)
#Alice sends her public key to Bob
client_socket.send(alice_public_key)

# Wait for a response from Bob
response = client_socket.recv(1024)
print('Received response:', response.decode())

# Close the connection
client_socket.close()