import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle

# Connect to Bob's socket
#Server IP needs to be updated while running the code
server_address = ('localhost', 9090)
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

#Once connection is established, Alice sends her public key to Bob
client_socket.send(alice_public_key)

#Alice receives Bob's public key
bob_public_key=client_socket.recv(1024)

#After the exchange of public keys between Alice & Bob, Alice creates a cipher object using Bob's public key
cipher = PKCS1_OAEP.new(RSA.import_key(bob_public_key))

#Alice open the top secret document on her end and prints the plain text message
with open('top_secret.txt', 'r') as f:
    message = f.read()
print("message=" + message)

# Alice encrypts the plain text message to Bob using Bob's public key
ciphertext = cipher.encrypt(message = message.encode())


# Alice signs the encrypted message by hashing the file contents using her private key
message_hash = SHA256.new(ciphertext)
signature = pkcs1_15.new(RSA.import_key(alice_private_key)).sign(message_hash)

# Alice sends the ciphertext and signature to Bob
data = pickle.dumps((ciphertext, signature))
client_socket.sendall(data)

# Wait for a response from Bob
response = client_socket.recv(1024)
print('Received response:', response.decode())

# Close the connection
client_socket.close()