import pickle
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_keys(size):
    key_pair = RSA.generate(size)
    public_key = key_pair.publickey().exportKey()
    private_key = key_pair.exportKey()

    return key_pair, private_key, public_key

# Generate Bob's key pair
bob_key, bob_private_key, bob_public_key = generate_keys(1024)

# Bind the socket to a specific IP address and port number
server_address = ('localhost', 9090)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(server_address)

# Listen for incoming connections from clients (e.g. Alice)
server_socket.listen(5)
print("socket is starting")

while True:
    # Wait for a client to connect
    print('Waiting for connection...')
    client_socket, client_address = server_socket.accept()
    
    print('Connection from', client_address)

    #Once connection is established, bob sends his public key to Alice
    client_socket.send(bob_public_key)

    # After the exchange of public keys between Alice & Bob, Bob receives ciphertext and signature from the client (Alice)
    # Receive and unpack message and signature
    packet = client_socket.recv(4096)
    ciphertext, signature, alice_public_key = pickle.loads(packet)
    # ciphertext = client_socket.recv(1024)
    print(f"cipher received:{ciphertext}")
    # signature = client_socket.recv(1024)
    # alice_public_key=client_socket.recv(1024)

    # Bob verifies the signature using Alice's public key
    message_hash = SHA256.new(ciphertext)
    try:
        pkcs1_15.new(RSA.import_key(alice_public_key)).verify(message_hash, signature)
    except (ValueError, TypeError):
        print('Error: Message has been tampered with or signature is invalid!')

    # Bob decrypts the ciphertext using his private key
    cipher = PKCS1_OAEP.new(RSA.import_key(bob_private_key))
    decrypted_message = cipher.decrypt(ciphertext)
    print('Received message:', decrypted_message.decode())

    # Send a response to the client (Alice)
    response = 'Hello, Alice! Message received'
    client_socket.send(response.encode())

    # Close the connection
    client_socket.close()
