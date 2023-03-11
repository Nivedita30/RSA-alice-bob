import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5

# Bind the socket to a specific IP address and port number
EVE_ADDR = ('192.168.246.251', 9090)
eve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
eve_socket.bind(EVE_ADDR)

BOB_ADDR = ("192.168.246.7", 9090)
ALICE_PKEY = ""
BOB_PKEY = ""

# Listen for incoming connections from clients (e.g. Alice)
eve_socket.listen(5)
print("socket is starting")

while True:
    # Wait for a client to connect
    print('Waiting for connection...')
    alice_socket, alice_addr = eve_socket.accept()
    print('Connection from alice:', alice_addr)
    #Once connection is establised, trudy receives Alice's public key
    alice_public_key=alice_socket.recv(1024)

    # Connect to Bob's socket
    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_socket.connect(BOB_ADDR)
    bob_socket.settimeout(15)
    print('Connected with bob!')
    #Once connection is established, trudy sends alice's public key to Bob
    bob_socket.send(alice_public_key)

    #Alice receives Bob's public key
    bob_public_key=bob_socket.recv(1024)
    #Then, bob sends his public key to Alice
    alice_socket.send(bob_public_key)

    # After the exchange of public keys between Alice & Bob, Bob receives ciphertext and signature from the client (Alice)
    # Receive and unpack message and signature
    pkt = alice_socket.recv(2048)
    ciphertext, signature = pickle.loads(pkt)

    cipher = PKCS1_OAEP.new(RSA.import_key(bob_public_key))
    # Modify the message
    modified_message = "Hello Bob! This message has been modified by Eve."

    modified_encrypted_message = cipher.encrypt(modified_message.encode())
    print("modified message:", modified_encrypted_message)

    # Send the ciphertext and signature to Bob
    data = pickle.dumps((modified_encrypted_message, signature))
    bob_socket.sendall(data)

    # Wait for a response from Bob
    response = bob_socket.recv(1024)
    print('Received response:', response.decode())
    alice_socket.send(response)
    
    # Close connections
    bob_socket.close()
    alice_socket.close()
    
