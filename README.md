
# RSA Encryption between Alice & Bob

In this project, RSA Encryption is implemented and tested for confidentiality and integrity. Alice has a top-secret document and wants to send it to her partner, Bob, who lives in a different country.


## Technology Stack

    1. Python
    2. Cryptodome
    3. Socket
    4. Scapy


## Algorithm used

RSA algorithm is an asymmetric cryptography algorithm. Asymmetric means it works on two different keys, i.e., Public Key and Private Key. Asymmetric encryption uses a key pair that is mathematically linked to encrypt and decrypt data. A private and public key is created, with the public key being accessible to anyone, and the private key is a secret known only by the key pair creator. With RSA, the private or public key can encrypt the data while the other key decrypts it.

### alice.py

Alice acts as a client in our program which connects to Bob(server) using socket connection. After a successful connection is established between Alice & Bob, the public keys are exchanged.
Alice then creates a cipher object using Bob's public key.
Alice then encrypts the message using her private key and send the ciphertext and signature to Bob
Once Bob receives the signature he then verifies using Alice's public key. If verified, Bob will send an acknowledgement to Alice as "Message Received", if not an error message will be sent to Alice as "Message has been tampered with or signature is invalid!"

## bob.py

Bob acts as a server in our program which will wait for a connection. Once Alice sends her public key, Bob will receive and respond with his public key. Bob then receives the ciphertext and signature from Alice, bob decrypts the message using his private key. To verify the integrity of the message bob verifies the signature sent by Alice using Alice's public key.

## trudy.py

We have simulated a Man in the Middle Attack where Trudy acts as a intruder who tries to manipulate the message sent by alice to bob by altering its contents. In this case Alice is unaware that she has an incorrect IP address and is connected to Trudy instead of Bob. Trudy forwards the public key received from Alice to Bob, and vice versa. Once Alice sends the encrypted message to Trudy(thinking he's Bob) Trudy manipulates the message and forwards it to Bob. Bob however, comes to know about when he tries to verify the signature using his Alice's public key. 
When Bob fails to send a response within 5 seconds the socket timeout is called and a response is sent to Alice that the socket is timed out, and bob might have not recieved the message or it was tampered!
## Steps to use

Make sure you have following files in the same folder,
alice.py [client]
bob.py [server]
trudy.py [MiTM]

Make sure the following dependencies are installed in your machine,
    1. python 3.9
    2. pickle 
    3. socket (pip install socket)
    4. Crypotodome (pip install cryptodome)

1. Open the terminal to the location where files described in the step 1 are present (using cd command).
2. Update the server(bob) IP address in alice.py and bob.py files for the socket connection
3. Type the following command in the terminal
    python bob.py to run the server
4. Once the server is up and running
    run python alice.py on another terminal

** For integrity check please run the trudy.py first by running the following command+

python trudy.py

** For testing the sniff.py file for running scapy please run the following command.

python sniff.py