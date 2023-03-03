from scapy.all import *
from scapy import IP
from scapy import TCP
# Define callback function to intercept packets


def intercept_packet(packet):
    if IP in packet and TCP in packet:
        # Check if the packet is from Alice to Bob
        if packet[IP].src == 'Alice_IP_address' and packet[IP].dst == 'Bob_IP_address' and packet[TCP].dport == 12345:
            # Decrypt the message and extract the plaintext
            encrypted_message, iv, signature = pickle.loads(
                packet[TCP].payload.load)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_message = cipher.decrypt(encrypted_message)
            message = padded_message.rstrip(b"\0")
            print("Original message:", message)

            # Modify the message
            modified_message = b"Hello Bob! This message has been modified by Eve."

            # Generate new signature with RSA
            with open("private_key_eve.pem", "rb") as f:
                private_key = RSA.import_key(f.read())
            hash = SHA256.new(modified_message)
            signature = pkcs1_15.new(private_key).sign(hash)

            # Pack and send the modified message and signature
            modified_data = pickle.dumps((modified_message, iv, signature))
            packet[TCP].payload.load = modified_data
            del packet[IP].chksum
            del packet[TCP].chksum
            print("Modified message:", modified_message)

            # Forward the modified packet to Bob
            send(packet, verbose=0)
    return


# Start sniffing packets
sniff(filter="tcp", prn=intercept_packet)
