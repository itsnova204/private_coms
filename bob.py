import sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import socket

import encript_then_mac
import rsa

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65437  # Port to listen on (non-privileged ports are > 1023)

def get_private_key():
    with open("bob_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def get_public_key():
    with open("bob_public.pem", "rb") as key_file:
        public_key_bytes = key_file.read()
        public_key = serialization.load_pem_public_key(public_key_bytes)
    return public_key

def handshake_rx(connection):
    print("Starting handshake rx")
    bob_public_RSA_key = get_public_key()

    # Use the appropriate encoding and format
    public_key_bytes = bob_public_RSA_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    connection.sendall(public_key_bytes)
    print("Sent public key to Alice")
    
    # Get the encrypted AES key
    private_key = get_private_key()
    print(sys.getsizeof(private_key))
    encrypted_aes_key = connection.recv(sys.getsizeof(private_key))
    print(sys.getsizeof(encrypted_aes_key))
    
    aes_key = rsa.rsa_decrypt(encrypted_aes_key, private_key)


    # Get the encrypted HMAC key
    encrypted_hmac_key = connection.recv(1024)
    hmac_key = rsa.rsa_decrypt(encrypted_hmac_key, get_private_key())
    print("Received HMAC key from Alice")
    print(hmac_key)

    return aes_key, hmac_key
    # Continue with the rest of your handshake_rx function

def get_public_key():
    with open("bob_public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

def handshake_tx(sock):
    print("Starting handshake tx")
    pubkey = get_public_key()

    aes_key = b'some_aes_key'
    encrypted_aes_key = rsa_encrypt(aes_key, pubkey)
    
    # Send the encrypted AES key
    sock.sendall(encrypted_aes_key)
    
    # Dummy value for hmac_key for demonstration purposes
    hmac_key = b'some_hmac_key'
    
    return aes_key, hmac_key

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))

    sock.listen()
    conn, addr = sock.accept()

    with conn:
        print(f"Connected by {addr}")
        aes_key, hmac_key = handshake_rx(conn)
        print(aes_key)
        print(hmac_key)
        
if __name__ == "__main__":
    main()