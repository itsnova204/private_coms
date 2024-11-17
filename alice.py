from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def establish_connection(reciver_public_RSA_key, aes_key, hmac_key):


    print("Starting key exchange...")

    encrypted_aes_key = reciver_public_RSA_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_hmac_key = reciver_public_RSA_key.encrypt(
        hmac_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_key, encrypted_hmac_key

def get_public_key():
    with open("bob_public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

import socket
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65436 

def main():
    with open("pw", "rb") as key_file:
        lines = key_file.readlines()
        aes_key = lines[0].strip()
        hmac_key = lines[1].strip()

    if len(aes_key) != 16 or len(hmac_key) != 32:
        print("Read invalid keys from file")
        return

    public_key = get_public_key()
    print("Alice's public key loaded")
    print("Alice waiting for connection...")
    encrypted_aes_key, encrypted_hmac_key = establish_connection(public_key, aes_key, hmac_key)

    print("Connection established")

    #TODO SOCKETS ARE NOT WORKING! probably packet size is problem!
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("sending aes key")
        print(encrypted_aes_key)
        s.sendall(encrypted_aes_key)
        print("sending hmac key")
        print(encrypted_hmac_key)
        s.sendall(encrypted_hmac_key)



if __name__ == "__main__":
    main()