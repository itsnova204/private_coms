from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def receive_connection(reciver_secrete_RSA_key, encrypted_aes_key, encrypted_hmac_key):

    print("Receiving keys...")

    aes_key = reciver_secrete_RSA_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    hmac_key = reciver_secrete_RSA_key.decrypt(
        encrypted_hmac_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key, hmac_key

def get_private_key():
    with open("bob_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key


def main():
    bob_secret_RSA_key = get_private_key()
    print("Bob's private key loaded")
    print("Bob waiting for connection...")
    import socket

    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 65436  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            for i in range(2):
                data = conn.recv(1024)
                if i == 0:
                    print("Received encrypted AES key")
                    print(data)
                    encrypted_aes_key = data
                else:
                    print("Received encrypted HMAC key")
                    encrypted_hmac_key = data

    print("Keys received")
    aes_key, hmac_key = receive_connection(bob_secret_RSA_key, encrypted_aes_key, encrypted_hmac_key)
    print("Connection established")
    print("AES key: ", aes_key)
    print("HMAC key: ", hmac_key)


if __name__ == "__main__":
    main()