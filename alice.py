import rsa
import encript_then_mac
import socket


HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65437

def handshake_tx(connection):
    print("Starting handshake tx")
    pubkey = connection.recv(2048) #TODO change this number
    
    aes_key = rsa.load_aes_key()
    hmac_key = rsa.load_mac_key()

    print("Received public key from Bob")

    encrypted_aes_key = rsa.rsa_encrypt(aes_key, pubkey)
    encrypted_hmac_key = rsa.rsa_encrypt(hmac_key, pubkey)

    connection.sendall(encrypted_aes_key)
    connection.sendall(encrypted_hmac_key)

    return aes_key, hmac_key

def main():
    with open("pw", "rb") as key_file:
        lines = key_file.readlines()
        aes_key = lines[0].strip()
        hmac_key = lines[1].strip()

    if len(aes_key) != 16 or len(hmac_key) != 32:
        print("Read invalid keys from file")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    aes_key, hmac_key = handshake_tx(sock)    

    print("Keys sent to Bob:")
    print(aes_key)
    print(hmac_key)

    # Insert the code block at line 12, column 24
    pubkey = connection.recv(1024) #TODO change this number

    aes_key = rsa.load_aes_key()
    hmac_key = rsa.load_mac_key()

    encrypted_aes_key = rsa.rsa_encrypt(aes_key, pubkey)
    encrypted_hmac_key = rsa.rsa_encrypt(hmac_key, pubkey)

    connection.sendall(encrypted_aes_key)
    connection.sendall(encrypted_hmac_key)

    return aes_key, hmac_key


if __name__ == "__main__":
    main()