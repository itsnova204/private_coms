import socket
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util import Counter

def read_keys():
    with open('pw', 'rb') as f:
        keys = f.read()
    return keys[:16], keys[16:]

def decrypt_message(encrypted_message, encryption_key, hmac_key):
    sequence_number = int.from_bytes(encrypted_message[:8], 'big')
    encrypted_message_body = encrypted_message[8:-32]
    mac = encrypted_message[-32:]

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(sequence_number.to_bytes(8, 'big') + encrypted_message_body)
    try:
        hmac.verify(mac)
    except ValueError:
        print(f"MAC check failed for sequence number {sequence_number}")
        return None

    ctr = Counter.new(128)
    cipher = AES.new(encryption_key, AES.MODE_CTR, counter=ctr)
    message = cipher.decrypt(encrypted_message_body).decode('utf-8')
    
    return message

def encrypt_message(message, encryption_key, hmac_key, sequence_number):
    ctr = Counter.new(128)
    cipher = AES.new(encryption_key, AES.MODE_CTR, counter=ctr)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(sequence_number.to_bytes(8, 'big') + encrypted_message)
    mac = hmac.digest()
    
    return sequence_number.to_bytes(8, 'big') + encrypted_message + mac

def main():
    encryption_key, hmac_key = read_keys()
    sequence_number = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        conn, addr = s.accept()
        with conn:
            messages = ["Hello Alice", "Me too. Same time, same place?"]
            for message in messages:
                data = conn.recv(1024)
                if data:
                    received_message = decrypt_message(data, encryption_key, hmac_key)
                    print(f"Decrypted message received: {received_message}")

                    sequence_number += 1
                    encrypted_message = encrypt_message(message, encryption_key, hmac_key, sequence_number)
                    conn.sendall(encrypted_message)
                    #print(f"Sent encrypted message: {encrypted_message}")

            # Wait for the last message from Alice
            data = conn.recv(1024)
            if data:
                received_message = decrypt_message(data, encryption_key, hmac_key)
                print(f"Decrypted message received: {received_message}")

                if received_message == "end":
                    #print("Conversation ended by Alice")
                    conn.close()

if __name__ == "__main__":
    main()