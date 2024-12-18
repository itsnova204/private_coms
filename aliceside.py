import socket
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util import Counter

def read_keys():
    with open('pw', 'rb') as f:
        keys = f.read()
    return keys[:16], keys[16:]

def encrypt_message(message, encryption_key, hmac_key, sequence_number):
    ctr = Counter.new(128)
    cipher = AES.new(encryption_key, AES.MODE_CTR, counter=ctr)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(sequence_number.to_bytes(8, 'big') + encrypted_message)
    mac = hmac.digest()
    
    return sequence_number.to_bytes(8, 'big') + encrypted_message + mac

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

def main():
    encryption_key, hmac_key = read_keys()
    sequence_number = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))
        messages = ["Hello Bob", "I would like to have dinner", "Sure!"]
        for message in messages:
            sequence_number += 1
            encrypted_message = encrypt_message(message, encryption_key, hmac_key, sequence_number)
            s.sendall(encrypted_message)
            #print(f"Sent encrypted message: {encrypted_message}")

            data = s.recv(1024)
            if data:
                response = decrypt_message(data, encryption_key, hmac_key)
                print(f"Decrypted message received: {response}")

        # Send end message
        sequence_number += 1
        end_message = encrypt_message("end", encryption_key, hmac_key, sequence_number)
        s.sendall(end_message)
        #print("Sent end message")

if __name__ == "__main__":
    main()