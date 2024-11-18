from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def encrypt_then_mac(message, key_enc, key_mac):
    if len(key_enc) != 16:
        raise ValueError("Encryption key must be 16 bytes long for AES-128 encryption")
    
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    
    hmac = HMAC(key_mac, SHA256(), backend=default_backend())
    hmac.update(iv + ciphertext)
    mac = hmac.finalize()
    
    
    return {
        "iv": iv,
        "ciphertext": ciphertext,
        "mac": mac
    }

def validate_and_decrypt(encrypted_data, key_enc, key_mac):
    if len(key_enc) != 16:
        raise ValueError("Encryption key must be 16 bytes long for AES-128 decryption")
    
    try:
        iv = encrypted_data["iv"]
        ciphertext = encrypted_data["ciphertext"]
        mac = encrypted_data["mac"]
    except KeyError as e:
        raise ValueError(f"Missing required field in encrypted data: {e}")
    
    hmac = HMAC(key_mac, SHA256(), backend=default_backend())
    hmac.update(iv + ciphertext)

    try:
        hmac.verify(mac)  #Throws an exception if the MAC is invalid
    except Exception:
        raise ValueError("HMAC verification failed. The data may have been tampered with")
    
    #Actually decrypt the data
    cipher = Cipher(algorithms.AES(key_enc), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode()


if __name__ == "__main__":
    key_enc = os.urandom(16)  #16-byte encryption key
    key_mac = os.urandom(32)  #32-byte MAC key
    
    message = "Hello World!"
    
    encrypted_data = encrypt_then_mac(message, key_enc, key_mac)
    
    try:
        decrypted_message = validate_and_decrypt(encrypted_data, key_enc, key_mac)
        print("Decrypted message:", decrypted_message)
    except ValueError as e:
        print("Decryption failed!")
        print("Error:", e)

