import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def rsa_encrypt(message, public_key):
    public_key_serialised = serialization.load_pem_public_key(public_key)
    encrypted_message = public_key_serialised.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def rsa_decrypt(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

def load_mac_key():
    with open("pw", "rb") as key_file:
        lines = key_file.readlines()
        return lines[1].strip()

def load_aes_key():
    with open("pw", "rb") as key_file:
        lines = key_file.readlines()
        return lines[0].strip()

def mac(message, key):
    return hmac.new(key, message, hashlib.sha256).digest()

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.encrypt(message)

def aes_decrypt(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.decrypt(encrypted_message)
