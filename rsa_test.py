import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def rsa_encrypt(message, public_key):
    encrypted_message = public_key.encrypt(
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

def get_private_key():
    with open("bob_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def get_public_key():
    with open("bob_public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

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


def main():
    private_key = get_private_key()
    public_key = get_public_key()
    message = "hello world".encode("utf-8")

    encrypted_message = rsa_encrypt(message, public_key)
    decrypted_message = rsa_decrypt(encrypted_message, private_key)

    print(message.decode("utf-8"))
    print(decrypted_message.decode("utf-8"))
    print(message == decrypted_message)

    print(load_aes_key)
    print(load_mac_key)

if __name__ == "__main__":
    main()