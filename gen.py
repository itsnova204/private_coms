import os


encryption_key = os.urandom(16)  # 128 bits
authentication_key = os.urandom(32)  # 256 bits

with open("pw", "wb") as key_file:
    key_file.write(encryption_key + b"\n" + authentication_key)

print("AES-128-CTR and HMAC-SHA256 Keys generated and saved to pw")
