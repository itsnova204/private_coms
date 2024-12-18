from Crypto.Random import get_random_bytes

def generate_keys():
    encryption_key = get_random_bytes(16)  # AES-128 key
    hmac_key = get_random_bytes(32)        # HMAC-SHA256 key
    with open('pw', 'wb') as f:
        f.write(encryption_key + hmac_key)

if __name__ == "__main__":
    generate_keys()