from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_image(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(16)
    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(salt + ciphertext)

def decrypt_image(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        data = f.read()

    salt = data[:16]
    ciphertext = data[16:]

    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC, iv=ciphertext[:16])
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

if __name__ == "__main__":
    input_image = "input_image.jpg"
    encrypted_image = "encrypted_image.enc"
    decrypted_image = "decrypted_image.jpg"

    password = "super_secure_password"  # Replace with your own secure password

    encrypt_image(input_image, encrypted_image, password)
    print("Image encrypted successfully!")

    decrypt_image(encrypted_image, decrypted_image, password)
    print("Image decrypted successfully!")
