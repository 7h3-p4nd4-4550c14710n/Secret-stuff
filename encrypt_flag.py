from Crypto.Cipher import AES
from decryptor import key

aes = AES.new(key, AES.MODE_ECB)

flag_cleartext = input("Enter flag to encrypt: ")
assert len(flag_cleartext) % 16 == 0

flag_encrypted = aes.encrypt(flag_cleartext)

with open("flag", "wb") as f:
    f.write(flag_encrypted)
